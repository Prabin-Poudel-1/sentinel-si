"""Real loopback Worker/D1 + Rust/SDK/sync test; no deployment or real OAuth.

Run from the repository: .venv/bin/python scripts/public_e2e.py
Requires cloud npm dependencies and a built local Rust runtime. Uses explicit
in-memory test credentials instead of touching the user's OS credential store.
"""
import json
import os
from pathlib import Path
import secrets
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
from dataclasses import asdict
from urllib import request, error

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from sentinel_sdk import TrustedSession, Proposal
from sentinel_sync import SyncClient, MemoryTestCredentials, SyncError, safe_event


class BrowserSession:
    def __init__(self, origin):
        self.origin, self.cookie, self.csrf = origin, "", ""

    def call(self, path, body=None, method=None, expected=200):
        headers = {"Content-Type": "application/json", "Origin": self.origin}
        if self.cookie: headers["Cookie"] = self.cookie
        if self.csrf: headers["X-CSRF-Token"] = self.csrf
        req = request.Request(self.origin + path, data=None if body is None else json.dumps(body).encode(),
                              headers=headers, method=method or ("GET" if body is None else "POST"))
        try:
            response = request.urlopen(req, timeout=10)
        except error.HTTPError as exc:
            response = exc
        with response:
            assert response.status == expected, f"Unexpected HTTP status for {path}: {response.status}"
            result = json.loads(response.read(65536))
            if response.headers.get("Set-Cookie"):
                self.cookie = response.headers["Set-Cookie"].split(";", 1)[0]
            if "csrf_token" in result: self.csrf = result["csrf_token"]
            return result


def main():
    work = ROOT.parents[1] / "work"
    work.mkdir(exist_ok=True)
    checks = []
    with tempfile.TemporaryDirectory(prefix="public-e2e-", dir=work) as temp:
        temp = Path(temp); os.chmod(temp, 0o700)
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0)); port = sock.getsockname()[1]
        origin = f"http://127.0.0.1:{port}"
        key = secrets.token_urlsafe(32)
        config = temp / "wrangler.toml"
        config.write_text(f'''name = "sentinel-e2e"
main = {json.dumps(str(ROOT / "cloud/src/index.js"))}
compatibility_date = "2025-10-01"
workers_dev = false
[vars]
PUBLIC_ORIGIN = "{origin}"
DEV_MODE = "true"
PRODUCTION_ENABLED = "false"
[[d1_databases]]
binding = "DB"
database_name = "sentinel-e2e"
database_id = "00000000-0000-0000-0000-000000000000"
migrations_dir = {json.dumps(str(ROOT / "cloud/migrations"))}
[assets]
directory = {json.dumps(str(ROOT / "web/dist"))}
binding = "ASSETS"
run_worker_first = ["/api/*"]
[dev]
ip = "127.0.0.1"
port = {port}
''')
        varsfile = temp / ".dev.vars"
        varsfile.write_text("DEV_AUTH_KEY=" + key + "\n"); os.chmod(varsfile, 0o600)
        command = ["node", str(ROOT / "cloud/node_modules/wrangler/bin/wrangler.js")]
        env = {**os.environ, "WRANGLER_SEND_METRICS": "false", "CI": "true"}
        log = (temp / "worker.log").open("w+")
        subprocess.run(command + ["d1", "migrations", "apply", "sentinel-e2e", "--local", "--config", str(config), "--persist-to", str(temp / "state")],
                       cwd=ROOT, env=env, stdout=log, stderr=log, check=True, timeout=60)
        process = None
        def start():
            nonlocal process
            process = subprocess.Popen(command + ["dev", "--local", "--config", str(config), "--persist-to", str(temp / "state"), "--port", str(port)],
                                       cwd=ROOT, env=env, stdout=log, stderr=log)
            deadline = time.monotonic() + 45
            while time.monotonic() < deadline:
                if process.poll() is not None: raise RuntimeError("Local Worker exited; inspect private work log")
                try:
                    BrowserSession(origin).call("/api/session", expected=401)
                    return
                except (error.URLError, ConnectionError): time.sleep(0.2)
            raise RuntimeError("Local Worker readiness timed out")
        def stop():
            nonlocal process
            if process:
                process.terminate()
                try: process.wait(timeout=10)
                except subprocess.TimeoutExpired: process.kill(); process.wait()
                process = None
        try:
            start()
            alice, bob = BrowserSession(origin), BrowserSession(origin)
            alice.call("/api/dev/login", {"key": key, "identity": "alice"})
            bob.call("/api/dev/login", {"key": key, "identity": "bob"})
            assert alice.call("/api/settings")["sync_enabled"] is False
            alice.call("/api/settings", {"sync_enabled": True}, "PATCH")
            checks.append("two_dev_identities_and_explicit_account_consent")
            pairing = alice.call("/api/devices/pair", {"name": "Synthetic E2E device"})["pairing_code"]
            store = MemoryTestCredentials()
            sync = SyncClient(origin, temp / "sync.sqlite", consent=True, credentials=store,
                              allow_test_credentials=True, allow_loopback_http=True)
            device_id = sync.pair(pairing)
            BrowserSession(origin).call("/api/device/pair", {"pairing_code": pairing}, expected=401)
            checks.append("pairing_code_one_use")
            assert bob.call("/api/devices")["devices"] == []
            bob.call(f"/api/devices/{device_id}/revoke", {}, expected=404)
            audit_path = temp / "audit.sqlite"
            with TrustedSession(audit_path=audit_path) as session:
                proposals = [Proposal("read_file", "README.md"), Proposal("write_file", "reports/summary.md", "Synthetic E2E"),
                             Proposal("read_file", ".env"), Proposal("api_post", "sim:publish", "Synthetic E2E")]
                results = [session.tools.request(p) for p in proposals]
                assert [r.decision for r in results] == ["ALLOW", "ALLOW", "DENY", "REQUIRE_APPROVAL"]
                with sqlite3.connect(audit_path) as db:
                    assert db.execute("SELECT count(*) FROM audit").fetchone()[0] == 4
                for p, r in zip(proposals, results): sync.enqueue(safe_event(asdict(r), p.operation))
                assert sync.flush() == 4
                assert bob.call("/api/events")["events"] == []
                remote = alice.call("/api/events")["events"]
                assert len(remote) == 4
                assert all(set(e) == {"seq", "event_id", "device_id", "timestamp", "operation", "decision", "executed", "reason_code"} for e in remote)
                checks.extend(["real_rust_sdk_allow_deny_approval_required", "four_local_audit_records", "sanitized_metadata_sync", "cross_account_isolation"])
                if "--browser" in sys.argv:
                    subprocess.run(["node", str(ROOT / "web/tests/browser_smoke.cjs")],
                                   input=json.dumps({"origin": origin, "key": key, "reportDir": str(ROOT / "reports")}),
                                   text=True, cwd=ROOT, check=True, timeout=90)
                    checks.append("real_browser_dashboard_two_accounts")
                sync.rotate()
                checks.append("device_credential_rotation")
                stop()
                offline = session.tools.request(Proposal("read_file", "README.md"))
                assert offline.executed
                sync.enqueue(safe_event(asdict(offline), "read_file"))
                try: sync.flush()
                except SyncError: pass
                else: raise AssertionError("Offline sync unexpectedly succeeded")
                assert sync.flush() == 0
                with sqlite3.connect(sync.queue_path) as db:
                    assert db.execute("SELECT count(*) FROM events").fetchone()[0] == 1
                checks.append("cloud_outage_does_not_block_local_gateway_or_drop_queue")
                start()
                time.sleep(max(0, sync.next_attempt - time.monotonic()))
                assert sync.flush() == 1
                checks.append("reconnect_retries_acknowledged_metadata")
                alice.call(f"/api/devices/{device_id}/revoke", {})
                sync.enqueue(safe_event(asdict(offline), "read_file"))
                try: sync.flush()
                except SyncError: pass
                else: raise AssertionError("Revoked device uploaded metadata")
                assert session.tools.request(Proposal("read_file", "README.md")).executed
                checks.append("revoked_device_cannot_upload_local_gateway_independent")
                try: sync.disconnect()
                except SyncError: pass  # Already revoked remotely.
                assert not store.values and sync.device_id is None
                checks.append("disconnect_clears_test_credentials_and_queue")
            report = {"status": "passed", "checks": checks, "cloud": "Actual local Wrangler Worker and D1 emulation",
                      "gateway": "Actual compiled Rust runtime via SDK", "identity": "Explicit development alice/bob identities; not real GitHub OAuth",
                      "credentials": "Explicit MemoryTestCredentials; OS credential store not exercised",
                      "network": "Loopback only; no deployment", "limitations": ["Does not verify production OAuth, DNS, HTTPS, hosted D1 or OS credential storage", "Approval-required workflow verified; authenticated approval execution covered by existing control-plane tests"]}
            (ROOT / "reports/public-e2e.json").write_text(json.dumps(report, indent=2) + "\n")
            print(json.dumps({"status": "passed", "checks": len(checks), "report": "reports/public-e2e.json"}))
        finally:
            stop(); log.close()


if __name__ == "__main__": main()
