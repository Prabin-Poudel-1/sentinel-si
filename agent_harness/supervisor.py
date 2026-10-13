"""TRUSTED local experiment controller, not an agent tool.

The local OS user launches this controller. Its ephemeral signing key represents
that controller's authority, not a production user identity or login system.
Never pass this object, key, or bootstrap frame to a model or untrusted code.
"""
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import subprocess
import tempfile
import time

from agent_harness.transport import exchange
from agent_harness.platform_security import private_directory, child_environment, runtime_binary
from agent_harness.gateway import Gateway, GatewayUnavailable
from simulated_tools import fixtures

ROOT = Path(__file__).resolve().parents[1]


def sign(key, domain, payload):
    wire = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return {"payload": wire, "mac": hmac.new(key, domain + wire.encode(), hashlib.sha256).hexdigest()}


class Supervisor:
    def __init__(self, injected=True, template=None, audit_path=None, key=None, session_id=None, isolated=False, fixture_data=None):
        self._temp = tempfile.TemporaryDirectory(prefix="sentinelos-")
        self.root = Path(self._temp.name)
        self._directory_guard = private_directory(self.root)
        self.audit_path = Path(audit_path) if audit_path else self.root / "audit.sqlite"
        self.key = key if key is not None else secrets.token_bytes(32)
        template = template if template is not None else json.loads((ROOT / "contracts/report-task.json").read_text())
        self.contract = {
            "task_id": template["task_id"], "capability_id": secrets.token_hex(16),
            "session_id": session_id or secrets.token_hex(16),
            "expires_at": int(time.time()) + template["ttl_seconds"], "grants": template["grants"],
        }
        if "protected_resources" in template:
            self.contract["protected_resources"] = template["protected_resources"]
        self.fixture = fixtures(injected) if fixture_data is None else fixture_data
        # A disposable sample repository is materialized for inspection. The runtime
        # executes against its own in-memory snapshot, never these host paths.
        repo = self.root / "sample-repository"
        for name, content in self.fixture["files"].items():
            dest = repo / name
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(content)
        try:
            binary = runtime_binary(ROOT)
            self.process = subprocess.Popen([str(binary), str(self.audit_path)],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, bufsize=1, close_fds=True, env=child_environment())
            boot = {"key_hex": self.key.hex(),
                    "contract": sign(self.key, b"sentinel-contract-v1\0", self.contract), **self.fixture, "isolated": isolated}
            response = exchange(self.process, (json.dumps(boot) + "\n").encode(), 10)
            if json.loads(response) != {"ready": True}:
                raise GatewayUnavailable("Bootstrap rejected")
        except Exception:
            self.close()
            raise GatewayUnavailable("Bootstrap failed closed") from None
        self.gateway = Gateway(self.process, self.contract["task_id"], self.contract["capability_id"])

    def approve(self, operation, resource, body="", ttl=60):
        """Explicit trusted-controller action; only predeclared approval grants.

        This does not modify a contract. Exact body, task, session and expiry are bound.
        """
        if not any(g["operation"] == operation and g["resource"] == resource and g["approval"]
                   for g in self.contract["grants"]):
            raise ValueError("No approval-eligible grant")
        payload = {"task_id": self.contract["task_id"], "capability_id": self.contract["capability_id"],
                   "session_id": self.contract["session_id"], "operation": operation,
                   "resource": resource, "body_sha256": hashlib.sha256(body.encode()).hexdigest(),
                   "nonce": secrets.token_hex(16),
                   "expires_at": min(int(time.time()) + ttl, self.contract["expires_at"])}
        return sign(self.key, b"sentinel-approval-v1\0", payload)

    def close(self):
        if hasattr(self, "process"):
            if self.process.stdin:
                try:
                    self.process.stdin.close()
                except BrokenPipeError:
                    pass
            try:
                self.process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait()
            self.process.stdout.close()
            self.process.stderr.close()
        self._directory_guard.close()
        self._temp.cleanup()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
