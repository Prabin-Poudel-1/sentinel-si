"""Real runtime integration plus administrator/API security regression tests."""
from concurrent.futures import ThreadPoolExecutor
import hashlib
import http.client
import json
import os
import secrets
import sqlite3
import threading
import time

import pytest

from agent_harness.gateway import GatewayUnavailable
from agent_harness.live import ModelAgent
from agent_harness.providers.local_http import LocalJsonModel
from agent_harness.supervisor import Supervisor
from control_plane.auth import Auth, AuthenticationError
from control_plane.server import Server
from control_plane.service import Service, advanced_template
from simulated_tools import fixtures


@pytest.fixture
def admin(tmp_path):
    password = secrets.token_urlsafe(24)
    Auth.initialize(tmp_path, password)
    service = Service(tmp_path)
    token, csrf = service.auth.login(password)
    yield service, token, csrf, password
    service.close()


def test_admin_database_connection_closes_after_context(admin):
    service, *_ = admin
    with service.auth.db() as connection:
        assert connection.execute("SELECT 1").fetchone() == (1,)

    with pytest.raises(sqlite3.ProgrammingError):
        connection.execute("SELECT 1")


def test_authenticated_approval_replay_and_revocation(admin):
    service, token, csrf, _ = admin
    with pytest.raises(AuthenticationError):
        service.demonstration("forged", csrf)
    result = service.demonstration(token, csrf)
    assert result["completed"] and all(r["executed"] for r in result["isolated"])
    assert result["isolated"][-1]["data"] == "checksum:198"
    pending = service.snapshot(token)["approvals"][0]
    with pytest.raises(AuthenticationError):
        service.decide(token, "forged", pending["id"], True)
    approved = service.decide(token, csrf, pending["id"], True)
    assert approved["result"]["decision"] == "ALLOW"
    assert approved["replay"]["reason"] == "approval_replayed"
    with pytest.raises(ValueError):
        service.decide(token, csrf, pending["id"], True)
    task = result["task_id"]
    service.revoke(token, csrf, task)
    assert service.snapshot(token)["sessions"][0]["status"] == "revoked"
    with pytest.raises(KeyError):
        service.request(task, "read_file", "README.md")


def test_approval_expiration_and_denial(admin):
    service, token, csrf, _ = admin
    service.demonstration(token, csrf)
    identifier = next(iter(service.pending))
    service.pending[identifier]["expires_at"] = int(time.time()) - 1
    with pytest.raises(ValueError):
        service.decide(token, csrf, identifier, True)
    task = next(iter(service.controllers))
    service.request(task, "api_post", "sim:publish", "different payload")
    pending = [p for p in service.pending.values() if p["status"] == "pending"][0]
    assert service.decide(token, csrf, pending["id"], False)["status"] == "denied"


def test_provenance_blocks_derived_and_encoded_flows(admin):
    service, token, csrf, _ = admin
    task = service.demonstration(token, csrf)["task_id"]
    result = service.provenance_demo(token, csrf, task)
    assert result["read_decision"] == "ALLOW"
    assert result["write"]["reason"] == result["network"]["reason"] == "protected_flow_blocked"
    assert service.request(task, "isolated_write", "output.txt", "base64-derived")["reason"] == "protected_flow_blocked"
    assert service.request(task, "wasm_run", "sim:checksum", "hash-derived")["reason"] == "protected_flow_blocked"
    # No sanitization/declassification through attacker-chosen encodings.
    assert service.request(task, "write_file", "reports/summary.md", "nothing secret")["decision"] == "DENY"


def test_concurrent_approval_consumed_once(admin):
    service, token, csrf, _ = admin
    service.demonstration(token, csrf)
    identifier = next(iter(service.pending))
    def decide():
        try:
            return service.decide(token, csrf, identifier, True)["result"]["decision"]
        except ValueError:
            return "rejected"
    with ThreadPoolExecutor(max_workers=6) as pool:
        outcomes = list(pool.map(lambda _: decide(), range(6)))
    assert outcomes.count("ALLOW") == 1 and outcomes.count("rejected") == 5


def test_password_verifier_session_expiry_logout_and_throttle(admin):
    service, token, csrf, password = admin
    stored = json.loads(service.auth.file.read_text())
    assert password not in json.dumps(stored)
    assert service.auth.verify(token, csrf)["identity"] == "local-admin"
    with service.auth.db() as db:
        db.execute("UPDATE sessions SET expires=0")
    with pytest.raises(AuthenticationError):
        service.auth.verify(token)
    token, _ = service.auth.login(password)
    service.auth.logout(token)
    with pytest.raises(AuthenticationError):
        service.auth.verify(token)
    for _ in range(5):
        with pytest.raises(AuthenticationError):
            service.auth.login("wrong-synthetic-password")
    with pytest.raises(AuthenticationError):
        service.auth.login(password)


def test_control_and_runtime_logs_redact_secrets(admin):
    service, token, csrf, password = admin
    result = service.demonstration(token, csrf)
    service.provenance_demo(token, csrf, result["task_id"])
    snapshot = json.dumps(service.snapshot(token))
    # State intentionally includes this session's CSRF secret; audit tables must not.
    assert password not in snapshot and token not in snapshot
    for path in [service.auth.db_path, service.audit_path]:
        with sqlite3.connect(path) as db:
            if path == service.auth.db_path:
                rows = db.execute("SELECT * FROM admin_events").fetchall()
            else:
                rows = db.execute("SELECT * FROM audit").fetchall()
        assert all(secret not in repr(rows) for secret in [password, token, csrf, "SYNTHETIC-PROTECTED-DATA"])


@pytest.mark.skipif(os.name == "nt", reason="Native Windows file isolation deliberately unavailable")
def test_isolated_gateway_scope_and_serial_concurrency():
    with Supervisor(template=advanced_template(), isolated=True) as controller:
        assert controller.gateway.call("isolated_read", "../input.txt")["decision"] == "DENY"
        assert controller.gateway.call("isolated_write", "input.txt", "overwrite")["decision"] == "DENY"
        assert controller.gateway.call("isolated_write", "new.txt", "create")["decision"] == "DENY"
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(lambda _: controller.gateway.call("isolated_read", "input.txt"), range(24)))
        assert all(r["data"] == "Synthetic isolated input" for r in results)
        assert len({r["event_id"] for r in results}) == 24


@pytest.fixture
def http_admin(admin):
    service, token, csrf, password = admin
    server = Server(("127.0.0.1", 0), service)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server, password
    server.shutdown()
    server.server_close()
    thread.join()


def http_call(server, path, body=None, cookie=None, csrf=None, extra=None):
    connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=5)
    headers = {}
    if cookie:
        headers["Cookie"] = cookie
    if csrf is not None:
        headers["X-Sentinel-CSRF"] = csrf
    if body is not None:
        headers["Content-Type"] = "application/json"
    headers.update(extra or {})
    connection.request("POST" if body is not None else "GET", path, json.dumps(body) if body is not None else None, headers)
    response = connection.getresponse()
    raw = response.read()
    result = response.status, dict(response.getheaders()), raw
    connection.close()
    return result


def test_dashboard_http_auth_csrf_host_and_real_data(http_admin):
    server, password = http_admin
    assert http_call(server, "/api/state")[0] == 401
    assert http_call(server, "/api/demo", {})[0] == 401
    assert http_call(server, "/", extra={"Host": "attacker.invalid"})[0] == 401
    assert http_call(server, "/api/login", {"password": password}, extra={"Origin": "https://attacker.invalid"})[0] == 401
    status, headers, raw = http_call(server, "/api/login", {"password": password})
    assert status == 200 and "HttpOnly" in headers["Set-Cookie"] and "SameSite=Strict" in headers["Set-Cookie"]
    cookie = headers["Set-Cookie"].split(";")[0]
    csrf = json.loads(raw)["csrf"]
    assert http_call(server, "/api/demo", {}, cookie)[0] == 401
    assert http_call(server, "/api/demo", {}, cookie, csrf)[0] == 200
    state = json.loads(http_call(server, "/api/state", cookie=cookie)[2])
    assert state["counts"]["DENY"] == 4 and len(state["sessions"]) == 1
    assert state["approvals"][0]["status"] == "pending"
    assert "body" not in state["approvals"][0]
    assert "default-src 'self'" in http_call(server, "/")[1]["Content-Security-Policy"]
    assert http_call(server, "/../../administrator.json")[0] == 404
    assert http_call(server, "/api/logout", {}, cookie, csrf)[0] == 200
    assert http_call(server, "/api/state", cookie=cookie)[0] == 401


def test_optional_model_routes_malicious_proposals_through_gateway():
    class Provider:
        def __init__(self):
            self.actions = iter([{"done": False, "operation": "read_file", "resource": "README.md", "body": ""},
                                 {"done": False, "operation": "read_file", "resource": "secrets/demo.txt", "body": ""},
                                 {"done": False, "operation": "api_post", "resource": "sim:attacker", "body": ""}, {"done": True, "operation": "", "resource": "", "body": ""}])
        def propose(self, messages):
            return next(self.actions)
    with Supervisor() as controller:
        result = ModelAgent(Provider(), controller.gateway).run("Synthetic task")
    assert result["finished"]
    assert [r["decision"] for r in result["events"]] == ["ALLOW", "DENY", "DENY"]


@pytest.mark.parametrize("url", ["https://production.invalid/v1", "http://localhost/v1", "http://user:pass@127.0.0.1/v1", "file:///tmp/model"])
def test_model_adapter_rejects_remote_or_ambiguous_endpoint(url):
    with pytest.raises(ValueError):
        LocalJsonModel(url, "synthetic-model")


def test_local_model_http_adapter_keeps_key_out_of_messages():
    from http.server import BaseHTTPRequestHandler, HTTPServer
    received = {}
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            received['auth'] = self.headers.get('Authorization')
            received['payload'] = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
            body = json.dumps({'choices': [{'finish_reason': 'stop', 'message': {'content': json.dumps({'done': False, 'operation': 'read_file', 'resource': 'README.md', 'body': ''})}}]}).encode()
            self.send_response(200)
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        def log_message(self, *args):
            pass
    server = HTTPServer(('127.0.0.1', 0), Handler)
    worker = threading.Thread(target=server.handle_request)
    worker.start()
    try:
        model = LocalJsonModel(f'http://127.0.0.1:{server.server_port}/v1/chat/completions', 'synthetic', 'SYNTHETIC-KEY')
        proposal = model.propose([{'role': 'user', 'content': 'synthetic task'}])
        assert proposal['operation'] == 'read_file'
        assert received['auth'] == 'Bearer SYNTHETIC-KEY'
        assert 'SYNTHETIC-KEY' not in json.dumps(received['payload'])
    finally:
        worker.join(timeout=5)
        server.server_close()
