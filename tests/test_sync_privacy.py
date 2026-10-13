import json
import sqlite3
import uuid
import pytest
from sentinel_sync import SyncClient, SyncError, safe_event, MemoryTestCredentials
from sentinel_sync.client import validate_event


def event():
    return safe_event({"decision": "DENY", "executed": False, "reason": "sensitive_resource", "data": "SECRET", "resource": "/private/secret"}, "read_file")


def client(tmp_path, consent=True):
    result = SyncClient("http://127.0.0.1:8788", tmp_path / "queue.sqlite", consent=consent,
                        credentials=MemoryTestCredentials(), allow_test_credentials=True, allow_loopback_http=True)
    result._post = lambda path, body, token=None: {"device_id": "test-device", "device_token": "synthetic-device-token-123"}
    if consent:
        result.pair("synthetic-pair-code")
    return result


def test_privacy_whitelist():
    value = event()
    assert "SECRET" not in json.dumps(value) and "private" not in json.dumps(value)
    assert set(value) == {"event_id", "timestamp", "operation", "decision", "executed", "reason_code"}
    for key in ("resource", "data", "task_id", "token", "hash"):
        with pytest.raises(ValueError):
            validate_event({**value, key: "secret"})


def test_off_by_default(tmp_path):
    c = client(tmp_path, False)
    assert not c.enqueue(event()) and c.flush() == 0
    with pytest.raises(SyncError):
        c.pair("code")


@pytest.mark.parametrize("origin", ["http://example.com", "http://localhost:8888", "https://example.com/path", "https://u:p@example.com", "https://example.com?q=x"])
def test_endpoint_restrictions(tmp_path, origin):
    with pytest.raises(ValueError):
        SyncClient(origin, tmp_path / "q")


def test_no_test_store_unless_explicit(tmp_path):
    with pytest.raises(ValueError):
        SyncClient("https://example.com", tmp_path / "q", credentials=MemoryTestCredentials())


def test_dedup_ack_retry_rotate_disconnect(tmp_path):
    c = client(tmp_path)
    e = event()
    c.enqueue(e); c.enqueue(e)
    calls = []
    def post(path, body, token=None):
        calls.append((path, body))
        if path == "/api/telemetry":
            return {"accepted": [e["event_id"]]}
        return {"device_token": "new-synthetic-token-12345"}
    c._post = post
    assert c.flush() == 1 and c.flush() == 0
    c.rotate()
    assert c.credentials.get(c._key()) == "new-synthetic-token-12345"
    c.disconnect()
    assert not c.consent and c.device_id is None and not c.credentials.values
    assert calls[-1][0] == "/api/device/revoke"


def test_failed_sync_never_acknowledges(tmp_path):
    c = client(tmp_path)
    c.enqueue(event())
    def fail(*args):
        raise SyncError("Unavailable")
    c._post = fail
    with pytest.raises(SyncError):
        c.flush()
    assert c.flush() == 0  # backoff, retained for retry
    with sqlite3.connect(c.queue_path) as db:
        assert db.execute("SELECT count(*) FROM events").fetchone()[0] == 1
    with pytest.raises(SyncError):
        c.disconnect()
    assert not c.credentials.values and not c.device_id


def test_queue_bound_retention_and_origin_binding(tmp_path):
    c = client(tmp_path)
    c.max_events = 2
    for _ in range(4): c.enqueue(event())
    with sqlite3.connect(c.queue_path) as db:
        assert db.execute("SELECT count(*) FROM events").fetchone()[0] == 2
        db.execute("UPDATE events SET created=0")
    c.enqueue(event())
    with sqlite3.connect(c.queue_path) as db:
        assert db.execute("SELECT count(*) FROM events").fetchone()[0] == 1
    with pytest.raises(ValueError):
        SyncClient("https://different.example", c.queue_path)


def test_invalid_ack_keeps_queue(tmp_path):
    c = client(tmp_path)
    c.enqueue(event())
    c._post = lambda *args: {"accepted": [str(uuid.uuid4())]}
    with pytest.raises(SyncError): c.flush()


def test_database_cannot_inject_extra_fields(tmp_path):
    c = client(tmp_path)
    e = event(); c.enqueue(e)
    with sqlite3.connect(c.queue_path) as db:
        db.execute("UPDATE events SET payload=?", (json.dumps({**e, "secret": "do not export"}),))
    with pytest.raises(ValueError): c.flush()


def test_refuse_existing_audit_database(tmp_path):
    path = tmp_path / "audit.sqlite"
    with sqlite3.connect(path) as db:
        db.execute("CREATE TABLE audit_events(secret TEXT)")
    with pytest.raises(ValueError):
        SyncClient("https://example.com", path)
    with sqlite3.connect(path) as db:
        assert db.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall() == [("audit_events",)]


def test_real_http_transport_and_redirect_rejected(tmp_path):
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    import threading
    calls = []
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args): pass
        def do_POST(self):
            payload = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            calls.append((self.path, payload))
            if self.path == "/api/device/pair":
                response = {"device_id": "http-test-device", "device_token": "synthetic-test-token-long"}
            elif self.path == "/api/telemetry":
                assert self.headers["Authorization"] == "Bearer synthetic-test-token-long"
                response = {"accepted": [e["event_id"] for e in payload["events"]]}
            else:
                self.send_response(302)
                self.send_header("Location", "/api/device/pair")
                self.end_headers()
                return
            wire = json.dumps(response).encode()
            self.send_response(200); self.send_header("Content-Length", str(len(wire))); self.end_headers(); self.wfile.write(wire)
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
    try:
        c = SyncClient(f"http://127.0.0.1:{server.server_port}", tmp_path / "q.sqlite", consent=True,
                       credentials=MemoryTestCredentials(), allow_test_credentials=True, allow_loopback_http=True)
        c.pair("synthetic-code"); c.enqueue(event())
        assert c.flush() == 1
        with pytest.raises(SyncError): c.rotate()
        assert len(calls) == 3  # No redirect followed.
    finally:
        server.shutdown(); server.server_close(); thread.join()
