"""Explicitly paired outbound client. Queue contains only bounded safe metadata."""
import json
import sqlite3
import time
import uuid
from urllib import request, error, parse
from pathlib import Path
from sentinel_sdk import OPERATIONS
from .credentials import SystemCredentials, MemoryTestCredentials


class SyncError(RuntimeError):
    pass


REASONS = frozenset({"authorized", "denied", "approval_required", "policy_blocked", "expired", "invalid", "execution_failed", "unknown"})
FIELDS = {"event_id", "timestamp", "operation", "decision", "executed", "reason_code"}


def safe_event(result, operation, *, timestamp=None, event_id=None):
    """Only allowlisted fields leave the process; no content/resource/task hashing."""
    raw_reason = result.get("reason", "unknown")
    reason = {"authorized": "authorized", "approval_required": "approval_required",
              "expired_contract": "expired", "policy_denied": "policy_blocked",
              "protected_flow_blocked": "policy_blocked", "out_of_scope": "denied",
              "sensitive_resource": "denied", "approval_replayed": "invalid",
              "invalid_approval": "invalid", "invalid_request": "invalid",
              "invalid_capability": "invalid", "malformed_request": "invalid"}.get(raw_reason, "unknown")
    event = {"event_id": str(uuid.uuid4()) if event_id is None else event_id,
             "timestamp": int(time.time()) if timestamp is None else timestamp,
             "operation": operation if operation in OPERATIONS else "unknown",
             "decision": result.get("decision"), "executed": result.get("executed"), "reason_code": reason}
    validate_event(event)
    return event


def validate_event(event):
    if type(event) is not dict or set(event) != FIELDS:
        raise ValueError("Invalid export fields")
    try:
        if str(uuid.UUID(event["event_id"])) != event["event_id"]:
            raise ValueError()
    except (ValueError, TypeError, AttributeError):
        raise ValueError("Invalid opaque event ID") from None
    if (type(event["timestamp"]) is not int or not 0 <= event["timestamp"] <= 2**53
            or event["operation"] not in OPERATIONS | {"unknown"}
            or event["decision"] not in {"ALLOW", "DENY", "REQUIRE_APPROVAL"}
            or type(event["executed"]) is not bool
            or event["executed"] != (event["decision"] == "ALLOW")
            or event["reason_code"] not in REASONS):
        raise ValueError("Invalid export metadata")


class NoRedirect(request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


class SyncClient:
    def __init__(self, origin, queue_path, *, consent=False, credentials=None,
                 allow_test_credentials=False, allow_loopback_http=False,
                 max_events=1000, retention_seconds=604800, timeout=10):
        parsed = parse.urlsplit(origin)
        try:
            port = parsed.port
        except ValueError:
            raise ValueError("Invalid sync origin") from None
        if (parsed.username or parsed.password or parsed.query or parsed.fragment
                or parsed.path not in {"", "/"} or not parsed.hostname
                or (parsed.scheme != "https" and not
                    (allow_loopback_http and parsed.scheme == "http" and parsed.hostname == "127.0.0.1"))):
            raise ValueError("Use an HTTPS origin (explicit loopback HTTP for development only)")
        if not 1 <= max_events <= 10000 or not 60 <= retention_seconds <= 604800 or not 0 < timeout <= 60:
            raise ValueError("Invalid sync limits")
        if credentials is not None and not isinstance(credentials, SystemCredentials):
            if not (allow_test_credentials and isinstance(credentials, MemoryTestCredentials)):
                raise ValueError("Only native credential stores are supported")
        self.origin = origin.rstrip("/")
        self.consent = consent is True
        self.credentials = credentials  # Lazily access OS store only when opting in.
        self.queue_path = Path(queue_path)
        self.max_events, self.retention_seconds, self.timeout = max_events, retention_seconds, timeout
        self.opener = request.build_opener(request.ProxyHandler({}), NoRedirect())
        self.device_id = None
        self.next_attempt = 0
        self.failures = 0
        with self._db() as db:
            tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            if tables - {"events", "pairing"}:
                raise ValueError("Use a dedicated sync queue, never an audit or application database")
            db.execute("CREATE TABLE IF NOT EXISTS events (id TEXT PRIMARY KEY, created INTEGER NOT NULL, payload TEXT NOT NULL)")
            db.execute("CREATE TABLE IF NOT EXISTS pairing (singleton INTEGER PRIMARY KEY CHECK(singleton=1), device_id TEXT NOT NULL, origin TEXT NOT NULL)")
            row = db.execute("SELECT device_id,origin FROM pairing WHERE singleton=1").fetchone()
            if row:
                if row[1] != self.origin:
                    raise ValueError("Queue belongs to another origin")
                self.device_id = row[0]
            self._prune(db)

    def _db(self):
        return sqlite3.connect(self.queue_path, timeout=5)

    def _store(self):
        if self.credentials is None:
            self.credentials = SystemCredentials()
        return self.credentials

    def _key(self):
        return self.origin + "/" + self.device_id

    def _prune(self, db):
        db.execute("DELETE FROM events WHERE created < ?", (int(time.time()) - self.retention_seconds,))
        db.execute("DELETE FROM events WHERE id IN (SELECT id FROM events ORDER BY created DESC,rowid DESC LIMIT -1 OFFSET ?)", (self.max_events,))

    def _post(self, path, payload, token=None):
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if token:
            headers["Authorization"] = "Bearer " + token
        wire = json.dumps(payload, separators=(",", ":"), allow_nan=False).encode()
        try:
            with self.opener.open(request.Request(self.origin + path, data=wire, headers=headers), timeout=self.timeout) as response:
                data = response.read(65537)
                if len(data) > 65536:
                    raise SyncError("Sync response exceeded limit")
                parsed = json.loads(data)
                if type(parsed) is not dict:
                    raise ValueError()
                return parsed
        except (error.URLError, OSError, ValueError) as exc:
            # Never include URLs, bodies, tokens, response text or underlying errors.
            raise SyncError("Sync request failed; local enforcement remains independent") from None

    def pair(self, pairing_code):
        if not self.consent:
            raise SyncError("Explicit local sync consent required")
        if self.device_id:
            raise SyncError("Disconnect the existing device before pairing")
        store = self._store()
        response = self._post("/api/device/pair", {"pairing_code": pairing_code})
        device_id, token = response.get("device_id"), response.get("device_token")
        if not isinstance(device_id, str) or not 1 <= len(device_id) <= 128 or not isinstance(token, str) or not 16 <= len(token) <= 1024:
            raise SyncError("Invalid pairing response")
        self.device_id = device_id
        try:
            store.set(self._key(), token)
            with self._db() as db:
                db.execute("INSERT INTO pairing VALUES(1,?,?)", (device_id, self.origin))
        except Exception:
            self.device_id = None
            raise SyncError("Credential persistence failed; revoke the device in account settings") from None
        return device_id

    def enqueue(self, event):
        if not self.consent or not self.device_id:
            return False
        validate_event(event)
        with self._db() as db:
            db.execute("INSERT OR IGNORE INTO events VALUES(?,?,?)", (event["event_id"], int(time.time()), json.dumps(event, separators=(",", ":"))))
            self._prune(db)
        return True

    def flush(self):
        if not self.consent or not self.device_id or time.monotonic() < self.next_attempt:
            return 0
        token = self._store().get(self._key())
        if not token:
            raise SyncError("Device credential unavailable; reconnect explicitly")
        with self._db() as db:
            self._prune(db)
            rows = db.execute("SELECT id,payload FROM events ORDER BY created,rowid LIMIT 25").fetchall()
        if not rows:
            return 0
        events = [json.loads(row[1]) for row in rows]
        for event in events:
            validate_event(event)
        try:
            result = self._post("/api/telemetry", {"events": events}, token)
            accepted = result.get("accepted")
            expected = {row[0] for row in rows}
            if type(accepted) is not list or any(type(v) is not str or v not in expected for v in accepted):
                raise SyncError("Invalid sync acknowledgement")
        except SyncError:
            self.failures += 1
            self.next_attempt = time.monotonic() + min(300, 2 ** min(self.failures, 8))
            raise
        with self._db() as db:
            db.executemany("DELETE FROM events WHERE id=?", [(v,) for v in accepted])
        self.failures, self.next_attempt = 0, 0
        return len(set(accepted))

    def rotate(self):
        if not self.consent or not self.device_id:
            raise SyncError("No consented paired device")
        store = self._store()
        response = self._post("/api/device/rotate", {}, store.get(self._key()))
        token = response.get("device_token")
        if not isinstance(token, str) or not 16 <= len(token) <= 1024:
            raise SyncError("Invalid rotation response")
        store.set(self._key(), token)

    def disconnect(self):
        """Revoke remotely first. On network failure local cleanup still happens."""
        try:
            if self.device_id:
                token = self._store().get(self._key())
                if token:
                    self._post("/api/device/revoke", {}, token)
        finally:
            try:
                if self.device_id:
                    self._store().delete(self._key())
            finally:
                with self._db() as db:
                    db.execute("DELETE FROM events")
                    db.execute("DELETE FROM pairing")
                self.device_id = None
                self.consent = False
