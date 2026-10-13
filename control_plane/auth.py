"""Single local administrator, scrypt password verifier, expiring revocable sessions."""
from contextlib import closing, contextmanager
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import sqlite3
import threading
import time
from agent_harness.platform_security import private_directory


class AuthenticationError(Exception):
    pass


class Auth:
    def __init__(self, directory):
        if not hasattr(hashlib, "scrypt"):
            raise RuntimeError("Python 3.12+ with OpenSSL scrypt is required for administrator authentication")
        self._directory_guard = private_directory(directory, initialize=False)
        self.directory = Path(directory)
        self.file = self.directory / "administrator.json"
        self.db_path = self.directory / "control.sqlite"
        self.lock = threading.RLock()
        self.failures = 0
        self.locked_until = 0
        with self.db() as db:
            db.execute("CREATE TABLE IF NOT EXISTS sessions(digest TEXT PRIMARY KEY, csrf TEXT, expires INTEGER)")

    @contextmanager
    def db(self):
        with closing(sqlite3.connect(self.db_path)) as connection:
            with connection:
                yield connection

    @staticmethod
    def initialize(directory, password):
        directory = Path(directory)
        guard = private_directory(directory)
        if len(password) < 12 or len(password) > 256:
            raise ValueError("Use a password between 12 and 256 characters")
        salt = secrets.token_bytes(16)
        digest = hashlib.scrypt(password.encode(), salt=salt, n=131072, r=8, p=1, maxmem=268435456)
        data = {"identity": "local-admin", "salt": salt.hex(), "verifier": digest.hex()}
        fd = os.open(directory / "administrator.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as output:
            json.dump(data, output)
        guard.close()

    def login(self, password):
        with self.lock:
            now = int(time.time())
            if now < self.locked_until or not isinstance(password, str) or len(password) > 256:
                raise AuthenticationError("Authentication failed")
            config = json.loads(self.file.read_text())
            digest = hashlib.scrypt(password.encode(), salt=bytes.fromhex(config["salt"]), n=131072, r=8, p=1, maxmem=268435456)
            if not hmac.compare_digest(digest.hex(), config["verifier"]):
                self.failures += 1
                if self.failures >= 5:
                    self.locked_until = now + 300
                raise AuthenticationError("Authentication failed")
            self.failures = 0
            token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
            with self.db() as db:
                db.execute("DELETE FROM sessions WHERE expires<=?", (now,))
                db.execute("INSERT INTO sessions VALUES(?,?,?)", (hashlib.sha256(token.encode()).hexdigest(), csrf, now + 900))
            return token, csrf

    def verify(self, token, csrf=None):
        if not isinstance(token, str) or len(token) > 128:
            raise AuthenticationError("Authentication required")
        with self.db() as db:
            row = db.execute("SELECT csrf,expires FROM sessions WHERE digest=?", (hashlib.sha256(token.encode()).hexdigest(),)).fetchone()
        if not row or row[1] <= int(time.time()):
            raise AuthenticationError("Authentication required")
        if csrf is not None and not hmac.compare_digest(row[0], csrf):
            raise AuthenticationError("Invalid CSRF proof")
        return {"identity": "local-admin", "csrf": row[0], "expires_at": row[1]}

    def logout(self, token):
        with self.db() as db:
            db.execute("DELETE FROM sessions WHERE digest=?", (hashlib.sha256(token.encode()).hexdigest(),))

    def close(self):
        self._directory_guard.close()
