"""Loopback-only dashboard/control API. Run python -m control_plane.server --help."""
import argparse
import getpass
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import sqlite3

from agent_harness.gateway import GatewayUnavailable
from agent_harness.supervisor import ROOT
from control_plane.auth import AuthenticationError, Auth
from control_plane.service import Service


class Server(ThreadingHTTPServer):
    daemon_threads = True
    def __init__(self, address, service):
        self.service = service
        super().__init__(address, Handler)
        self.authority = "127.0.0.1:" + str(self.server_port)


class Handler(BaseHTTPRequestHandler):
    server_version = "SentinelLocal/0.2"
    def setup(self):
        super().setup()
        self.connection.settimeout(5)

    def log_message(self, *args):
        pass  # Never log raw URLs, headers, request bodies or tokens.

    def send(self, status, data, content_type="application/json", cookie=None):
        raw = data if isinstance(data, bytes) else json.dumps(data).encode()
        self.send_response(status)
        for key, value in {
            "Content-Type": content_type, "Content-Length": str(len(raw)), "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer",
            "Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
        }.items():
            self.send_header(key, value)
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()
        self.wfile.write(raw)

    def token(self):
        cookie = SimpleCookie()
        cookie.load(self.headers.get("Cookie", ""))
        return cookie["sentinel_session"].value if "sentinel_session" in cookie else ""

    def boundary(self):
        if self.headers.get("Host") != self.server.authority:
            raise AuthenticationError("Invalid host")
        origin = self.headers.get("Origin")
        if origin is not None and origin != "http://" + self.server.authority:
            raise AuthenticationError("Invalid origin")

    def do_GET(self):
        try:
            self.boundary()
            if self.path == "/api/state":
                return self.send(200, self.server.service.snapshot(self.token()))
            assets = {"/": ("index.html", "text/html; charset=utf-8"),
                      "/app.js": ("app.js", "text/javascript; charset=utf-8"),
                      "/style.css": ("style.css", "text/css; charset=utf-8")}
            if self.path not in assets:
                return self.send(404, {"error": "Not found"})
            name, mime = assets[self.path]
            self.send(200, (ROOT / "dashboard/dist" / name).read_bytes(), mime)
        except AuthenticationError:
            self.send(401, {"error": "Authentication required"})
        except (ValueError, OSError, sqlite3.Error):
            self.send(503, {"error": "Service unavailable"})

    def do_POST(self):
        try:
            self.boundary()
            if self.headers.get("Content-Type") != "application/json" or self.headers.get("Transfer-Encoding"):
                return self.send(400, {"error": "JSON required"})
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 < length <= 4096:
                return self.send(400, {"error": "Invalid request size"})
            body = json.loads(self.rfile.read(length))
            if not isinstance(body, dict):
                return self.send(400, {"error": "Object required"})
            service = self.server.service
            if self.path == "/api/login":
                try:
                    token, csrf = service.auth.login(body.get("password"))
                except AuthenticationError:
                    service.event("login", result="denied")
                    raise
                service.event("login")
                return self.send(200, {"csrf": csrf}, cookie="sentinel_session=" + token + "; HttpOnly; SameSite=Strict; Path=/; Max-Age=900")
            token = self.token()
            csrf = self.headers.get("X-Sentinel-CSRF", "")
            service.authorize(token, csrf)
            if self.path == "/api/logout":
                service.auth.logout(token)
                return self.send(200, {"status": "logged_out"}, cookie="sentinel_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0")
            if self.path == "/api/demo":
                return self.send(200, service.demonstration(token, csrf))
            if self.path == "/api/approval":
                if type(body.get("approve")) is not bool or not isinstance(body.get("id"), str):
                    return self.send(400, {"error": "Invalid decision"})
                return self.send(200, service.decide(token, csrf, body["id"], body["approve"]))
            if self.path == "/api/revoke":
                return self.send(200, service.revoke(token, csrf, body.get("task")))
            if self.path == "/api/provenance":
                return self.send(200, service.provenance_demo(token, csrf, body.get("task")))
            self.send(404, {"error": "Not found"})
        except AuthenticationError:
            self.send(401, {"error": "Authentication or CSRF verification failed"})
        except (KeyError, ValueError, TypeError):
            self.send(409, {"error": "Invalid, expired or unavailable operation"})
        except (GatewayUnavailable, OSError, sqlite3.Error):
            self.send(503, {"error": "Service failed closed"})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, default=ROOT / ".local-state")
    parser.add_argument("--port", type=int, default=8787)
    parser.add_argument("--init", action="store_true", help="Create administrator using an interactive password prompt")
    args = parser.parse_args()
    if args.init:
        password = getpass.getpass("New local administrator password (12+ characters): ")
        if password != getpass.getpass("Confirm password: "):
            raise SystemExit("Passwords did not match")
        Auth.initialize(args.state, password)
        print("Local administrator initialized")
        return
    if not (args.state / "administrator.json").exists():
        raise SystemExit("Initialize a local administrator first with --init")
    service = Service(args.state)
    server = Server(("127.0.0.1", args.port), service)
    print("Sentinel AI local dashboard: http://" + server.authority, flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        service.close()


if __name__ == "__main__":
    main()
