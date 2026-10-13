"""Private browser-test fixture: generated synthetic password is passed over a pipe only."""
import json
import secrets
import tempfile
import signal

def stop_fixture(signum, frame):
    raise KeyboardInterrupt

signal.signal(signal.SIGTERM, stop_fixture)
from control_plane.auth import Auth
from control_plane.service import Service
from control_plane.server import Server

with tempfile.TemporaryDirectory(prefix="sentinel-ui-test-") as directory:
    password = secrets.token_urlsafe(24)
    Auth.initialize(directory, password)
    service = Service(directory)
    server = Server(("127.0.0.1", 0), service)
    import threading
    import sys
    threading.Thread(target=lambda: (sys.stdin.read(), server.shutdown()), daemon=True).start()
    print(json.dumps({"url": "http://" + server.authority, "password": password}), flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        service.close()
