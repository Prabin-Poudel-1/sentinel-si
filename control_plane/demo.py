"""Reproducible integration demonstration using a disposable authenticated administrator."""
import argparse
import json
from pathlib import Path
import secrets
import tempfile
from control_plane.auth import Auth
from control_plane.service import Service


def run():
    with tempfile.TemporaryDirectory(prefix="sentinel-phase2-") as directory:
        password = secrets.token_urlsafe(24)
        Auth.initialize(directory, password)
        service = Service(directory)
        try:
            token, csrf = service.auth.login(password)
            service.event("login")
            demo = service.demonstration(token, csrf)
            request_id = next(iter(service.pending))
            approval = service.decide(token, csrf, request_id, True)
            flow = service.provenance_demo(token, csrf, demo["task_id"])
            service.revoke(token, csrf, demo["task_id"])
            snapshot = service.snapshot(token)
            snapshot.pop("identity")  # Never publish session/CSRF material.
            assert demo["completed"]
            assert all(r["decision"] == "ALLOW" for r in demo["isolated"])
            assert demo["approval"]["decision"] == "REQUIRE_APPROVAL"
            assert approval["result"]["decision"] == "ALLOW"
            assert approval["replay"]["decision"] == "DENY"
            assert flow["write"]["decision"] == flow["network"]["decision"] == "DENY"
            assert snapshot["counts"]["DENY"] == 7
            assert snapshot["sessions"][0]["status"] == "revoked"
            service.auth.logout(token)
            return {"passed": True, "mode": "deterministic, synthetic credentials, disposable state",
                    "task_completed": demo["completed"], "isolated_execution": demo["isolated"],
                    "approval": approval, "provenance": flow, "audit_snapshot": snapshot}
        finally:
            service.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    report = json.dumps(run(), indent=2) + "\n"
    if args.output:
        args.output.write_text(report)
    else:
        print(report, end="")


if __name__ == "__main__":
    main()
