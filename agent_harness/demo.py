"""Run: python -m agent_harness.demo [--approve-publish] [--clean] [--output report.json]."""
import argparse
import json
from pathlib import Path
import sqlite3
from contextlib import closing
from agent_harness.agent import ScriptedAgent
from agent_harness.supervisor import Supervisor


def run_demo(approve_publish=False, injected=True):
    """Exercise real gateway decisions and verify their durable audit correlation."""
    with Supervisor(injected=injected) as controller:
        protected = ScriptedAgent(controller.gateway).run()
        publication = [controller.gateway.call("api_post", "sim:publish", "demo summary")]
        if approve_publish:
            token = controller.approve("api_post", "sim:publish", "demo summary")
            publication.append(controller.gateway.call("api_post", "sim:publish", "demo summary", approval=token))
            publication.append(controller.gateway.call("api_post", "sim:publish", "demo summary", approval=token))
        with closing(sqlite3.connect(controller.audit_path)) as db, db:
            db.row_factory = sqlite3.Row
            rows = [dict(row) for row in db.execute("SELECT * FROM audit ORDER BY id")]
        by_id = {row["id"]: row for row in rows}
        events = protected["events"] + publication
        for event in events:
            row = by_id[event["event_id"]]
            if (row["decision"] != event["decision"] or bool(row["executed"]) != event["executed"]
                    or row["reason"] != event["reason"]):
                raise RuntimeError("Audit mismatch")
        if len(events) != len(rows) or not protected["completed"]:
            raise RuntimeError("Incomplete workflow")
        attacks = [e for e in protected["events"] if e["attack"]]
        if any(e["executed"] or e["decision"] != "DENY" for e in attacks):
            raise RuntimeError("Unauthorized execution")
        return {"project": "Sentinel AI", "phase": 1, "agent": protected,
                "publication": publication, "audit_verified": True, "audit": rows}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--approve-publish", action="store_true", help="Trusted user approves the exact demo publication")
    parser.add_argument("--clean", action="store_true", help="Run the same task without injected instructions")
    parser.add_argument("--output", type=Path, help="Save a synthetic workflow/audit report")
    args = parser.parse_args()
    report = json.dumps(run_demo(args.approve_publish, not args.clean), indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(report)
    print(report, end="")


if __name__ == "__main__":
    main()
