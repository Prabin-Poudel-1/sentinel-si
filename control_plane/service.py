"""Authenticated control plane. All agent requests still execute in the Rust gateway."""
from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import secrets
import sqlite3
import threading
import time

from agent_harness.agent import ScriptedAgent
from agent_harness.supervisor import ROOT, Supervisor
from control_plane.auth import Auth
from simulated_tools import fixtures


def advanced_template():
    data = json.loads((ROOT / "contracts/report-task.json").read_text())
    data["task_id"] = "task-" + secrets.token_hex(6)
    data["protected_resources"] = ["private/customer.txt"]
    data["grants"] += [
        {"operation": "isolated_read", "resource": "input.txt", "approval": False},
        {"operation": "isolated_read", "resource": "output.txt", "approval": False},
        {"operation": "isolated_write", "resource": "output.txt", "approval": False},
        {"operation": "wasm_run", "resource": "sim:checksum", "approval": False},
        {"operation": "read_file", "resource": "private/customer.txt", "approval": False},
    ]
    return data


class Service:
    def __init__(self, directory):
        self.directory = Path(directory)
        self.auth = Auth(directory)
        self.audit_path = self.directory / "runtime.sqlite"
        self.controllers = {}
        self.pending = {}
        self.history = {}
        self.lock = threading.RLock()
        with self.auth.db() as db:
            db.execute("CREATE TABLE IF NOT EXISTS admin_events(id INTEGER PRIMARY KEY, timestamp INTEGER, actor TEXT, action TEXT, task TEXT, request_id TEXT, result TEXT)")

    def event(self, action, task="", request_id="", result="accepted"):
        with self.auth.db() as db:
            db.execute("INSERT INTO admin_events(timestamp,actor,action,task,request_id,result) VALUES(?,?,?,?,?,?)",
                       (int(time.time()), "unauthenticated" if action == "login" and result == "denied" else ("runtime" if action == "approval_requested" else "local-admin"), action, task, request_id, result))

    def authorize(self, token, csrf=None):
        return self.auth.verify(token, csrf)

    def request(self, task, operation, resource, body="", approval=None):
        with self.lock:
            controller = self.controllers[task]
            result = controller.gateway.call(operation, resource, body, approval)
            if result["decision"] == "REQUIRE_APPROVAL":
                identifier = secrets.token_hex(16)
                self.pending[identifier] = {
                    "id": identifier, "task": task, "operation": operation, "resource": resource,
                    "body": body, "body_sha256": hashlib.sha256(body.encode()).hexdigest(),
                    "expires_at": min(int(time.time()) + 120, controller.contract["expires_at"]),
                    "status": "pending", "event_id": result["event_id"],
                }
                self.event("approval_requested", task, identifier)
            return result

    def demonstration(self, token, csrf):
        self.authorize(token, csrf)
        with self.lock:
            if len(self.controllers) >= 4:
                raise ValueError("Revoke an existing task before starting another")
            fixture = fixtures(True)
            fixture["files"]["private/customer.txt"] = "SYNTHETIC-PROTECTED-DATA"
            controller = Supervisor(template=advanced_template(), audit_path=self.audit_path,
                                    isolated=True, fixture_data=fixture)
            task = controller.contract["task_id"]
            self.controllers[task] = controller
            self.history[task] = {"task_id": task, "status": "active", "expires_at": controller.contract["expires_at"],
                                  "grants": controller.contract["grants"], "protected_resources": controller.contract["protected_resources"]}
            self.event("task_started", task)
            service = self
            class Tools:
                def call(self, op, resource, body=""):
                    return service.request(task, op, resource, body)
            agent = ScriptedAgent(Tools()).run()
            isolated = [] if os.name == "nt" else [self.request(task, "isolated_read", "input.txt"),
                        self.request(task, "isolated_write", "output.txt", "Written through pinned descriptor"),
                        self.request(task, "isolated_read", "output.txt")]
            isolated.append(self.request(task, "wasm_run", "sim:checksum", "ABC"))
            approval = self.request(task, "api_post", "sim:publish", "Synthetic demo publication")
            return {"task_id": task, "completed": agent["completed"], "isolated": isolated, "approval": approval}

    def decide(self, token, csrf, request_id, approve):
        self.authorize(token, csrf)
        with self.lock:
            pending = self.pending.get(request_id)
            if not pending or pending["status"] != "pending":
                raise ValueError("Approval request is not pending")
            task = pending["task"]
            if pending["expires_at"] <= int(time.time()) or task not in self.controllers:
                pending["status"] = "expired"
                self.event("approval_expired", task, request_id, "denied")
                raise ValueError("Approval expired")
            self.event("approval_granted" if approve else "approval_denied", task, request_id)
            pending["status"] = "consumed" if approve else "denied"
            if not approve:
                return {"status": "denied"}
            controller = self.controllers[task]
            signed = controller.approve(pending["operation"], pending["resource"], pending["body"], ttl=min(60, pending["expires_at"] - int(time.time())))
            try:
                result = controller.gateway.call(pending["operation"], pending["resource"], pending["body"], signed)
                # Test the exact approved token again through Rust, never expose it to the UI/agent.
                replay = controller.gateway.call(pending["operation"], pending["resource"], pending["body"], signed)
                self.event("approval_executed", task, request_id, result["decision"])
                return {"result": result, "replay": replay}
            except Exception:
                self.event("approval_execution_failed", task, request_id, "unknown_outcome")
                raise

    def provenance_demo(self, token, csrf, task):
        self.authorize(token, csrf)
        with self.lock:
            read = self.request(task, "read_file", "private/customer.txt")
            blocked = self.request(task, "write_file", "reports/summary.md", "derived sensitive data")
            network = self.request(task, "api_post", "sim:publish", "encoded sensitive data")
            self.history[task]["tainted"] = True
            return {"read_decision": read["decision"], "write": blocked, "network": network}

    def revoke(self, token, csrf, task):
        self.authorize(token, csrf)
        with self.lock:
            if task not in self.controllers:
                raise ValueError("Task is not active")
            self.event("task_revoked", task)
            self.controllers.pop(task).close()
            self.history[task]["status"] = "revoked"
            for pending in self.pending.values():
                if pending["task"] == task and pending["status"] == "pending":
                    pending["status"] = "revoked"
            return {"status": "revoked"}

    def snapshot(self, token):
        identity = self.authorize(token)
        with self.lock:
            events = []
            if self.audit_path.exists():
                with closing(sqlite3.connect(self.audit_path)) as db, db:
                    db.row_factory = sqlite3.Row
                    events = [dict(r) for r in db.execute("SELECT * FROM audit ORDER BY id DESC LIMIT 500")]
                    counts = dict(db.execute("SELECT decision,COUNT(*) FROM audit GROUP BY decision"))
            else:
                counts = {}
            with self.auth.db() as db:
                db.row_factory = sqlite3.Row
                admin = [dict(r) for r in db.execute("SELECT * FROM admin_events ORDER BY id DESC LIMIT 100")]
            pending = [{k: v for k, v in p.items() if k != "body"} for p in self.pending.values()]
            for p in pending:
                if p["status"] == "pending" and p["expires_at"] <= int(time.time()):
                    p["status"] = "expired"
            sessions = [dict(s) for s in self.history.values()]
            for session in sessions:
                if session["status"] == "active" and session["expires_at"] <= int(time.time()):
                    session["status"] = "expired"
            metrics_path = ROOT / "benchmarks/phase2-results.json"
            return {"identity": identity, "counts": counts, "events": events, "approvals": pending,
                    "sessions": sessions, "admin_events": admin,
                    "benchmarks": json.loads(metrics_path.read_text()) if metrics_path.exists() else None,
                    "controls": {"native_execution": "unavailable",
                                 "platform_validation": "Native Windows candidate; client validation pending" if os.name == "nt" else "See platform validation report", "network": "simulated only; Wasm has no socket imports",
                                 "filesystem": "unavailable on native Windows; use WSL2" if os.name == "nt" else "pinned input/output descriptors", "wasm": "import-free checksum; fuel and memory limits",
                                 "provenance": "experimental sticky task taint", "live_model": "optional, disabled by default"}}

    def close(self):
        with self.lock:
            for controller in self.controllers.values():
                controller.close()
            self.controllers.clear()
            self.auth.close()
