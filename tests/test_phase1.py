"""Phase 1 tool-surface, transport failure, audit, and virtual-filesystem tests."""
import importlib.util
import json
import os
import sqlite3
import subprocess
import sys
import time

import pytest

from agent_harness.agent import ScriptedAgent
from agent_harness.demo import run_demo
from agent_harness.gateway import Gateway, GatewayUnavailable
from agent_harness.supervisor import ROOT, Supervisor


@pytest.fixture
def controller():
    with Supervisor() as controller:
        yield controller


@pytest.mark.parametrize("field,value", [
    ("operation", None), ("operation", []), ("resource", {"path": "README.md"}),
    ("resource", 42), ("body", []), ("body", None), ("approval", "trust-me"),
    ("task_id", True), ("capability_id", {}),
])
def test_malformed_argument_types_are_audited(controller, field, value):
    req = {"task_id": controller.contract["task_id"],
           "capability_id": controller.contract["capability_id"],
           "operation": "read_file", "resource": "README.md", "body": ""}
    req[field] = value
    result = controller.gateway.raw(req)
    assert result["decision"] == "DENY" and result["reason"] == "malformed_request"
    with sqlite3.connect(controller.audit_path) as db:
        assert db.execute("SELECT decision,executed FROM audit WHERE id=?", (result["event_id"],)).fetchone() == ("DENY", 0)


@pytest.mark.parametrize("injected", [False, True])
def test_complete_demo_and_audit(injected):
    report = run_demo(approve_publish=True, injected=injected)
    assert report["audit_verified"] and report["agent"]["completed"]
    assert [event["decision"] for event in report["publication"]] == ["REQUIRE_APPROVAL", "ALLOW", "DENY"]
    assert report["publication"][-1]["reason"] == "approval_replayed"
    assert sum(e["attack"] for e in report["agent"]["events"]) == (4 if injected else 0)
    assert all(row["timestamp"] > 0 and row["task"] == "report-task" for row in report["audit"])


def test_no_alternate_executor_available():
    assert importlib.util.find_spec("simulated_tools.baseline") is None
    # This is a surface regression check, not proof against arbitrary Python execution.
    assert sorted(p.name for p in (ROOT / "simulated_tools").glob("*.py")) == ["__init__.py"]


def test_host_symlinks_cannot_redirect_virtual_tools(controller, tmp_path):
    target = tmp_path / "synthetic-private.txt"
    target.write_text("SYNTHETIC-HOST-CONTENT")
    sample = controller.root / "sample-repository"
    read_path = sample / "README.md"
    read_path.unlink()
    try:
        read_path.symlink_to(target)
    except OSError as error:
        if os.name == "nt" and getattr(error, "winerror", None) == 1314:
            pytest.skip("Windows symlink privilege unavailable; junction tests remain mandatory")
        raise
    assert controller.gateway.call("read_file", "README.md")["data"] == controller.fixture["files"]["README.md"]
    write_path = sample / "reports/summary.md"
    write_path.unlink()
    write_path.symlink_to(target)
    assert controller.gateway.call("write_file", "reports/summary.md", "virtual update")["executed"]
    assert target.read_text() == "SYNTHETIC-HOST-CONTENT"
    assert controller.gateway.call("read_file", "reports/summary.md")["data"] == "virtual update"
    assert controller.gateway.call("symlink", "reports/summary.md", str(target))["decision"] == "DENY"


def test_host_changes_do_not_rewrite_runtime_contract(controller):
    controller.contract["grants"].append({"operation": "write_file", "resource": "README.md", "approval": False})
    decoy = controller.root / "sample-repository/contracts/task.json"
    decoy.write_text(json.dumps(controller.contract))
    assert controller.gateway.call("write_file", "README.md", "not authorized")["reason"] == "out_of_scope"


def test_empty_grants_default_deny():
    with Supervisor(template={"task_id": "empty", "ttl_seconds": 60, "grants": []}) as controller:
        assert controller.gateway.call("read_file", "README.md")["reason"] == "out_of_scope"


def test_live_audit_failure_closes_gateway(controller):
    with sqlite3.connect(controller.audit_path) as db:
        db.execute("DROP TABLE audit")
    with pytest.raises(GatewayUnavailable):
        controller.gateway.call("write_file", "reports/summary.md", "must fail")
    with pytest.raises(GatewayUnavailable):
        controller.gateway.call("read_file", "README.md")


def fake_runtime(script):
    # Trusted test fixture only, never registered as an agent tool.
    return subprocess.Popen([sys.executable, "-u", "-c", script], stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)


def close_process(process):
    if process.poll() is None:
        process.kill()
    process.wait(timeout=3)
    for pipe in (process.stdin, process.stdout, process.stderr):
        pipe.close()


@pytest.mark.parametrize("script", [
    'import sys,time; sys.stdin.readline(); sys.stdout.write("{"); sys.stdout.flush(); time.sleep(10)',
    'import time; time.sleep(10)',
])
def test_stalled_or_partial_response_deadline(script):
    process = fake_runtime(script)
    try:
        gateway = Gateway(process, "t", "c", timeout=.2)
        started = time.monotonic()
        with pytest.raises(GatewayUnavailable):
            gateway.call("read_file", "README.md")
        assert time.monotonic() - started < 2
        with pytest.raises(GatewayUnavailable):
            gateway.call("read_file", "README.md")
    finally:
        close_process(process)


@pytest.mark.parametrize("response", [
    [], {"decision": "ALLOW", "executed": False},
    {"decision": "DENY", "executed": True},
    {"decision": "DENY", "executed": False, "event_id": 1, "reason": "denied", "data": "leak"},
    {"decision": "ALLOW", "executed": True, "event_id": 1, "reason": "authorized", "data": "text", "provenance": "trusted"},
])
def test_invalid_gateway_response_fails_closed(response):
    wire = json.dumps(response) + "\n"
    process = fake_runtime('import sys; sys.stdin.readline(); sys.stdout.write(' + repr(wire) + '); sys.stdout.flush()')
    try:
        with pytest.raises(GatewayUnavailable):
            Gateway(process, "t", "c").call("read_file", "README.md")
    finally:
        close_process(process)
