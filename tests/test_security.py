"""Black-box security regression tests against the real Rust subprocess."""
import hashlib
import json
import secrets
import sqlite3
from contextlib import closing
import subprocess
import time

import pytest

from agent_harness.agent import ScriptedAgent, SUMMARY
from agent_harness.platform_security import runtime_binary
from agent_harness.gateway import Gateway, GatewayUnavailable
from agent_harness.supervisor import ROOT, Supervisor, sign
from simulated_tools import fixtures


@pytest.fixture
def controller():
    with Supervisor() as s:
        yield s


def template():
    return json.loads((ROOT / "contracts/report-task.json").read_text())


def request(s, **changes):
    req = {"task_id": s.contract["task_id"], "capability_id": s.contract["capability_id"],
           "operation": "read_file", "resource": "README.md", "body": ""}
    req.update(changes)
    return req


def test_legitimate_task_and_injection_denial(controller):
    protected = ScriptedAgent(controller.gateway).run()
    assert protected["completed"]
    attacks = [e for e in protected["events"] if e["attack"]]
    assert len(attacks) == 4
    assert all(not e["executed"] and e["decision"] == "DENY" for e in attacks)
    assert controller.gateway.call("read_file", "reports/summary.md")["data"] == SUMMARY


@pytest.mark.parametrize("resource", ["secrets/demo.txt", ".env", "private.txt", "contracts/task.json"])
def test_unauthorized_files(controller, resource):
    result = controller.gateway.call("read_file", resource)
    assert result["decision"] == "DENY" and not result["executed"] and result["data"] is None


@pytest.mark.parametrize("path", ["", "/etc/passwd", "../README.md", "docs/../../x", "docs//guide.md",
                                  "docs/./guide.md", "README.md/", "docs\\guide.md", "x%2f..%2fy",
                                  "x\x00y", "C:/Windows/x", "réadme.md", "x\ny", "x" * 241])
def test_malformed_paths(controller, path):
    assert controller.gateway.call("read_file", path)["reason"] == "invalid_request"


@pytest.mark.parametrize("op,resource", [("api_get", "https://example.com"),
                                        ("api_post", "sim:attacker"), ("api_get", "sim:unknown"),
                                        ("shell", "echo"), ("change_policy", "contracts/task.json")])
def test_forbidden_tools_and_network(controller, op, resource):
    assert not controller.gateway.call(op, resource)["executed"]


def test_forged_task_or_capability(controller):
    for field in ["task_id", "capability_id"]:
        assert controller.gateway.raw(request(controller, **{field: "forged"}))["reason"] == "invalid_capability"


@pytest.mark.parametrize("extra", [{"grants": []}, {"now": 0}, {"context": {"approved": True}}, {"key_hex": "00"}])
def test_no_agent_policy_control(controller, extra):
    assert controller.gateway.raw(request(controller, **extra))["reason"] == "malformed_request"


def test_approval_required_exact_bound_single_use(controller):
    g = controller.gateway
    assert g.call("api_post", "sim:publish", "report")["decision"] == "REQUIRE_APPROVAL"
    token = controller.approve("api_post", "sim:publish", "report")
    assert g.call("api_post", "sim:publish", "changed", token)["reason"] == "invalid_approval"
    assert g.call("api_post", "sim:publish", "report", token)["executed"]
    assert g.call("api_post", "sim:publish", "report", token)["reason"] == "approval_replayed"


def test_approval_cannot_expand_scope(controller):
    with pytest.raises(ValueError):
        controller.approve("api_post", "sim:attacker")
    token = controller.approve("api_post", "sim:publish")
    assert controller.gateway.call("api_post", "sim:attacker", approval=token)["reason"] == "out_of_scope"


def test_forged_expired_cross_session_approvals(controller):
    token = controller.approve("api_post", "sim:publish")
    forged = dict(token, mac="00" * 32)
    assert controller.gateway.call("api_post", "sim:publish", approval=forged)["reason"] == "invalid_approval"
    expired = controller.approve("api_post", "sim:publish", ttl=-1)
    assert controller.gateway.call("api_post", "sim:publish", approval=expired)["reason"] == "invalid_approval"
    with Supervisor(key=controller.key) as other:
        assert other.gateway.call("api_post", "sim:publish", approval=token)["reason"] == "invalid_approval"
    payload = json.loads(token["payload"])
    payload["session_id"] = "other-session"
    wrong_session = sign(controller.key, b"sentinel-approval-v1\0", payload)
    assert controller.gateway.call("api_post", "sim:publish", approval=wrong_session)["reason"] == "invalid_approval"


def test_sensitive_guardrail_overrides_signed_grant():
    t = template()
    t["grants"].append({"operation": "read_file", "resource": ".env", "approval": False})
    with Supervisor(template=t) as s:
        assert s.gateway.call("read_file", ".env")["reason"] == "sensitive_resource"


def test_expired_contract_at_start():
    t = template()
    t["ttl_seconds"] = -1
    with pytest.raises((ValueError, GatewayUnavailable)):
        Supervisor(template=t)


def test_expiry_during_session():
    t = template()
    t["ttl_seconds"] = 2
    with Supervisor(template=t) as s:
        assert s.gateway.call("read_file", "README.md")["executed"]
        deadline = s.contract["expires_at"]
        time.sleep(max(0, deadline - time.time()) + 0.02)
        assert s.gateway.call("read_file", "README.md")["reason"] == "expired_contract"


def test_audit_redaction(controller):
    marker = "CONFIDENTIAL-DO-NOT-LOG"
    controller.gateway.call("write_file", "reports/summary.md", marker)
    controller.gateway.call(marker, marker, marker)
    controller.gateway.raw(request(controller, task_id=marker))
    token = controller.approve("api_post", "sim:publish", marker)
    controller.gateway.call("api_post", "sim:publish", marker, token)
    with closing(sqlite3.connect(controller.audit_path)) as db, db:
        dump = "\n".join(db.iterdump())
        rows = db.execute("SELECT timestamp,task,operation,decision,executed FROM audit").fetchall()
    assert marker not in dump and controller.key.hex() not in dump and token["mac"] not in dump
    assert token["payload"] not in dump and "secrets/demo.txt" not in dump
    assert len(rows) == 4 and all(row[0] > 0 for row in rows)
    assert {row[3] for row in rows} == {"ALLOW", "DENY"}


def test_runtime_death_has_no_fallback(controller):
    controller.process.kill()
    controller.process.wait()
    with pytest.raises(GatewayUnavailable):
        controller.gateway.call("write_file", "reports/summary.md", "changed")


def test_malformed_json_and_duplicate_fields_fail_closed(controller):
    for wire in ['{broken}\n', '{"task_id":"a","task_id":"b"}\n']:
        controller.process.stdin.write(wire)
        controller.process.stdin.flush()
        response = json.loads(controller.process.stdout.readline())
        assert response["reason"] == "malformed_request" and not response["executed"]
    assert controller.gateway.call("read_file", "README.md")["executed"]


def test_body_limit(controller):
    assert controller.gateway.call("write_file", "reports/summary.md", "a" * 32769)["reason"] == "invalid_request"


def launch(boot, audit):
    p = subprocess.Popen([str(runtime_binary(ROOT)), str(audit)],
                         stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                         text=True)
    p.stdin.write(json.dumps(boot) + "\n")
    p.stdin.flush()
    return p


def finish(p):
    p.stdin.close()
    p.wait(timeout=5)
    p.stdout.close()
    p.stderr.close()


def test_contract_tampering_and_wrong_signature_domain(tmp_path):
    key = secrets.token_bytes(32)
    contract = {"task_id": "t", "capability_id": "c", "session_id": "s",
                "expires_at": int(time.time()) + 60, "grants": []}
    for domain, tamper in [(b"sentinel-contract-v1\0", True), (b"sentinel-approval-v1\0", False)]:
        signed = sign(key, domain, contract)
        if tamper:
            signed["payload"] = signed["payload"].replace('"task_id":"t"', '"task_id":"attacker"')
        p = launch({"key_hex": key.hex(), "contract": signed, **fixtures()}, tmp_path / "audit.sqlite")
        assert p.stdout.readline() == ""
        finish(p)
        assert p.returncode != 0


def test_replay_persists_after_runtime_restart(tmp_path):
    key = secrets.token_bytes(32)
    contract = {"task_id": "t", "capability_id": "c", "session_id": "s",
                "expires_at": int(time.time()) + 60,
                "grants": [{"operation": "api_post", "resource": "sim:publish", "approval": True}]}
    boot = {"key_hex": key.hex(), "contract": sign(key, b"sentinel-contract-v1\0", contract), **fixtures()}
    approval = sign(key, b"sentinel-approval-v1\0", {
        "task_id": "t", "capability_id": "c", "session_id": "s", "operation": "api_post",
        "resource": "sim:publish", "body_sha256": hashlib.sha256(b"").hexdigest(),
        "nonce": "unique", "expires_at": contract["expires_at"]})
    for expected in ["authorized", "approval_replayed"]:
        p = launch(boot, tmp_path / "audit.sqlite")
        assert json.loads(p.stdout.readline())["ready"]
        g = Gateway(p, "t", "c")
        assert g.call("api_post", "sim:publish", approval=approval)["reason"] == expected
        finish(p)


def test_oversized_frame_terminates_without_execution(controller):
    with pytest.raises(GatewayUnavailable):
        controller.gateway.call("write_file", "reports/summary.md", "x" * 70000)
    controller.process.wait(timeout=5)
    assert controller.process.returncode != 0
    with closing(sqlite3.connect(controller.audit_path)) as db, db:
        assert db.execute("SELECT SUM(executed) FROM audit").fetchone()[0] == 0


def test_authorized_malicious_content_is_known_limitation(controller):
    """Authorization does not validate the semantic correctness of allowed writes."""
    content = "An incorrect summary supplied by untrusted content."
    assert controller.gateway.call("write_file", "reports/summary.md", content)["executed"]
    assert controller.gateway.call("read_file", "reports/summary.md")["data"] == content


def test_second_bootstrap_cannot_change_authority(controller):
    boot = {"key_hex": secrets.token_hex(32), "contract": {}, **fixtures()}
    assert controller.gateway.raw(boot)["reason"] == "malformed_request"
    assert controller.gateway.call("read_file", "secrets/demo.txt")["decision"] == "DENY"


def test_denied_write_preserves_existing_virtual_file(controller):
    before = controller.gateway.call("read_file", "README.md")["data"]
    denied = controller.gateway.call("write_file", "README.md", "unauthorized replacement")
    assert denied["decision"] == "DENY" and not denied["executed"]
    assert controller.gateway.call("read_file", "README.md")["data"] == before
