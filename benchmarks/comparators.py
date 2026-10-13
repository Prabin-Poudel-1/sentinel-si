"""RESEARCH ONLY. No host filesystem, sockets, authentication keys or runtime fallback.

Not imported by the application/control plane. These in-memory comparison arms
are explicitly requested experiment baselines, not available agent tool backends.
"""
import copy


class Comparator:
    def __init__(self, arm, fixture, grants):
        self.arm = arm
        self.fixture = copy.deepcopy(fixture)
        self.grants = grants
        self.sequence = 0

    def call(self, operation, resource, body=""):
        self.sequence += 1
        reason = "simulated"
        decision = "ALLOW"
        if self.arm == "B_basic_tools" and operation not in {"read_file", "write_file", "api_get"}:
            decision = "DENY"
        if self.arm == "C_static_policy":
            grant = next((g for g in self.grants if (g["operation"], g["resource"]) == (operation, resource)), None)
            if grant is None or resource.startswith("secrets/") or resource == ".env":
                decision = "DENY"
            elif grant["approval"]:
                decision = "REQUIRE_APPROVAL"
        data = None
        if decision == "ALLOW":
            if operation == "read_file":
                data = self.fixture["files"].get(resource)
            elif operation == "write_file":
                self.fixture["files"][resource] = body
                data = "written"
            elif operation == "api_get":
                data = self.fixture["apis"].get(resource)
            elif operation == "api_post" and resource in self.fixture["apis"]:
                data = "simulated request accepted"
            if data is None:
                decision = "DENY"
        return {"event_id": self.sequence, "reason": reason, "decision": decision,
                "executed": decision == "ALLOW", "data": data}
