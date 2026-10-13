"""Bounded platform-specific pipe transport. No execution fallback, including on partial responses."""
import json
import threading
from agent_harness.transport import exchange


class GatewayUnavailable(RuntimeError):
    pass


class Gateway:
    def __init__(self, process, task_id, capability_id, timeout=5):
        self._process = process
        self.task_id = task_id
        self.capability_id = capability_id
        self._timeout = timeout
        self._lock = threading.Lock()
        self._failed = False

    def call(self, operation, resource, body="", approval=None):
        return self.raw({"task_id": self.task_id, "capability_id": self.capability_id,
                         "operation": operation, "resource": resource,
                         "body": body, "approval": approval})

    @staticmethod
    def _validate(response):
        if not isinstance(response, dict):
            raise ValueError("Invalid response")
        decision = response.get("decision")
        if decision not in {"ALLOW", "DENY", "REQUIRE_APPROVAL"}:
            raise ValueError("Invalid decision")
        if type(response.get("executed")) is not bool:
            raise ValueError("Invalid execution status")
        if response["executed"] != (decision == "ALLOW"):
            raise ValueError("Inconsistent execution status")
        if type(response.get("event_id")) is not int or response["event_id"] <= 0:
            raise ValueError("Missing audit correlation")
        if not isinstance(response.get("reason"), str):
            raise ValueError("Invalid reason")
        if decision == "ALLOW":
            if (not isinstance(response.get("data"), str)
                    or response.get("provenance") not in {"untrusted_tool_output", "untrusted_protected_output"}):
                raise ValueError("Invalid tool output")
        elif response.get("data") is not None or response.get("provenance") is not None:
            raise ValueError("Rejected request leaked output")
        return response

    def raw(self, request):
        # One request/response at a time; prevent two callers interleaving frames.
        with self._lock:
            if self._failed:
                raise GatewayUnavailable("Gateway closed; no fallback execution")
            try:
                wire = (json.dumps(request, separators=(",", ":"), allow_nan=False) + "\n").encode()
                received = exchange(self._process, wire, self._timeout)
                return self._validate(json.loads(received))
            except (OSError, ValueError, TypeError, EOFError) as exc:
                self._failed = True
                if self._process.poll() is None:
                    self._process.kill()
                raise GatewayUnavailable("Gateway failed closed; no fallback execution") from exc
