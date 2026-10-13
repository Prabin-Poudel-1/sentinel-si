"""Typed integration surface. These objects are not an OS isolation boundary."""
from dataclasses import dataclass
from typing import Literal
from agent_harness.gateway import Gateway, GatewayUnavailable
from agent_harness.supervisor import Supervisor

Operation = Literal["read_file", "write_file", "api_get", "api_post", "isolated_read", "isolated_write", "wasm_run"]
OPERATIONS = frozenset(Operation.__args__)


@dataclass(frozen=True)
class Proposal:
    operation: Operation
    resource: str
    body: str = ""

    def __post_init__(self):
        if self.operation not in OPERATIONS or type(self.resource) is not str or type(self.body) is not str:
            raise ValueError("Invalid proposal")
        if len(self.resource.encode()) > 1024 or len(self.body.encode()) > 32768:
            raise ValueError("Proposal exceeds limits")


@dataclass(frozen=True)
class Result:
    decision: str
    executed: bool
    reason: str
    event_id: int
    data: str | None = None
    provenance: str | None = None
    authorization_ns: int = 0


class AgentTools:
    """Expose only request() to a model's tool dispatcher, never arbitrary Python."""
    def __init__(self, gateway: Gateway):
        self.__gateway = gateway

    def request(self, proposal: Proposal) -> Result:
        if not isinstance(proposal, Proposal):
            raise TypeError("Expected a Proposal")
        return Result(**self.__gateway.call(proposal.operation, proposal.resource, proposal.body))


class TrustedSession:
    """Trusted local controller creates and signs a task. Do not expose to agents.

    The contract/template is administrator configuration, never model output.
    Authentication/approval stays with the existing control plane. This convenience
    API intentionally offers no approval, contract-edit, shell or fallback method.
    """
    def __init__(self, *, template=None, injected=False, audit_path=None, isolated=False):
        self.__supervisor = Supervisor(template=template, injected=injected,
                                       audit_path=audit_path, isolated=isolated)
        self.tools = AgentTools(self.__supervisor.gateway)

    def close(self):
        self.__supervisor.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


__all__ = ["Proposal", "Result", "AgentTools", "TrustedSession", "GatewayUnavailable"]
