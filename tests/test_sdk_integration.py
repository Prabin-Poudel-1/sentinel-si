import pytest
from sentinel_sdk import Proposal, TrustedSession, GatewayUnavailable


def test_sdk_independent_controller_gateway():
    with TrustedSession() as session:
        result = session.tools.request(Proposal("read_file", "README.md"))
        assert result.executed and result.decision == "ALLOW" and result.event_id > 0
        denied = session.tools.request(Proposal("read_file", ".env"))
        assert not denied.executed and denied.decision == "DENY" and denied.data is None
        approval = session.tools.request(Proposal("api_post", "sim:publish", "test"))
        assert approval.decision == "REQUIRE_APPROVAL" and not approval.executed
    with pytest.raises(GatewayUnavailable):
        session.tools.request(Proposal("read_file", "README.md"))


@pytest.mark.parametrize("args", [("shell", "ls"), ("read_file", None), ("write_file", "x", None), ("write_file", "x", "a" * 32769)])
def test_sdk_rejects_invalid(args):
    with pytest.raises(ValueError):
        Proposal(*args)
