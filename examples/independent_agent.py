"""Run: python -m examples.independent_agent. No model/API dependency required."""
from sentinel_sdk import Proposal, TrustedSession


def independent_agent(tools):
    """Replace proposal generation with any model; tools still enforce each call."""
    for proposal in [Proposal("read_file", "README.md"),
                     Proposal("write_file", "reports/summary.md", "Synthetic summary"),
                     Proposal("read_file", ".env"),
                     Proposal("api_post", "sim:publish", "Synthetic summary")]:
        result = tools.request(proposal)
        # Deliberately omit resource names and returned document contents.
        print(proposal.operation, result.decision, result.executed, result.reason, result.event_id)


if __name__ == "__main__":
    with TrustedSession() as session:
        independent_agent(session.tools)
