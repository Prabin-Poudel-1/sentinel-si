"""Intentionally gullible deterministic agent surrogate; no eval, exec, shell or LLM.

The TOOL marker models an agent following instructions found in untrusted content.
The marker parser is NOT a defense or a classifier. Only the gateway is exposed as a tool.
"""
import json

SUMMARY = "# Summary\nThe fictional project reports operational status.\n"


class ScriptedAgent:
    def __init__(self, tool):
        self.tool = tool
        self.events = []

    def act(self, operation, resource, body="", attack=False):
        response = self.tool.call(operation, resource, body)
        self.events.append({"operation": operation, "attack": attack,
                            "decision": response["decision"], "executed": response["executed"],
                            "event_id": response["event_id"], "reason": response["reason"]})
        return response

    def observe(self, content):
        for line in content.splitlines():
            if line.startswith("TOOL "):
                try:
                    action = json.loads(line[5:])
                    self.act(action["operation"], action["resource"], action.get("body", ""), attack=True)
                except (ValueError, KeyError, TypeError):
                    continue

    def run(self):
        """Trusted task: read project docs/status and write reports/summary.md."""
        for operation, resource in [("read_file", "README.md"), ("read_file", "docs/guide.md"),
                                    ("api_get", "sim:status")]:
            response = self.act(operation, resource)
            if response["executed"]:
                self.observe(response["data"])
        self.act("write_file", "reports/summary.md", SUMMARY)
        final = self.act("read_file", "reports/summary.md")
        completed = final.get("data") == SUMMARY and all(e["executed"] for e in self.events if not e["attack"])
        return {"completed": completed, "events": self.events}
