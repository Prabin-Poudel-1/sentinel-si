"""python -m benchmarks.run --repetitions 30 --output benchmarks/results.local.json"""
import argparse
import hashlib
import json
import platform
from pathlib import Path
import statistics
import time

from agent_harness.agent import ScriptedAgent
from agent_harness.supervisor import ROOT, Supervisor


class TimedTools:
    def __init__(self, inner):
        self.inner = inner
        self.latencies = []
        self.authorization = []

    def call(self, *args, **kwargs):
        start = time.perf_counter_ns()
        response = self.inner.call(*args, **kwargs)
        self.latencies.append(time.perf_counter_ns() - start)
        if response.get("authorization_ns") is not None:
            self.authorization.append(response["authorization_ns"])
        return response


def summarize(runs, latencies, authorization):
    events = [e for r in runs for e in r["events"]]
    attacks = [e for e in events if e["attack"]]
    legitimate = [e for e in events if not e["attack"]]
    unauthorized_executed = sum(e["executed"] for e in attacks)
    false_denials = sum(not e["executed"] for e in legitimate)
    values = sorted(latencies)
    return {"tasks": len(runs), "completed_tasks": sum(r["completed"] for r in runs),
            "legitimate_task_completion_rate": sum(r["completed"] for r in runs) / len(runs),
            "unauthorized_attempts": len(attacks), "unauthorized_executed": unauthorized_executed,
            "unauthorized_execution_rate": unauthorized_executed / len(attacks) if attacks else None,
            "legitimate_operations": len(legitimate), "false_denials": false_denials,
            "false_denial_rate": false_denials / len(legitimate),
            "tool_latency_median_us": statistics.median(values) / 1000,
            "tool_latency_p95_us": values[min(len(values) - 1, int(len(values) * .95))] / 1000,
            "allowed_authorization_median_us": statistics.median(authorization) / 1000 if authorization else None}


def evaluate(repetitions):
    results = {}
    for name, injected in [("clean", False), ("repository_and_api_injection", True)]:
        runs, latencies, authorization = [], [], []
        for _ in range(repetitions):
            with Supervisor(injected=injected) as controller:
                tools = TimedTools(controller.gateway)
                runs.append(ScriptedAgent(tools).run())
            latencies.extend(tools.latencies)
            authorization.extend(tools.authorization)
        results[name] = summarize(runs, latencies, authorization)
    return {"benchmark_version": 2, "repetitions_per_scenario": repetitions,
            "python": platform.python_version(), "platform": platform.platform(),
            "cargo_lock_sha256": hashlib.sha256((ROOT / "Cargo.lock").read_bytes()).hexdigest(),
            "contract_template_sha256": hashlib.sha256((ROOT / "contracts/report-task.json").read_bytes()).hexdigest(),
            "notes": ["Gateway-only evaluation; no unprotected executor is available.",
                      "Deterministic scripted agent, no model inference or production service.",
                      "Timings exclude service startup; default debug binary. No warm-up discarded.",
                      "Gateway time includes IPC, Rust validation, Cedar, SQLite and virtual execution.",
                      "Authorization time covers accepted requests through Cedar, excluding audit, execution and IPC.",
                      "Repeated identical fixtures measure timing variation, not independent security evidence.",
                      "Approval and lifecycle attacks are regression tests, not counted in this benchmark."],
            "scenarios": results}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--repetitions", type=int, default=30)
    p.add_argument("--output", type=Path, default=ROOT / "benchmarks/results.local.json")
    args = p.parse_args()
    if args.repetitions < 1:
        p.error("repetitions must be positive")
    result = evaluate(args.repetitions)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
