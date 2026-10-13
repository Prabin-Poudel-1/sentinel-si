# Phase 1 validation record

> Historical Phase 1 baseline. For current Phase 2 behavior, trust boundaries,
> tests and limitations, read the [Phase 2 engineering report](phase2-engineering-report.md).

Validated locally on 2026-10-12 with Rust 1.99.0 and Python 3.9.6.

- `cargo test --locked`: 5 Rust tests passed.
- `python -m pytest -q`: 68 Python security/transport/workflow tests passed.
- `cargo clippy --locked --all-targets -- -D warnings`: passed.
- `cargo fmt --all -- --check`: passed.
- Clean, injected and approval/replay demos completed; every event matched its audit row.
- Host symlink redirection, malformed response and partial-response timeout tests passed.
- The gateway-only benchmark completed 30 runs per scenario: 60/60 tasks completed,
  0/120 injected unauthorized proposals executed, and 0/300 false denials.

The source bundle excludes build caches, environments and test databases. Rust dependencies and the Pytest version
are pinned by Cargo.lock and requirements-dev.txt. No commits, pushes or deployments
were made. Dependency downloading was the only development network activity besides
reading public research sources in the earlier milestone; the agent tools never make network calls.

## This workspace's local tooling

Rust and Pytest were installed under the surrounding workspace's `work/` directory,
without modifying the shell profile. From this repository the local commands can be
run with:

```sh
export RUSTUP_HOME="$(cd ../../work/toolchain/rustup && pwd)"
export CARGO_HOME="$(cd ../../work/toolchain/cargo && pwd)"
export PATH="$CARGO_HOME/bin:$PATH"
export PYTHON="$(cd ../../work/venv/bin && pwd)/python"
./scripts/verify.sh
"$PYTHON" -m benchmarks.run --repetitions 30
```

These relative paths describe this delivery workspace only. On another machine use
the standard setup in README.md. `scripts/verify.sh` does not install dependencies.

## Findings fixed and remaining failures

Inspection found an executable unprotected comparison backend in the prior research demo.
It was removed from active source, imports, tests and benchmark execution. The current
agent has no available unprotected tool backend. Historical JSON metrics remain only as
records; the previous milestone archive is not the current Phase 1 delivery.

Inspection also found that the old client called blocking `readline()` after a readiness
check, allowing a response prefix without a newline to hang indefinitely. The replacement
uses bounded pipe reads/writes under one deadline, validates complete responses and closes
the client on failure. Tests exercise stalled and partial responses.

No final validation check failed. These passes do not establish an OS sandbox, live-model
robustness, human identity authentication or semantic correctness of allowed writes.
An explicit regression test confirms the latter limitation: malicious content is allowed
when its destination is already authorized. Phase 2 addresses these remaining boundaries.
