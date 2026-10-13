# Development roadmap

## Delivered foundation

Phase 1 established the Rust/Cedar gateway, immutable signed task contracts,
simulated tools, audit records, approval replay checks and deterministic regressions.

Phase 2 adds local administrator authentication, an exact-action approval queue,
revocation, descriptor-pinned real file tools, a bounded import-free Wasmtime
component, experimental sticky provenance, an optional local-model adapter,
four-arm research comparisons, and an audit-backed dashboard. See the
[engineering report](phase2-engineering-report.md) for actual validation.

## Subsequent work

1. Independent security review and expanded attack/benign-task corpus.
2. Live-model experiments and AgentDojo integration with comparable denominators.
3. Value-level provenance, explicit declassification and cross-task flow policies.
4. Durable lifecycle/revocation and crash reconciliation without duplicate execution.
5. Verified Linux native execution boundaries and constrained nested path resolution.
6. Multiuser identity, remote transport security and tamper-evident audit.
7. Matched performance ablations and resource saturation tests.

Native execution, arbitrary WASI programs, full information-flow security and
production deployment remain unavailable. Do not interpret this roadmap as
implemented capabilities.

## Windows portability gate

Native Windows 10/11 code and Windows CI are implemented as an unverified candidate.
Client OS builds, DACL/reparse tests, Wasm and dashboard runs must pass before claiming
compatibility. Native agent file isolation remains disabled; WSL2 uses the Linux path.
See [the Windows guide](windows.md).
