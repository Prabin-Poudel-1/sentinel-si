# Threat model and security assumptions

> Historical Phase 1 baseline. For current Phase 2 behavior, trust boundaries,
> tests and limitations, read the [Phase 2 engineering report](phase2-engineering-report.md).

## Protected properties

Within the tool protocol, an action executes only if an authentic, unexpired task
contract grants the exact operation and resource and any required approval is valid.
Untrusted content cannot create grants. Approvals authorize one exact action once.
Audit failure prevents subsequent execution. Rejected requests return no file content.

## Attacker control

The adversary controls repository documents, simulated API responses and arbitrary
agent request fields. It can request secrets, attempt path traversal, impersonate task
IDs, invent privileged tools, inject policy/context fields, forge approval tokens,
change an approved payload, replay approval tokens and send malformed/oversized frames.
The agent is assumed willing to follow malicious instructions. No classifier is trusted.

## Trusted computing base

- Local user and Python supervisor, including fixture/template selection and launch.
- Rust runtime, compiled Cedar policy, crypto implementation and SQLite dependencies.
- Host OS process memory/channel protections, clock, filesystem and private audit state.
- The simple transport and agent runner: untrusted instructions are data, never Python code.

Only synthetic content is used. Real passwords, API keys, tokens and confidential
files are never loaded. Ephemeral random HMAC bytes are test authority material, never
real service credentials and never printed or stored in the audit log.

## Explicit limitations

- This is a process-separated reference monitor for simulated tools, not an OS sandbox.
  The Python process has ambient OS privileges. Malicious Python code, a compromised
  supervisor, same-user process inspection, or direct host access defeats assumptions.
  Never execute attacker-provided code or attach unrestricted tools to this harness.
- HMAC establishes trusted-controller possession, not independently verified human
  identity. There is no multi-user authentication, remote API, revocation service,
  approval UI or key rotation system. Runtime and supervisor share signing authority.
- Agent tool outputs carry provenance labels only. No taint propagation or data-flow
  restrictions exist. Malicious edits *within* an allowed write, or disclosure through
  an already authorized destination, can still succeed. Task quality and semantics are
  not established by authorization. Sensitive-name blocking is a small guardrail,
  not a general confidential-data classifier.
- Exact path matching is virtual. Symlink, hard-link, mount, TOCTOU and URL/DNS attacks
  are absent by construction, not solved for a real executor.
- A privileged local attacker can modify SQLite or roll back/delete its replay ledger.
  Restart replay protection assumes the same intact database. Fresh random sessions
  prevent ordinary cross-launch token reuse. Audit records are not cryptographically sealed.
- Wall-clock rollback can extend effective permission lifetime. Clock integrity is
  assumed. Quotas limit some resource use but do not establish availability guarantees.
- Single-threaded service serialization is intentional. Distributed/concurrent
  execution, persistent tool state and crash-atomic external effects are not implemented.
- Repeated synthetic fixtures are narrow evidence. There is no independent audit,
  formal proof, live-model attack success measurement or production security claim.

## Test-to-threat mapping

| Threat | Mechanism | Evidence |
|---|---|---|
| Repository/API prompt injection | Scope independent of content | Injected proposals denied with correlated audit records |
| Sensitive or unauthorized file read | Exact grants plus reserved segments | Black-box denials with no data |
| Traversal/ambiguous path | Strict grammar | Parameterized malformed-path tests |
| Real network or shell attempt | No such executor | Unknown tool and URL tests |
| Contract tampering/self-escalation | HMAC, immutable bootstrap, strict fields | Tamper/domain/context tests |
| Expired task or approval | Runtime clock | Boundary unit and live-session tests |
| Forged/rebound/replayed approval | MAC, exact binding, durable nonce | Payload/session/restart tests |
| Audit/engine failure | Fail-closed errors, no fallback | Rust audit-failure and process-death tests |
| Secret-bearing logs | Fixed metadata only | Audit redaction test |

Future real execution must use verified isolation and OS-enforced capability boundaries
before making stronger claims. The first milestone deliberately provides no real attack
execution path into production services.

## Phase 1 completion boundary

All four registered virtual operations route through Rust. The active repository contains
no unprotected executor, shell tool, URL client or policy-edit operation. This is the
meaning of gateway-only execution in this phase. The trusted Python launcher can start
processes and load fixtures; that capability is not registered with the agent. A claim
against arbitrary Python code or a hostile local OS user would require a real isolation
boundary and is explicitly not made.

Host symlink replacement and rejected `symlink` tool proposals are tested. The runtime
never resolves host paths for agent operations, so real filesystem TOCTOU races are not
covered. The trusted launcher's fixture materialization and custom audit path rely on
the host-user trust assumption. A future real adapter must defend symlink/hardlink/mount
races using OS primitives rather than extending the current string validator.
