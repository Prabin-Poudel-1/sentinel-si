# Research positioning

> Historical Phase 1 baseline. For current Phase 2 behavior, trust boundaries,
> tests and limitations, read the [Phase 2 engineering report](phase2-engineering-report.md).

## Hypothesis H1

For a fixed workload with independently specified task grants, moving authorization
and virtual execution into a trusted reference monitor will reduce execution of
out-of-scope agent proposals relative to the same unprotected agent, while preserving
completion of in-scope tasks. The decision must be independent of whether the proposal
was prompted by a user, repository document or API response.

Milestone one tests this at the tool boundary with a deterministic, deliberately
susceptible agent. This is an engineering hypothesis and regression baseline, not a
claim that the defense is novel or that arbitrary agents become immune to injection.
A failure is any executed proposal outside the authentic contract, any valid approval
replay, or an unexpected denial of a predefined legitimate operation.

## Established approaches and comparison

| Approach | Established method | Relationship to this milestone |
|---|---|---|
| AgentDojo | Dynamic benchmark of tool-using agents facing untrusted inputs; measures attacks and utility | Inspires paired security/utility evaluation. Our four injected proposals are synthetic and are not AgentDojo results. |
| CaMeL | Separates control/data flow and uses capabilities to constrain unauthorized data flows | Stronger information-flow motivation than this milestone. We only enforce action/resource scope and attach an untrusted label; no CaMeL-style interpreter or flow tracking. |
| Cedar | Decoupled authorization with default deny and forbid-overrides-permit | Used as an actual policy engine, after cryptographic and structural validation. Rust handles approval state; Cedar is not a sandbox. |
| NVIDIA OpenShell | Agent runtime with kernel-enforced sandbox and policy-controlled access | Illustrates enforcement outside the agent and real execution isolation. This prototype uses virtual tools and does not reproduce or validate OpenShell's isolation guarantees. |
| Wasmtime/WASI | WebAssembly isolation plus explicitly provided host functionality | Candidate future isolated executor. The safety of host functions and granted resources remains part of the design; not integrated here. |

Primary sources:

- [AgentDojo paper](https://arxiv.org/abs/2406.13352) and
  [official implementation](https://github.com/ethz-spylab/agentdojo).
- [CaMeL: Defeating Prompt Injections by Design](https://arxiv.org/abs/2503.18813).
- [Cedar authorization semantics](https://docs.cedarpolicy.com/auth/authorization.html)
  and [security guidance](https://docs.cedarpolicy.com/other/security.html).
- [NVIDIA OpenShell official repository](https://github.com/NVIDIA/OpenShell).
- [Wasmtime security documentation](https://docs.wasmtime.dev/security.html).

Sources reviewed 2026-10-12. The comparison describes documented approaches, not
independent validation of third-party security claims. No benchmark scores from other
systems are treated as directly comparable to this experiment.

## Potential Sentinel AI contributions

Capability security, reference monitors, default-deny policies, sandboxing, and
prompt-injection defenses are existing work. This milestone contributes a small
reproducible integration and adversarial test corpus. That alone is not an established
research novelty claim.

A possible subsequent contribution is a task-contract lifecycle that combines exact
single-action approvals, provenance-derived flow constraints, and isolated execution,
with experiments separating each mechanism's effect on security, utility and overhead.
Novelty requires a broader literature review, baseline implementations, ablations and
external evaluation. An eventual claim should name the new mechanism or empirical
finding, rather than relabel capability-based security as new.

## Next evaluation design

1. Predefine legitimate outcomes and adversarial objectives independently of policies.
2. Add varied tasks and attacks, held-out workloads, and a policy-authoring error set.
3. Compare no enforcement, action allowlists, task contracts, and provenance controls.
4. Add AgentDojo with an explicit model/version and controlled untrusted tool outputs.
5. Record attack execution and legitimate completion separately, plus false denials,
   approval burden, p50/p95 latency, and failures under restarts/concurrency.
6. Report uncertainty across genuinely varied tasks and models; repeated identical
   scripts alone do not justify population-level confidence intervals.

## Phase 1 update

The earlier unprotected comparison is historical evidence, retained as JSON under
`benchmarks/history/`. Its executable backend was removed to satisfy the current
gateway-only requirement. Benchmark version 2 evaluates clean and injected workloads
through the enforced runtime only. No current command reproduces the historical
unprotected arm. Any future comparative study needs a separately isolated research
fixture, never a bypass switch in the operational agent.
