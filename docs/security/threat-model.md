# Public candidate threat model

## Assets and trust boundaries

Local signing authority, approval credentials, task contracts and raw audit/tool data
stay on the trusted host. An untrusted model proposes typed actions through SDK →
Python transport → Rust/Cedar → constrained executor → local SQLite. Only the trusted
controller bootstraps signed authority. Simulated APIs cannot reach external networks;
fixed Wasm code has no imports. Descriptor-pinned Unix tools operate private fixtures.

A separate opt-in sync client exports an exact metadata allowlist over HTTPS using a
native credential store. The cloud Worker authenticates browser sessions or device
bearers and scopes every query to server-derived ownership. D1 contains metadata and
hashed bearer/session/enrollment values. GitHub access tokens exist only during login,
are not persisted, and carry no requested additional OAuth scopes. Pages uses a fixed
service binding to the Worker. There is no inbound laptop listener for cloud commands.

## Adversaries and controls

| Adversary | Attempt | Control / residual assumption |
|---|---|---|
| Malicious document/model | Expand task authority, exfiltrate or execute shell | Strict proposals, signatures, exact grants, default deny, no such executor; model can still choose bad allowed actions |
| Anonymous cloud user | Guess codes, forge login, exhaust quotas | Random 256-bit codes/tokens, hashed storage, PKCE/state, bounded input, durable throttles; free-tier denial of service remains possible |
| Malicious account | Access another account/device, stored XSS, SQL injection | Server-derived ownership, parameterized SQL, exact payload schema, textContent rendering, CSP |
| Compromised account | Read/delete metadata, enroll/revoke devices | Reauthentication for account deletion, session/device revocation; cannot obtain local signing authority |
| Stolen device bearer | Forge metadata | Expiration, rotation, revocation and bounded ingestion; bearer possession suffices until revoked |
| Compromised endpoint | False telemetry, local bypass | Cloud records explicitly self-reported; not remote attestation; hostile same-UID Python or admin compromises are outside isolation scope |
| Malicious integration | Provide alternate tool path | SDK exposes gateway-only calls; integrator must remove all bypass paths; SDK wrapper is not an OS sandbox |
| Compromised dependency/release | Execute trusted malicious software | Locks, audits, SHA-pinned workflows, explicit artifact allowlist/checksums; signing/notarization/independent rebuild remain unverified |
| Quota abuse/cloud outage | Exhaust free service | 429/503 and bounded offline queue; authorization never queries the cloud |

## Explicit exclusions

No arbitrary local directory mounting, arbitrary Wasm upload/native execution,
production API attack tests, remote local approvals or cloud policy modification.
Native Windows file isolation remains disabled; use the documented Linux/WSL2 route.
A trusted parent directory and OS user are required for local state; checking a
pinned inode does not protect against a hostile parent owner or same-UID process.
No independent audit, adversarial penetration certification or immunity is claimed.
