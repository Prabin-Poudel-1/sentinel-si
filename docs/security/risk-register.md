# Risk register

| Risk | Severity | Status / owner action |
|---|---|---|
| Production authentication/hosting integration not verified | High assurance gate | Public API disabled; owner must validate real OAuth, HTTPS, service binding and free CPU budget |
| Final release identity and scan coverage | High publication gate, partially closed | Official repository/private reporting established; clean nine-commit Gitleaks scan maintainer-reported. Refresh for final tag/artifacts; see Phase 1 evidence |
| Linux/Windows native credential storage not exercised | High activation gate for real cloud credentials | No plaintext fallback; local tests use explicit MemoryTestCredentials; macOS native synthetic lifecycle passed; owner validates remaining stores |
| Free-tier quota exhaustion / global rate-limit denial of service | Medium accepted beta constraint | Cloud may be unavailable; bounded queues and local enforcement remain; monitor and cap beta population |
| Compromised device submits false/covert metadata | Medium inherent | Self-reported label, schema restricts channels; not trusted attestation or data-loss prevention |
| Same-UID process/admin bypasses Python controller or tampers with host | High outside promised boundary | Do not run arbitrary hostile Python; future process/OS sandbox required |
| SDK integrator exposes a bypass tool | High integration error | Explicit integration contract; Sentinel only governs routed tools; no universal protection claim |
| Unsigned/unnotarized release or compromised account/checksum | Medium | Four-platform CI passed and physical Apple Silicon testing is reported; Gatekeeper may still block quarantined downloads. Signing/notarization remains open; never require disabling protections |
| Windows native isolation unverified | High unsupported capability | Host-file tools disabled; no verified native release; WSL2 documented separately |
| Recent event replay after deletion/retention | Low | Dedup lasts while retained; metadata only, never re-executes a tool; document limitation |
| Coarse protected-flow restrictions / false denials | Medium research limitation | Preserve explicit experimental label and deterministic evaluation; no semantic flow claim |
| Local state parent races / hostile trusted-host user | Medium outside fixture isolation | Descriptor checks reduce path attacks; trusted parent and OS user remain required |
| Cloud deletion vs provider backups | Low privacy limitation | Application cascade tested; provider retention disclosed, no physical-erasure guarantee |

Acceptance is limited to local research verification. Open public-release gates are
not accepted by declaring a passing local test suite; production remains disabled.
