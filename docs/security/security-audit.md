# Engineering security review — 0.3.0-rc.1

Review date: 2026-10-14. Scope: source, local/cloud trust boundaries, typed SDK, sync,
auth/session and pairing APIs, migrations, frontend rendering, release inputs and CI.
This is an implementation-team review and regression exercise, **not an independent
penetration test or certification**. Synthetic local fixtures only; no production attacks.

## Findings and dispositions

| ID / severity | Evidence, attack surface and impact | Mitigation / verification |
|---|---|---|
| S01 Medium — fixed | POSIX `private_directory(initialize=False)` did not validate owner/mode/linked children; init chmod followed root links. Misconfigured local state could expose/redirect auth data. | Pinned O_NOFOLLOW/O_DIRECTORY descriptor, fstat/fchmod, owner/mode checks, reject linked child state. Five new POSIX regression cases. Trusted parent/same-UID assumption remains. |
| S02 Medium — fixed | Worker assets initially pointed to `web/`, potentially serving frontend source/config instead of only public assets. | Both runtime and E2E configs now serve `web/dist`; browser public-page/CSP checks pass. No secrets existed in frontend source. |
| S03 Medium — fixed | 50 individual telemetry inserts plus authentication/quota queries exceeded Free D1's 50-query limit. | Max25 events in both client/server; query-count regression checks maximum batch. |
| S04 Medium — fixed | In-flight device token rotation/revocation could race an earlier authentication read. | Write SQL rechecks current token, revocation, expiry and sync consent; acknowledgement rechecks active status. Pairing consumption and rotation are atomic conditional SQL. Revocation tests and concurrency pairing case pass. Previously authorized in-flight writes may linearize before revocation. |
| S05 Medium — mitigated | Unbounded public abuse can exhaust free quotas; dashboard scans and rate counters also consume quota. | Exact body limits, bounded pagination, per-device/user/global throttles, ingestion day limits and retention; quota/D1 failure tests. Deliberate cloud denial-of-service remains possible; local gateway independent. |
| S06 Low — fixed | Floating workflow action tags and broad artifact copying increase supply-chain risk. | Full action SHAs verified from upstream refs; read-only tokens, no secret-bearing PR jobs; allowlisted runtime/source builders and scanners, verified local installer. |
| S07 Low — fixed/excluded | Compiler paths and XML reports contained the local machine's username/path. | Remapped release build paths, generic documentation paths, raw reports excluded from source/runtime artifacts; scanner reports no matches. |
| S08 High release gate — disabled/unverified | Production OAuth, real hosted cookie/service-binding behavior, cross-platform native keyring and edge free CPU limit cannot be established by mocks. Unsafe activation without validation would expose public authentication/credentials to unverified integration. | PRODUCTION_ENABLED=false; exact owner-run staging/production checklist before enabling. No production compatibility claim. This is an assurance gap, not a demonstrated exploitable flaw. |
| S09 High publication gate — partially closed | Official repository and private disclosure are now recorded in SECURITY.md; a clean nine-commit Gitleaks history scan is maintainer-reported. | Refresh scanning for the final tag/artifacts and confirm release identity/license. Completed four-platform CI does not authorize publication. See the Phase 1 evidence. |

No demonstrated unresolved Critical/High exploit was found in the locally enabled
supported paths. That is not proof none exists. Public activation remains NOT READY
because S08/S09 gates are open. Native Windows isolation remains disabled/unverified.

## Controls examined

Rust default-deny Cedar and signed contracts/expiry/exact scope retained unchanged.
Approval body/task/session/nonce binding, replay rejection, revocation, protected flow,
Wasm imports/fuel/memory and descriptor-pinned file race tests remain. Python gateway
fails closed on invalid responses/transport failure; SDK adds no fallback executor.
External content never authorizes permissions. Arbitrary hostile Python is excluded.

Cloud SQL is parameterized. Browser ownership comes only from hashed expiring session;
mutations require CSRF+Origin. Device bearers/codes are random, hashed at rest, rotated
and revocable. OAuth uses one-use state, S256 PKCE, exact callback and redirects disabled
for upstream requests; mocked upstream verification only. No raw request/body logs.
Frontend uses textContent, CSP and same-origin API, with no token localStorage. Data
is labeled self-reported and historical, never a confirmed attack or persistent online
status. Sync cannot approve, change contracts or send local commands.

## Audit limitations

The initial workspace lacked Git history. The official repository now exists, with a
maintainer-reported clean Gitleaks history scan of nine commits. The reviewed main
contains 11 reachable commits; no full-current-history scan is claimed by this update. Private local
state was identified by location and excluded, not printed or copied. High-signal
secret scanning is not exhaustive entropy analysis. Dependency audits found no known
advisories at run time; they do not certify dependency safety. macOS/Linux tests are
historical local execution. Remote release Actions now passed on four macOS/Linux
targets, and Windows Server regression CI passed. Native Windows 10/11, WSL2, direct
ChatGPT/Claude integrations, production cloud and Linux Secret Service remain unverified.
See [Phase 1 evidence](../release-validation-v0.3.0-rc.1.md).
A separate macOS native Keychain synthetic lifecycle passed and removed its test entry. See the final engineering report
for exact counts, commands and failed-check corrections.
