# Sentinel AI public candidate — engineering report

Candidate: **0.3.0-rc.1**, reviewed 2026-10-14.
Status: **functional local candidate; NOT READY for public activation**.
No commits, pushes, releases, deployments, external account changes or public laptop
listeners were created. Download buttons intentionally remain disabled until the owner
supplies a verified official repository/release. Production API fails closed by default.

## What works

**IMPLEMENTED:** the existing independent Rust/Cedar gateway remains the execution
boundary. New typed Python SDK and independent example reuse it. Optional sync is
separate, off by default, metadata-only, HTTPS outbound, native-keyring-only in production,
with queue limits, retry, dedup, rotation and revocation. Workers/D1 implement GitHub
OAuth code/state/PKCE, hashed sessions, CSRF, ownership, one-use pairing, telemetry,
retention and deletion. Pages-compatible public pages and an observational dashboard
render actual account records. No cloud route can approve local operations or modify
trusted contracts. Default-deny, replay/revocation, Wasm and provenance tests remain.

**TESTED:** the full local journey works against actual Wrangler/workerd/D1 and the
compiled Rust gateway: two synthetic identities, pair, ALLOW/ALLOW/DENY/REQUIRE_APPROVAL,
four SQLite audit records, consented metadata upload, real Chrome dashboard, two-account
isolation, rotation, actual Worker stop, continued local enforcement, restart/retry,
revoked upload rejection and local disconnect cleanup. Browser checks also cover mobile
layout, static security headers and inert hostile text rendering (the latter explicitly
uses a separate mocked hostile response). No production OAuth result is inferred.

**PARTIALLY VERIFIED:** OAuth flow is implemented and mocked-upstream tested; session,
CSRF and pairing behavior are tested on local Workers. Native keyring selection fails
closed and is unit-tested with injected stores; a separate native macOS Keychain smoke test stored/read/replaced/deleted a temporary synthetic entry successfully. No existing credentials were read.
Free-tier capacity was checked against official limits, with query-count/quota tests,
but real edge CPU/usage and hosted bindings remain unmeasured. Release workflows are
prepared and SHA-pinned, not dispatched. Artifacts are unsigned and unnotarized.

**NOT VERIFIED:** real GitHub OAuth, hosted Cloudflare/D1/Pages, production HTTPS and
cookie configuration, Linux/Windows native credential persistence, Intel macOS, Windows10/11,
WSL2 itself, remote CI and independent reproducibility/security certification.
Historical Qwen reports are retained; Qwen was not re-run for this cloud extension.

**BLOCKED:** official public URLs/disclosure channel and history audit need the actual
repository and owner account configuration. Production activation and publication remain
disabled pending those and the production/keyring verification checklist.

## Verification results

| Check | Actual result |
|---|---|
| Fresh pre-change macOS Python baseline |141 passed,4 Windows-only skipped |
| Fresh pre-change Rust baseline |10 passed |
| Updated macOS Python suite |166 passed,4 Windows-only skipped |
| Updated Linux-container Python suite |166 passed,4 Windows-only skipped |
| Updated Rust tests, macOS and Linux |10 passed on each |
| Rust formatting and Clippy |Passed, warnings denied |
| Cloud security/unit tests |27 passed; real SQLite adapter, mocked OAuth upstream |
| Full local public E2E |12 checks passed with actual Wrangler/D1/Rust and Chrome |
| Public browser |7 checks passed; desktop/mobile screenshots saved |
| Native macOS Keychain |4 synthetic lifecycle checks passed; entry removed; authentication UI disabled |
| macOS and Linux ARM64 bundled installers |6 checks each: checksum, offline install, actual gateway, overwrite refusal, uninstall, tamper rejection |
| Existing local admin browser |Passed; retained approval/replay/revocation journey |
| Existing synthetic benchmark |3 repetitions, seed1729; full Sentinel arm0/18 unauthorized execution,3/3 tasks completed,0 false denials; synthetic only |
| Dependency audit |Rust242 locked packages, Python4 dev,5 macOS optional-sync and10 Linux optional-sync applicable packages, npm91 dependency tree: no known advisories reported |
| Source/runtime artifact scan |No high-signal secret/personal-path matches; explicit private-state/report exclusions |

The Python count includes20 SDK/sync cases and5 POSIX state-hardening cases added to
the141-test baseline. Four native Windows kernel/DACL/reparse cases skip on both Unix
hosts. Linux was a Docker Linux arm64 environment, not WSL or a native x64 laptop.

Failures encountered and corrected: an initial test command named a nonexistent file
(no tests ran; corrected to the existing phase2 suite); initial browser automation
tried to fill a collapsed development-login details panel (opened it, then passed);
initial release binary contained personal compiler paths (rebuilt with remapping);
initial third-party notice collection lacked unfetched non-host lockfile packages
(fetched locked packages, regenerated notices). An ad-hoc source-ZIP check initially used the wrong relative parent path; it was corrected and archive integrity passed. None is hidden as a passing initial run.
The audit also fixed asset-directory exposure, maximum-batch D1 query budget and local
state link/mode checks; see security/security-audit.md for severity and evidence.

## Files and architecture changed

| Area | Files/directories |
|---|---|
| Existing local hardening |agent_harness/platform_security.py; tests/test_local_hardening.py |
| SDK and external example |sentinel_sdk/; examples/independent_agent.py; tests/test_sdk_integration.py |
| Optional sync |sentinel_sync/; tests/test_sync_privacy.py; docs/integration.md; docs/sync.md |
| Cloud API |cloud/src/index.js; migrations/0001_initial.sql; package.json/lock; wrangler.toml; tests/worker.test.js; README.md |
| Public site/dashboard |web/build.py; dashboard_page.py; dist/; functions/api/[[path]].js; tests/browser_smoke.cjs |
| Local E2E |scripts/public_e2e.py; configure_cloud_dev.py |
| Packaging/security tooling |packaging/; scripts/build_release.py; build_source.py; test_install.py; scan_release.py; third_party.py |
| CI |Existing ci/windows-client actions pinned; new public-security.yml and release-candidate.yml |
| Documentation |README.md, SECURITY.md, LICENSE, .gitignore, docs/installation.md, deployment.md, architecture.md, security/*; generic paths in local-llm-integration.md |

Rust authorization/execution sources, model adapter and existing security policies
were preserved. No Git metadata exists, so this is a component change inventory,
not a fabricated Git diff. Source archives explicitly exclude private working state,
raw historical reports, build outputs and dependencies. Full evidence remains in the
local workspace; public-safe summary reports identify executed checks.

## Reproduce locally

From this project directory, with Rust1.99/Python3.12/Node22.13+ installed:

```sh
cargo build --locked
cargo fmt --all --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
.venv/bin/python -m pytest -q -ra
npm ci --prefix cloud
npm test --prefix cloud
.venv/bin/python scripts/public_e2e.py
# Install Playwright1.62.1 + its Chromium or use a local Chrome channel:
npm install --no-save --package-lock=false playwright@1.62.1
npx playwright install chromium
.venv/bin/python scripts/public_e2e.py --browser
.venv/bin/python -m examples.independent_agent
.venv/bin/python -m control_plane.demo --output reports/public-local-demo.json
.venv/bin/python -m benchmarks.phase2 --seed 1729 --repetitions 3 --output reports/public-benchmark.json
```

The execution environment used its existing workspace Rust toolchain and Python venv;
Chrome was selected with BROWSER_CHANNEL=chrome and the existing bundled Playwright
module. Docker tests ran network-disabled with read-only source and cached dependencies.

For interactive public-site development, follow cloud/README.md: create the explicit
loopback config with a hidden development-key prompt, migrate local D1, run Wrangler,
then visit http://127.0.0.1:8788. For the independent local administrator dashboard:

```sh
.venv/bin/python -m control_plane.server --init
.venv/bin/python -m control_plane.server --port 8787
```

Do not reinitialize existing state. Cloud account login never grants local administrator
rights. Optional live model command remains:

```sh
.venv/bin/python -m agent_harness.live --endpoint http://127.0.0.1:11434/v1/chat/completions --model qwen2.5:3b
```

For owner-run GitHub/Cloudflare publication steps, exact setup commands, secrets,
service binding, health checks and rollback, use [deployment.md](deployment.md).
Before enabling anything public, close [release-readiness.md](security/release-readiness.md).

Additional verification commands executed:

```sh
cargo audit --file Cargo.lock --json
python -m pip_audit -r requirements-dev.txt
python -m pip_audit -r requirements-sync.txt
npm audit --prefix cloud
python scripts/scan_release.py --source --artifacts release-artifacts
python scripts/build_source.py
python scripts/build_release.py
python scripts/test_install.py
# Explicit native-store test after installing requirements-sync.txt (macOS only):
python scripts/native_store_smoke.py
```

The optional-sync dependency audit was also run inside a fresh Linux Python3.12
container to include Secret Service dependencies. Both package installers ran as an
unprivileged user without network access. Rebuilding the macOS tarball twice from
identical inputs produced the same SHA256. The source ZIP CRC/integrity and exclusion
checks passed. Neither proves bit-for-bit independent compilation of Rust binaries.
