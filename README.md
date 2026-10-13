# Sentinel AI

**Public candidate 0.3.0-rc.1:** local SDK, opt-in metadata synchronization, Workers/D1
backend and a responsive observational cloud dashboard are implemented. The complete
local user journey passes with synthetic identities. **Public deployment is NOT READY**
until production OAuth/hosting/platform validation and repository/disclosure gates close.
No website or release has been published. See the [engineering report](docs/public-release-report.md).

- [Install the local candidate](docs/installation.md)
- [Start the public site/API locally](cloud/README.md)
- [Integrate another supported agent](docs/integration.md)
- [Opt-in synchronization](docs/sync.md)
- [Security review and release gates](docs/security/release-readiness.md)
- [Owner-run zero-cost publication guide](docs/deployment.md)


A local research runtime that authorizes agent actions independently of the model.

**Local LLM update (2026-10-13):** Ollama 0.40.3 with `qwen2.5:3b` was tested
through the strict schema adapter and real gateway. See the [integration report](docs/local-llm-integration.md)
for commands, audit evidence, safe stops and model-quality limitations.

**Windows extension:** native Windows 10/11 portability code and CI are added, but
Windows builds/tests have not run here. Compatibility is **not verified**. Native
Windows agent file tools are disabled; use the documented WSL2 Linux route for
Unix file isolation. See [Windows setup and security scope](docs/windows.md).
Phase 2 extends the working SentinelOS foundation; internal package names remain
compatible. This is a security runtime, not an operating-system kernel.

**Implemented:** Rust/Cedar default-deny gateway, signed task contracts, SQLite audit,
authenticated one-time approvals, descriptor-pinned file tools, an import-free
Wasmtime tool, experimental protected-data flow restrictions, optional local-model
adapter, and a dashboard backed by actual runtime events.

**Scope:** the application exposes no native-code, shell, arbitrary filesystem or
external-network executor. Python controllers and the host administrator are trusted.
The Wasm boundary applies to the fixed checksum component; the whole Python process
is not sandboxed. No complete prompt-injection immunity is claimed.

## Run locally

Requirements: Python **3.12+ with OpenSSL scrypt**, Rust **1.99.0**, a C compiler,
and macOS or Linux. Install dependencies once; default demonstrations need no network.

```sh
python3.12 -m venv .venv
.venv/bin/python -m pip install -r requirements-dev.txt
cargo build --locked
cargo test --locked
.venv/bin/python -m pytest -q
.venv/bin/python -m control_plane.demo --output reports/phase2-demo.json
.venv/bin/python -m benchmarks.phase2 --seed 1729 --repetitions 20
```

Run commands from this repository. `Cargo.lock` pins Rust dependencies.
`SENTINEL_RUNTIME` can select a trusted, separately built runtime binary.

## Dashboard

```sh
.venv/bin/python -m control_plane.server --init
.venv/bin/python -m control_plane.server --port 8787
```

Initialization asks for a new local administrator password (12–256 characters).
There is no default password. Open **http://127.0.0.1:8787**, authenticate, and select
**Run controlled demonstration**. Inspect allowed and denied events, approve the
pending synthetic publication once, test protected-data flow, and revoke the task.
Approving in this research demonstration also deliberately attempts the same signed
approval again so the dashboard shows its replay denial.

The server binds only to loopback. It checks Host/Origin, uses CSRF protection,
HttpOnly/SameSite cookies, scrypt password verification, expiring sessions and login
throttling. `.local-state/` is private local state; never publish it. This single-user
HTTP service is not designed for remote exposure. Live task handles and approval
queues are in memory; restart discards them while audit records persist.

Local screenshots and private demonstration reports are excluded from the public source archive.

## Supported enforcement

| Component | Behavior | Boundary / limitation |
|---|---|---|
| Rust gateway | Identity, signature, expiry, argument, exact scope, Cedar and approval checks | Trusted controller supplies bootstrap and signing authority |
| Virtual tools | Repository reads/writes and simulated API calls | No host/network side effects |
| Pinned file tools | Read `input.txt`/`output.txt`, write existing `output.txt` | Private disposable directory; no traversal, dynamic creation or path re-resolution |
| Wasmtime | Fixed checksum module; no imports, WASI, sockets, filesystem or environment | 64 KiB guest memory, fuel and epoch deadline; not a process-wide resource cap |
| Approvals | Authenticated admin; exact task/action/body binding; expiry and one-time use | No agent-visible signing or approval tool |
| Provenance | Signed protected-resource labels; sticky task taint blocks subsequent sinks | Coarse experimental rule, no cross-task or semantic flow tracking |
| Optional model | Loopback JSON-chat adapter, bounded steps and proposals | Disabled by default; local Qwen smoke tests recorded |

Every application agent tool uses the gateway, with no failure fallback. Research
comparison arms are separate, in-memory simulators under `benchmarks/`; they cannot
operate host files or networks and are not application tool paths. Arbitrary Python
code execution by an attacker is outside the supported threat model.

## Validation and research

The Phase 2 baseline report records **82 Python tests**, **10 Rust tests on macOS and
Linux**, and a passing browser workflow. Updated portability validation is recorded
separately in [the release-readiness report](docs/security/release-readiness.md). Formatting and Clippy passed. All 73
Phase 1 tests are retained within the expanded suite.

The deterministic four-arm benchmark used seed 1729 and 20 repetitions. Full
Sentinel enforcement executed **0/120 unauthorized proposals** and completed
**20/20 tasks**. These are repeated synthetic scenarios, not 120 independent
attacks or an AgentDojo score. See [full measurements](benchmarks/phase2-results.json)
and the [engineering report](docs/phase2-engineering-report.md) for denominators,
timing methodology, failures corrected and unresolved limitations.

Optional browser verification (Node 22+):

```sh
npm install --no-save --package-lock=false playwright@1.62.1
npx playwright install chromium
PYTHON=.venv/bin/python node scripts/browser_smoke.cjs
```

Set `BROWSER_CHANNEL=chrome` to use an installed Chrome. Browser tests use generated
synthetic credentials, disposable state and real backend events. CI configuration
covers macOS/Linux; remote CI itself has not been run in this session.

Optional locally hosted model, only when explicitly configured (Ollama/Qwen commands are in the integration report):

```sh
.venv/bin/python -m agent_harness.live
.venv/bin/python -m agent_harness.live --endpoint http://127.0.0.1:8000/v1/chat/completions --model YOUR_LOCAL_MODEL
```

The first command reports disabled. The second requires a model server you supply.
No model or paid service is installed or activated. Optional `SENTINEL_MODEL_KEY`
stays in the trusted adapter and is stripped from the Rust child's environment.

## Repository

- `runtime/` — Rust enforcement, audit and isolated components.
- `agent_harness/` — deterministic/model agents and trusted gateway transport.
- `control_plane/` — local authentication, approval lifecycle, HTTP server and demo.
- `policies/`, `contracts/` — trusted Cedar rules and contract templates.
- `simulated_tools/` — synthetic fixtures.
- `tests/`, `scripts/` — regressions and browser automation.
- `benchmarks/` — fixed-seed research comparisons and measured results.
- `dashboard/dist/` — dependency-free frontend.
- `docs/`, `reports/` — design, evidence and limitations.

Start with the [engineering report](docs/phase2-engineering-report.md),
[architecture](docs/architecture.md), [threat model](docs/threat-model.md), and
[roadmap](docs/roadmap.md). Phase 1 reports are preserved as historical evidence.
No credentials, production service connections, deployments or automatic commits
are required.
