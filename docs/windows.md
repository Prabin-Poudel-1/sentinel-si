# Windows 10 / Windows 11 portability — validation pending

**Native Windows is an implementation candidate, not verified compatibility.**
The development host is macOS. No Windows VM is configured and no Windows build,
Windows kernel test or Windows browser run has succeeded in this session. CI files
are not evidence of a passing run. Windows Server runners are not substitutes for
Windows 10 and Windows 11 client validation.

## Platform scope

| Component | Native Windows candidate | macOS / Linux / WSL2 Linux path |
|---|---|---|
| Rust/Cedar gateway, contracts, SQLite, approvals, audit | Portable source; must build/test on Windows | Existing implementation retained |
| Python gateway transport | Serialized worker-based pipe exchange with timeout/child termination | Existing POSIX readiness checks retained |
| Authentication / trusted state | Protected Windows DACL and pinned directory handle; pywin32 required | POSIX private directory mode |
| Fixed import-free Wasm tool | Independent of file adapter; candidate for Windows x64 | Existing fuel, memory, import and epoch controls |
| Native agent file tools | **Unavailable**, even with a signed grant | Existing descriptor-pinned two-file adapter |
| Simulated repository / APIs | In-memory, no Windows path resolution | Unchanged |
| Dashboard | Same loopback/authenticated frontend/backend | Unchanged |
| Benchmarks | CPU/RSS POSIX measurements explicitly null | Existing measurements preserved |
| Native programs / arbitrary Python or WASI | Unavailable | Unavailable |

Initial native target is x64 Windows 10/11 with Python 3.12 and the MSVC Rust
1.99.0 toolchain. Windows ARM64 and 32-bit configurations are not validated targets.
The standard library, compiler and dependencies may impose additional OS servicing
requirements. This document does not extend Microsoft's Windows support lifecycle.

## Native setup for validation

Use a disposable Windows test machine and a normal local user. Install Python 3.12
with OpenSSL/scrypt, Rust 1.99.0 for `x86_64-pc-windows-msvc`, and Visual Studio C++
Build Tools including the Windows SDK. Node 22 is needed only for browser testing.
Extract the source into a local NTFS directory owned by that user, with a trusted
parent. Avoid network shares, OneDrive redirection, junctions and reparse-point paths.

From PowerShell in the repository:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
cargo build --locked
cargo fmt --all --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
.\.venv\Scripts\python.exe -m pytest -q -ra --junitxml=reports/pytest.xml
.\.venv\Scripts\python.exe -m scripts.platform_report --output reports/platform-validation.json
.\.venv\Scripts\python.exe -m control_plane.demo --output reports/windows-demo.json
.\.venv\Scripts\python.exe -m benchmarks.phase2 --repetitions 20 --output reports/windows-benchmark.json
.\.venv\Scripts\python.exe -m control_plane.server --init
.\.venv\Scripts\python.exe -m control_plane.server --port 8787
```

Open `http://127.0.0.1:8787`. The native Windows demonstration executes the Wasm
tool and virtual task, while omitting unavailable real-file tools. The dashboard
states that Windows file isolation is unavailable. No permission switch enables it.
Default runtime resolution selects `target/debug/sentinel-runtime.exe`. An explicit
`SENTINEL_RUNTIME` override is trusted controller configuration, never an agent field.
The Rust child inherits only `LANG` and Windows `SystemRoot`, not provider secrets
or a general PATH. No shell launch is used by agent tools.

Browser validation:

```powershell
npm install --no-save --package-lock=false playwright@1.62.1
npx playwright install chromium
$env:PYTHON = (Resolve-Path .\.venv\Scripts\python.exe).Path
node scripts/browser_smoke.cjs
```

The fixture receives only a generated synthetic password over a private pipe.
Closing its stdin shuts it down cleanly on all platforms. The server remains
loopback-only; remote exposure is unsupported.

## Windows filesystem security decisions

The Unix `openat`/O_NOFOLLOW backend is compiled only on Unix. On native Windows,
Rust returns an audited DENY with `unsupported_platform` for otherwise authorized
`isolated_read`/`isolated_write`. No `Path.resolve`, prefix matching or ordinary
`open()` replacement attempts to emulate Unix confinement. This also avoids claiming
that rejecting a symlink alone handles junctions, mount points, device namespaces,
alternate data streams, case aliases or directory replacement races.

Virtual resource grammar and exact grants reject Windows traversal/device/stream
requests from the agent; virtual tools never dereference them as host paths. A plain
string check is therefore not being used as the host-file isolation boundary.

Trusted application state is a different surface. It contains password verifiers,
session metadata, SQLite audit/replay databases and sidecars. The Windows setup:

- Requires a local filesystem advertising persistent ACL support; rejects UNC and
  stream-qualified state paths and observed reparse ancestors.
- Creates a new directory with a protected, inheritable DACL granting only the
  current user and SYSTEM. An existing empty temporary directory is hardened by
  handle before any sensitive contents are written.
- Opens the directory using `FILE_FLAG_OPEN_REPARSE_POINT` and backup semantics,
  examines handle metadata, and holds a handle without DELETE sharing throughout
  controller lifetime. This prevents replacing that directory by rename/deletion.
- Rejects unexpected owners, unprotected/broad DACLs on existing state, reparse
  state files, hardlinked state files and unexpected subdirectories. Administrators
  and SYSTEM are trusted OS principals; elevated-created administrator ownership
  is accepted, while allowed DACL entries remain current-user/SYSTEM only.
- Relies on inherited kernel ACLs for newly created SQLite/auth files. It does not
  treat Windows `chmod(0700)` as access control and never falls back when pywin32 or
  an ACL operation fails.

These mechanisms are implemented but **not Windows-kernel-validated here**. Parent
selection and bootstrap run in a trusted host context. Ancestor string inspection is
only defense in depth, not a race-proof directory broker. An already compromised
same-user process, privileged administrator, malicious driver or previously opened
unauthorized handle is outside the threat model. State must be initialized under a
trusted parent. There is no claim of user-to-user isolation before that precondition.
No general Windows file creation or arbitrary tree traversal is offered to an agent.

Sources: [Microsoft file access rights](https://learn.microsoft.com/en-us/windows/win32/fileio/file-security-and-access-rights),
[CreateFile flags and sharing](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew),
and [pywin32 handle information](https://mhammond.github.io/pywin32/win32file__GetFileInformationByHandle_meth.html).

## WSL2 alternative

WSL2 is the supported **Linux deployment route** on Windows when equivalent Unix
file tools are required. Linux regressions are run in a disposable Linux environment;
a WSL2-hosted end-to-end run has not been performed here and must not be inferred.
Use the entire Linux toolchain and Python inside the distribution, not Windows
Python or a Windows-built gateway.

Microsoft's current installation command requires Windows 10 version 2004/build
19041 or newer, or Windows 11. See [official WSL installation instructions](https://learn.microsoft.com/en-us/windows/wsl/install).
From an administrator PowerShell, following that documentation:

```powershell
wsl --install -d Ubuntu
wsl --set-version Ubuntu 2
wsl --list --verbose
```

Inside the distribution, put the repository and private state in the Linux filesystem,
for example `~/sentinel-ai`, and follow the README's Linux commands with Python 3.12
and Rust 1.99.0. Do **not** put state, repositories or temporary directories on
`/mnt/c`, `/mnt/d`, network mounts or symlinked Windows directories. POSIX private
state setup now checks that group/other permissions were actually removed and fails
if the filesystem does not honor that requirement. Do not enable metadata mount
options as an assumed substitute for the tested Linux filesystem semantics.

Run the complete Rust/Python suite and browser workflow in the distribution before
using its results. Keep the server at loopback; do not add port forwarding or bind
0.0.0.0 merely to reach it from a Windows browser.

## CI and evidence required before claiming compatibility

The regular CI matrix now includes `windows-2022` and `windows-2025` hosted runners,
alongside existing macOS/Linux jobs. It runs Rust format/lint/build/tests, Python
regressions, the actual demo, benchmarks and Playwright. Those Windows runners are
Windows **Server** environments. They can catch Windows API/build problems but do
not certify the two requested client OS versions.

A separate manually dispatched `windows-client.yml` targets dedicated clean
self-hosted x64 runners labeled `windows-10` or `windows-11`. It never triggers on
pull requests. No workflow was pushed, dispatched or remotely executed here. Native
support remains pending until successful artifacts exist for both client OS versions.

Mandatory platform tests cover: denial of signed native-file requests, Wasm output,
protected/inherited state DACLs, pinned-handle rename denial, junction rejection,
hardlink rejection and broad-ACL rejection. The existing symlink test may skip only
when Windows reports missing symlink privilege; the junction test does not use that
privilege exemption. Unix-only descriptor tests remain active on macOS/Linux.
Portable tests also exercise the threaded transport with the real Rust subprocess,
concurrent requests, stalled/partial pipe timeouts and hostile Windows resource forms.

Preserve platform version/build/architecture, pytest XML (including skips), Rust logs,
demo and benchmark JSON, and browser evidence. Do not relabel macOS/Linux passes,
cross compilation, downloaded Windows wheels or configured workflows as Windows
execution. WSL2 results likewise do not establish native Windows compatibility.
