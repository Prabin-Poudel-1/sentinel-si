# Installation candidate 0.3.0-rc.1

This release candidate is local-only until the release-readiness gates are closed.
No official repository or download URL is configured yet. Do not trust similarly named packages.

## Platform scope

| Platform | Status |
|---|---|
| macOS Apple Silicon | Local Rust/Python regression and bundled-runtime installer tested; unsigned, not notarized |
| Linux | Linux ARM64 Debian12 container: source tests and bundled installer tested; x64 build workflow supplied |
| macOS Intel | Build workflow supplied; not executed in this environment |
| Windows WSL2 | Use the Linux installation route inside WSL2; WSL2 itself not exercised here |
| Native Windows 10/11 | Portability candidate only; no verified package; host file tools disabled |

The Linux ARM64 binary was built against Debian12/glibc2.36. Other libc/architecture
combinations require their own build and verification. The macOS artifact was exercised
on this Apple Silicon Mac, not every macOS version.

Prerequisites: Python 3.12+ with OpenSSL scrypt and venv. Bundled packages include
Rust runtime and SQLite; no Rust compiler is needed to run them. Source builds need
Rust 1.99.0 and a C compiler. Model inference is optional and user-provided.

## Verify, extract and install

Download the platform archive and its `.sha256` from the same reviewed GitHub
release, after checking the repository identity. A checksum detects corruption;
it does not authenticate a malicious release account. Review CI provenance too.

```sh
shasum -a 256 -c sentinel-ai-0.3.0-rc.1-darwin-arm64.tar.gz.sha256
# Linux: sha256sum -c <archive>.sha256
tar -xzf sentinel-ai-0.3.0-rc.1-darwin-arm64.tar.gz
mkdir -p "$HOME/.local/share"
python3.12 sentinel-ai-0.3.0-rc.1-darwin-arm64/installer.py \
  --prefix "$HOME/.local/share/sentinel-ai-0.3.0-rc.1"
"$HOME/.local/share/sentinel-ai-0.3.0-rc.1/sentinel" example
```

Installer verifies the manifest/platform, refuses root, existing destinations and
symlink prefixes, and creates a private user-owned installation. Parent directories
must be trusted. It executes no downloaded shell script and performs no network access.
There is no privileged daemon or autostart service.

## Local administrator and dashboard

Choose a private state directory outside the installation to preserve it on upgrades.

```sh
SENTINEL="$HOME/.local/share/sentinel-ai-0.3.0-rc.1/sentinel"
"$SENTINEL" dashboard --init --state "$HOME/.local/share/sentinel-state"
"$SENTINEL" dashboard --state "$HOME/.local/share/sentinel-state" --port 8787
```

Open http://127.0.0.1:8787. Set a unique password interactively. Never expose this
local HTTP administration server publicly. Cloud login does not replace local login.

```sh
"$SENTINEL" live --endpoint http://127.0.0.1:11434/v1/chat/completions --model qwen2.5:3b
```

The standalone example requires no model. See `docs/integration.md` for the typed SDK,
`docs/sync.md` for optional opt-in sync and native secure credential storage. The
installed `.venv` is intentionally dependency-free; for optional sync use a separate
Python 3.12 environment with `keyring==25.7.0`, point PYTHONPATH at the installation,
and set SENTINEL_RUNTIME to its `bin/sentinel-runtime`. Do not use a plaintext keyring.

## Upgrade and uninstall

Install a new release into a new version-specific prefix, run its example/test task,
then launch it with the existing external state directory after backing up that
private directory securely. Never copy local credentials into release artifacts.
Roll back by selecting the earlier executable and compatible state backup; never
roll back to a known vulnerable version. Database migrations require a reviewed plan.

Stop Sentinel processes first. Run the extracted package's `installer.py --uninstall
--prefix <exact-installation>` to remove a marked installation. It refuses to remove
an embedded `.local-state`; move that state to a private backup first. External state,
cloud records and Keychain entries are not deleted by uninstall. Disconnect sync and
revoke the cloud device before removing software; delete cloud events/account separately.

## Build an artifact locally

```sh
RUSTFLAGS="--remap-path-prefix=$PWD=/sentinel-build --remap-path-prefix=$HOME/.cargo=/cargo" cargo build --release --locked
cargo fetch --locked
python3.12 scripts/third_party.py
python3.12 scripts/build_release.py
```

The builder uses an explicit source allowlist, excludes local state, reports, tokens,
venvs, node_modules and caches, and refuses binaries containing personal build paths.
Tar metadata and gzip timestamps are deterministic for identical input bytes. This
is not a claim of independently reproduced Rust compiler output.
