# Release readiness: NOT READY FOR PUBLIC ACTIVATION

The local public-release candidate is functional and tested. **Do not activate the
public API or advertise a verified hosted product yet.** Production configuration
fails closed by default (`PRODUCTION_ENABLED=false`, no real OAuth credentials).

## Passed locally

- Existing default-deny runtime and supported tool workflows preserved.
- SDK, one-use pairing, hashed sessions/tokens, ownership, CSRF, rotation/revocation.
- Actual local Wrangler+D1 ingestion and two-account Chrome dashboard journey.
- Sanitized opt-in sync, bounded queue, actual cloud stop/restart and local continuity.
- macOS/Linux regressions; native Windows-only tests explicitly skipped.
- macOS Apple Silicon and Linux ARM64 offline installers, manifest/checksum, tamper rejection and uninstall.
- Rust/Python/npm known-vulnerability audits and high-signal source/artifact scanning.

## Owner/environment gates still open

1. Supply official GitHub repository/release identity and monitored private disclosure;
   scan full Git history (none exists in this workspace), confirm license/copyright.
2. Validate real GitHub OAuth and hosted Pages→Worker→D1 configuration, HTTPS cookies,
   callback/state/CSRF, two-account isolation, scheduled retention and Free CPU/row usage.
3. Native macOS Keychain synthetic set/get/replace/delete passed separately. Exercise
   Linux Secret Service and Windows Credential Manager before claiming those integrations.
   Local full E2E intentionally uses an in-memory synthetic credential fixture.
4. Run remote release CI on every platform to be advertised; Intel macOS, native Windows
   and WSL2 were not executed here. Do not publish unverified compatibility badges.
5. Verify final official release artifacts and deploy only after explicit owner approval.

No deployment, commit, push or GitHub release occurred. Known unsupported capabilities
remain disabled. Installer artifacts are unsigned/unnotarized; checksums are integrity
metadata, not proof of an uncompromised publisher. See public-release-report.md for
exact executed checks and operational commands.
