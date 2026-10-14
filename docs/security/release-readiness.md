# Release readiness: NOT READY FOR PUBLIC ACTIVATION

The local public-release candidate is functional and tested. **Do not activate the
public API or advertise a verified hosted product yet.** Production configuration
fails closed by default (`PRODUCTION_ENABLED=false`, no real OAuth credentials).

## Completed evidence

Four-platform release CI has passed on macOS ARM64/Intel and Linux ARM64/x64.
Physical Apple Silicon testing and a clean Gitleaks scan of nine commits are
maintainer-reported. See [Phase 1 evidence](../release-validation-v0.3.0-rc.1.md) for
run links, scan scope and the unsigned/unnotarized Gatekeeper limitation.

## Retained local results

- Existing default-deny runtime and supported tool workflows preserved.
- SDK, one-use pairing, hashed sessions/tokens, ownership, CSRF, rotation/revocation.
- Actual local Wrangler+D1 ingestion and two-account Chrome dashboard journey.
- Sanitized opt-in sync, bounded queue, actual cloud stop/restart and local continuity.
- macOS/Linux regressions; native Windows-only tests explicitly skipped.
- macOS Apple Silicon and Linux ARM64 offline installers, manifest/checksum, tamper rejection and uninstall.
- Rust/Python/npm known-vulnerability audits and high-signal source/artifact scanning.

## Owner/environment gates still open

1. Official repository and private reporting are recorded in SECURITY.md. Confirm the
   final release identity/license and refresh history/artifact scanning for the final
   tag; the completed nine-commit Gitleaks scan does not cover later commits.
2. Validate real GitHub OAuth and hosted Pages→Worker→D1 configuration, HTTPS cookies,
   callback/state/CSRF, two-account isolation, scheduled retention and Free CPU/row usage.
3. Native macOS Keychain synthetic set/get/replace/delete passed separately. Exercise
   Linux Secret Service and Windows Credential Manager before claiming those integrations.
   Local full E2E intentionally uses an in-memory synthetic credential fixture.
4. Four-platform macOS/Linux release CI is complete. Native Windows 10/11 and WSL2
   remain unverified; Windows Server CI is not client validation. Direct ChatGPT/Claude
   integrations are unverified. Preserve gateway-only tool integration boundaries.
5. Verify final official release artifacts and deploy only after explicit owner approval.

This Phase 1 documentation update does not deploy services or publish a release. Known unsupported capabilities
remain disabled. Installer artifacts are unsigned/unnotarized; checksums are integrity
metadata, not proof of an uncompromised publisher. See public-release-report.md for
exact executed checks and operational commands.
