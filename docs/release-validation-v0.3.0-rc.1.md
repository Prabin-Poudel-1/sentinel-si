# v0.3.0-rc.1 — Phase 1 release evidence

This record updates release documentation only. It does not authorize publication or
production activation. Official repository: [Prabin-Poudel-1/sentinel-si](https://github.com/Prabin-Poudel-1/sentinel-si).

## Completed CI, verified from GitHub

Reviewed main commit: `10e9e2679f9dc0d5c7a406b68ed0e42ef6d8e884`.
[Release candidate run 38486294825](https://github.com/Prabin-Poudel-1/sentinel-si/actions/runs/38486294825)
completed successfully on all four matrix targets:

| Runner | Artifact platform | Result |
|---|---|---|
| macos-14 | macOS ARM64 / Apple Silicon | Passed |
| macos-15-intel | macOS x86_64 / Intel | Passed |
| ubuntu-24.04 | Linux x86_64 | Passed |
| ubuntu-24.04-arm | Linux ARM64 | Passed |

The workflow includes Rust tests, Python tests, release compilation, artifact scanning,
and installer verification. These are completed CI checks, not just configured jobs.
No binaries were rebuilt for this documentation update.

[Main regression run 38485069724](https://github.com/Prabin-Poudel-1/sentinel-si/actions/runs/38485069724)
also passed on Ubuntu, macOS, Windows Server 2022 and Windows Server 2025.
Windows Server CI does **not** establish native Windows 10/11 protection or enable
unsupported host-file tools. The [public security run 38481589047](https://github.com/Prabin-Poudel-1/sentinel-si/actions/runs/38481589047)
passed on the preceding PR commit `651a58004090da12c900522b83cf9c5d7fba9152`;
it is not represented as a separate security run on the merge commit.

## Maintainer-reported checks

- Physical Apple Silicon testing completed. This supplements hosted macOS CI; it
  does not certify every macOS version, Intel hardware or downloaded package behavior.
- A clean Gitleaks history scan covered **9 commits**. This is the completed scan
  reported by the maintainer, not a scan rerun in this documentation task. The reviewed
  main now contains 11 reachable commits; the nine-commit result must not be described
  as coverage of later commits or the final release tag. Retain the scan log and
  refresh history/artifact scanning at the eventual release boundary.
- **Gatekeeper limitation:** macOS packages remain unsigned and unnotarized. Local
  execution and CI success do not establish seamless launch of quarantined downloads.
  Gatekeeper may block downloaded executables. Do not disable Gatekeeper, strip
  quarantine as an installation requirement, or describe the packages as notarized.

The physical test and Gitleaks details above are attributed to the maintainer's
release-preparation report; no new hardware test or history scan was performed here.

## Still unverified / deferred

- Production cloud: real GitHub OAuth, hosted Pages/Workers/D1, HTTPS/session setup,
  quota behavior and production operations. Keep `PRODUCTION_ENABLED=false`.
- Native Windows 10/11 security and compatibility; host-file tools remain disabled.
  WSL2 is a documented Linux route, not a claim of a completed WSL2 test.
- Direct ChatGPT or Claude integrations. The existing Python SDK protects only
  supported tool calls routed through the gateway; no automatic desktop integration
  or universal agent protection is claimed.
- Linux/Windows native credential-store validation, signing/notarization and
  independent security certification.

Private vulnerability reporting is documented in [SECURITY.md](../SECURITY.md).
Four-platform CI and physical Mac testing advance release preparation, but do not
close the [public-activation gates](security/release-readiness.md). Publishing the
release and deploying cloud services are separate owner-authorized actions.
