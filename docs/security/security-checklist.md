# Maintainer checklist

- [ ] Configure official repository, license decision and monitored private disclosure.
- [ ] Review diff; never publish .local-state, .dev.vars, keys, databases or raw reports.
- [ ] Scan allowlisted source/artifacts and full Git history in the actual repository.
- [ ] Run Python, Rust, cloud, browser, installer and end-to-end regression commands.
- [ ] Audit locked dependencies; triage advisories instead of ignoring failures.
- [ ] Use SHA-pinned actions, read-only PR tokens and no deployment secrets on PRs.
- [ ] Protect main/release branches: required review/checks, no force push, 2FA, restricted maintainers.
- [ ] Verify production OAuth exact callback, PKCE/state, cookie/CSRF and fresh reauthentication.
- [ ] Verify native keyring on each advertised platform, revoked token and outage behavior.
- [ ] Inspect artifact manifests/checksums and platform labels; no unverified Windows claims.
- [ ] Verify hosted same-origin Pages service binding, CSP and no public debug/dev login.
- [ ] Verify Free plans, quotas, cleanup, provider logging redaction and incident kill switch.
- [ ] Close High/Critical findings before enabling the affected public capability.
- [ ] Obtain owner authorization before commit/push/release/deployment/account changes.

The checkboxes are publication gates, not claims that production checks ran locally.
