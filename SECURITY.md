# Security policy

Sentinel AI is a research-derived release candidate, not an independently audited
security product. Read docs/security/release-readiness.md before enabling public services.

## Report a vulnerability privately

Official repository: https://github.com/Prabin-Poudel-1/sentinel-si

Private vulnerability reporting is enabled for this repository.
Report vulnerabilities privately through GitHub Security → Report a vulnerability.
Do not disclose sensitive exploit details in public issues. Do not put exploit details, credentials, user
prompts or private documents in a public issue. Include affected version, minimal
synthetic reproduction, impact and a safe contact method. Never send real secrets.

Maintainers should acknowledge within three business days where feasible, coordinate
remediation and disclosure, and publish an advisory and patched artifact when ready.
No bug bounty or guaranteed response time is promised. Only the latest verified beta
will receive fixes; do not run unverified historical archives as security software.

## Supported boundary

The gateway governs supported tools routed through it. The trusted Python controller,
OS administrator and build chain remain trusted. No arbitrary Python sandbox,
universal desktop-agent protection or complete prompt-injection immunity is claimed.
The optional cloud is observational and cannot approve local tools or alter contracts.

See docs/security/incident-response.md for credential compromise and rollback procedures.
