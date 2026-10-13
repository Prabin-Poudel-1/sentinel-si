# Incident response

1. Contain: set PRODUCTION_ENABLED=false and redeploy only with owner authorization;
   static public documentation can remain. Disable account sync and stop local sync
   clients. Local gateway enforcement is independent and continues offline.
2. Preserve minimal evidence: version, time, affected opaque IDs and safe reason codes.
   Keep any private evidence encrypted/access-controlled; never attach secrets to issues.
3. Revoke: compromised accounts should secure GitHub/2FA and revoke the OAuth grant;
   separately remove Sentinel sessions (GitHub grant revocation alone does not revoke
   already-issued Sentinel sessions). Use prepared administrative D1 queries scoped to
   the affected user. Revoke device rows and enrollment records. Rotate leaked GitHub
   client secret through provider UI and Worker secret binding; restart login flows.
4. Endpoint compromise: revoke every associated device, stop the local service and
   investigate the OS. Cloud revocation cannot repair a compromised host. Reinitialize
   local credentials/signing sessions on a trusted host; preserve private audit evidence.
5. Repository secret exposure: immediately rotate affected secrets even if removed from
   the latest tree. Inventory forks, artifacts and logs. Coordinate history remediation
   with the owner; never rewrite history destructively automatically.
6. Dependency/artifact compromise: disable download links, quarantine affected versions,
   pin/review a fixed dependency, rebuild on clean runners, rerun full security tests and
   checksum verification, and publish an advisory. Checksums from a compromised account
   do not establish authenticity. Do not reuse compromised CI credentials.
7. Outage/quota exhaustion: inspect safe usage metrics, retain bounded queues, allow retry
   after the provider reset; do not silently upgrade to a paid tier or bypass authorization.
8. Recovery: test two-account isolation, login/logout, pairing replay, revoked tokens,
   sanitized ingestion and offline operation before owner-authorized reenablement.
   Roll back frontend/Worker versions and compatible D1 backups as a coordinated change;
   do not restore revoked credentials inadvertently.
9. Communicate: privately notify affected users with confirmed scope, mitigations and
   timestamps, then publish a coordinated security advisory without private data.

Data requests: authenticate ownership, use account/event deletion, record only a safe
request status, and explain backup retention. Never claim immediate physical erasure.
Suspicious telemetry alone is not proof of an attack; endpoint data is self-reported.
