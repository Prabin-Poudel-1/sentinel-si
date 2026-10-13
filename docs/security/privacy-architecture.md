# Privacy architecture

Sync is off by default on both client and account. Pairing alone does not authorize
upload. The serializer exports only random event ID, timestamp, enumerated operation,
decision, boolean execution and enumerated reason. Device identity comes from the
bearer credential. No task/resource names or deterministic content hashes are sent.
Prompts, conversations, files, tool outputs, environment variables, keys and whole
local databases are excluded by code and tests. Application version is not currently
sent because it is unnecessary for the beta event view.

GitHub ID/login, synthetic device label, timestamps and coarse activity remain
personal metadata. Use a generic device label. Cloudflare/GitHub see connection
metadata under their own terms. The application does not log raw requests or tokens;
do not enable provider request-body capture. OAuth callback code/state may be visible
to infrastructure request logging: disable/redact query strings and keep retention short.

Cloud events expire after 30 days; reads exclude expired records even if scheduled
cleanup is delayed. Cleanup runs hourly and may be delayed by free-tier exhaustion.
Client queue defaults to 1,000 events/seven days, drops oldest at capacity, and sends
at most 25 per batch. This is intentionally lossy telemetry, not the authoritative
audit log. IDs deduplicate accepted retries per device while records are retained;
retention or user deletion removes dedup records, so a compromised device can replay
otherwise-valid recent metadata after deletion. This does not execute a tool.

Users can disable ingestion, revoke devices, delete events and delete accounts.
Deletion cascades through D1 application tables; provider backups/Time Travel obey
provider retention and are not proven physically erased. Disconnect clears local
credential/queue state even if remote revocation fails; explicitly revoke via the
website if offline. OS keyring absence fails closed, with no plaintext fallback.
An in-memory credential store is available only through explicit test injection.
