# Optional privacy-preserving sync

Sync is **off by default**. It is a separate outbound client; cloud availability or account settings cannot grant local tool permissions, sign contracts, issue approvals, or replace Rust decisions. Local authentication and audit remain independent.

A user first enables sync in authenticated cloud account settings, then requests a one-use device pairing code. Locally install the optional `keyring==25.7.0` dependency into the existing environment, and run:

```sh
python -m sentinel_sync pair --origin https://YOUR-DEPLOYED-ORIGIN --queue /private/state/sync-queue.sqlite --consent
```

The pairing code is entered through a hidden prompt, never a command-line argument. This project does not ship a production origin or deployment. Use a dedicated local queue path: **never pass the security audit SQLite database**. OS credentials must be available: macOS Keychain, Linux Secret Service, or Windows Credential Manager via the allowlisted keyring backend. Missing/locked/unsupported backends fail closed; there is no plaintext fallback. Headless environments must provision a supported OS store or leave sync disabled.

A trusted integration may call `safe_event(gateway_result, operation)` and `enqueue(event)` followed by `flush()`. Only six fields are exported: a random UUID, integer timestamp, allowlisted operation, decision, executed boolean and coarse reason code. No document contents, file paths, resource identifiers, task IDs, passwords, raw tokens or resource hashes are exported. The client does not scan or upload the audit database. The UUID should be created once and retained for retries; enqueueing the same UUID deduplicates it. Audit selection/scheduling is an explicit application integration, not an automatic background service.

The SQLite queue caps at 1,000 events by default (maximum 10,000), drops entries older than seven days and sends batches of at most 25. Failed uploads retain pending events and use bounded exponential backoff; only acknowledged IDs are removed. Queue metadata is not encrypted: place it inside a private OS-protected state directory. Consent is explicit per client construction/startup and is not persisted as an implicit opt-in. The server independently enforces account consent, device revocation, quotas and ownership.

```sh
python -m sentinel_sync flush --origin https://YOUR-DEPLOYED-ORIGIN --queue /private/state/sync-queue.sqlite --consent
python -m sentinel_sync rotate --origin https://YOUR-DEPLOYED-ORIGIN --queue /private/state/sync-queue.sqlite --consent
python -m sentinel_sync disconnect --origin https://YOUR-DEPLOYED-ORIGIN --queue /private/state/sync-queue.sqlite
```

Disconnect attempts remote revocation, then deletes the local credential and pending queue even if the network fails. If remote revocation fails, revoke the device in cloud account settings too. Credential-store failure during rotation may leave an unusable old local credential; revoke/re-pair rather than retrying privileged operations. Device IDs and origin are non-secret queue metadata, while device tokens live only in the OS store.

HTTPS is mandatory. Redirects and proxy environment variables are disabled. Explicit `allow_loopback_http=True` allows only literal `127.0.0.1` HTTP for development. The CLI exposes no insecure transport flag. `MemoryTestCredentials` additionally requires `allow_test_credentials=True`; it is only for disposable tests, never a production fallback. Cloud requests are bounded to ten seconds by default and responses to 64 KiB. Sync does not run automatically in the tool execution path and failures must not change gateway authorization.
