# Observational cloud API

Workers JavaScript + D1, with no local execution/approval endpoint. Production is
**disabled** by default. Local mock identity requires DEV_MODE=true, a loopback origin
and a configured 32+ character development key. No default credential exists.

## Local setup

From the repository root, install Node 22.13+ and Python 3.12+:

```sh
npm ci --prefix cloud
python3.12 web/build.py
python3.12 web/dashboard_page.py
python3.12 scripts/configure_cloud_dev.py
cd cloud
npx wrangler d1 migrations apply sentinel-local --local --config wrangler.local.toml
npx wrangler dev --local --config wrangler.local.toml
```

Open http://127.0.0.1:8788. Expand **Local development sign-in** on the dashboard;
enter the development key chosen at the hidden prompt and select Alice or Bob.
Never reuse a real password. Files `.dev.vars`, `wrangler.local.toml`, `.wrangler/`
are private ignored state. Stop with Ctrl-C. No Cloudflare account is needed locally.

```sh
npm test --prefix cloud             # from repository root
python3.12 scripts/public_e2e.py     # independent disposable real Wrangler+D1 fixture
# With Playwright installed and Chromium available:
python3.12 scripts/public_e2e.py --browser
```

## Contract and safeguards

Browser APIs use HttpOnly session cookie and `X-CSRF-Token` plus exact Origin for
mutations. GET `/api/session`, `/api/devices`, `/api/events`, `/api/summary`,
`/api/settings`; POST `/api/logout`, `/api/devices/pair`, `/api/devices/:id/revoke`;
PATCH `/api/settings`; DELETE `/api/events`, `/api/account` (login <5 minutes old).
GitHub `/api/auth/github` and callback implement code/state/PKCE and minimal scopes.
Session lifetime is one hour, at most five sessions per account. GitHub recovery is
upstream; revoke Sentinel sessions separately during compromise.

Device API: POST `/api/device/pair` with one-time code, `/api/device/rotate`,
`/api/device/revoke`, `/api/telemetry` with bearer credential. Pairing expires after
five minutes; tokens after 30 days. Each account has at most 100 device records.
Revocation/rotation are rechecked in event writes. Codes are consumed atomically;
a failed subsequent insert consumes the code safely, requiring a new enrollment.

Telemetry exact shape: `{events:[{event_id,timestamp,operation,decision,executed,reason_code}]}`.
No extra fields, max 25 events, 32 KiB body, 30-day age and five-minute clock skew.
Dedup is per device/event ID while retained. No arbitrary strings for operations or
reasons. Retrieval max100/page; user ownership is always derived from authentication.

Throttles: login/pair20 per source-IP minute, dev login10/minute; OAuth and enrollment
100/hour globally; enrollment creation10/hour/account; account APIs120/minute;
ingest20/minute/device,20 batches/day/account,200 batches/day globally. Global limits
can be exhausted deliberately; the safe outcome is cloud unavailability, not local
policy bypass or automatic paid service. Retention is30 days with hourly cleanup.

Node tests emulate D1 using real SQLite; `public_e2e.py` additionally uses actual
Wrangler/workerd/D1 emulation. Neither proves production OAuth, hosted Free CPU
budget or edge configuration. See `docs/deployment.md` before any publication.
