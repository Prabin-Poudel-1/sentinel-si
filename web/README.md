# Public frontend and observational dashboard

Dependency-free, same-origin HTML/CSS/JavaScript. The existing `dashboard/dist/`
local administration UI is unchanged; this `web/dist/` UI never grants local
permissions or runs local tools.

## Build

From the repository root (Python 3.12+):

```sh
python web/build.py
python web/dashboard_page.py
```

The static files are committed/generated deliverables, so no build is required
for ordinary local development. `research-data.json` is the existing
`benchmarks/phase2-results.json` artifact, not a newly measured result. Its table
must be updated deliberately together with methodology if a different artifact
is published.

## Local preview

Use the cloud Worker's local development command from `cloud/README.md`; its
`ASSETS` binding serves `web/dist`. A static-only server can preview public pages,
but account functionality correctly remains unavailable without the API.

The dashboard's development login is visible only at loopback hostnames. The
backend additionally requires explicit development mode and a configured random
key; the browser does not establish the security boundary. Production login uses
GitHub OAuth. Sessions use HttpOnly cookies, and CSRF tokens remain in memory.

## Pages preparation (manual publication only)

Set Pages output directory to `web/dist`; there is no Node build step. Place the
Pages Functions directory at `web/functions` (run Wrangler Pages commands from
`web/`). Bind the Pages service binding **API** to the reviewed Sentinel Worker.
`functions/api/[[path]].js` forwards only the `/api/` namespace to that fixed
binding. Configure the Worker's exact `PUBLIC_ORIGIN` to the Pages origin. Do not
configure wildcard CORS or an arbitrary browser-selected upstream.

Public pages can render while the API is unavailable. Protected requests fail
closed; the dashboard displays unavailable/stale status and never substitutes
sample records. `_headers` supplies a strict CSP and other static security
headers. Worker responses must independently set API security headers.

## Publication prerequisites

No GitHub repository, release URL, security contact or Cloudflare account is
invented in this source. Download buttons are intentionally disabled until the
owner configures official release links and verifies the artifacts. Update
`build.py` with the real repository, release asset links, verified platform labels
and private security reporting channel before publication, then rebuild.

Do not advertise native Windows as verified. Do not publish private local reports,
state databases, enrollment codes or screenshots containing credentials.
