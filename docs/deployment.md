# Zero-mandatory-cost publication runbook

**Production deployment remains gated.** The official repository is now
[Prabin-Poudel-1/sentinel-si](https://github.com/Prabin-Poudel-1/sentinel-si), and
four-platform release CI is complete. This documentation phase neither deploys cloud
services nor publishes a release; production cloud remains unverified and disabled. Resolve the
release-readiness gates first. Every command below that changes a remote service is
for the owner to run deliberately, after authorization and review.

## Free-tier constraints

Official documentation checked 2026-10-14:

| Service | Free allocation relevant here | Behavior |
|---|---|---|
| Workers / Pages Functions | 100,000 dynamic requests/day; 10 ms CPU/invocation | Shared limited allowance; API may become unavailable |
| D1 | 5 million rows read/day, 100,000 rows written/day, 5 GB total | Reads count scanned rows; indexes also cost writes; requests fail at limit |
| D1 per database | 500 MB; 50 queries per Worker invocation | Current max25-event batch stays below50 including checks |
| Pages | 500 builds/month on Free | Static public site remains separate from dynamic API quotas |
| GitHub public Releases | Repository release assets, each under2 GiB | Use public official repository; no mandatory paid distribution provider |

Sources: [Workers pricing](https://developers.cloudflare.com/workers/platform/pricing/),
[D1 pricing](https://developers.cloudflare.com/d1/platform/pricing/),
[D1 limits](https://developers.cloudflare.com/d1/platform/limits/),
[Pages limits](https://developers.cloudflare.com/pages/platform/limits/),
[GitHub Releases](https://docs.github.com/en/repositories/releasing-projects-on-github/about-releases).
These are capacity limits, not unlimited free production guarantees. Use the provider
subdomain (no mandatory paid domain), Free plans only and user-provided compute/models.
Verify current account settings and documentation before publication. Do not enable
paid overages or add commercial AI/authentication services.

The API caps ingestion at20 batches/day/account and200/day globally, max25 events each.
This caps successful new ingestion at5,000 events/day globally. Indexed writes,
retention deletion, auth, dashboard reads and rate-limit accounting consume additional
quota. Anonymous/distributed abuse can still exhaust free capacity. A 429/503 or
provider quota failure leaves the bounded local queue for retry; local authorization
never fails open and never waits for the cloud. Measure real hosted CPU/row usage and
reduce beta capacity if needed; local timings do not establish the10ms edge budget.

## 1. Prepare an official public repository

Use the official repository above. Private vulnerability reporting is documented in
SECURITY.md; confirm the MIT license/copyright and maintainer 2FA. A clean Gitleaks
history scan of nine commits is maintainer-reported. Refresh scanning for the final
release tag and artifacts; do not extend that result to subsequent commits.
Use branch protection, required reviews/checks and no untrusted self-hosted PR runners.
Keep production secrets out of repository/Actions PR jobs. The supplied workflows have
read-only contents permissions and verified full-SHA action references.

## 2. Configure free accounts and resources

Create/sign into GitHub and Cloudflare yourself. Stay on Free plans. In Cloudflare,
create a Pages project named by you; use the assigned exact HTTPS `pages.dev` origin.
Install pinned tooling with `npm ci --prefix cloud` and authenticate interactively:

```sh
cd cloud
npx wrangler login
npx wrangler d1 create sentinel-metadata
```

Copy the returned database ID into `cloud/wrangler.toml`, set database_name to
`sentinel-metadata`, set PUBLIC_ORIGIN to the exact Pages HTTPS origin (no trailing
slash/path), DEV_MODE=false and leave PRODUCTION_ENABLED=false during initial setup.
Do not use the all-zero local database ID remotely. Keep workers_dev=false; the API
is reached through the fixed Pages service binding, not a separate cross-site cookie.

## 3. GitHub OAuth

GitHub Settings → Developer settings → OAuth Apps → New OAuth App. Set Homepage to
that exact Pages origin and callback to `<origin>/api/auth/github/callback`. Use an
OAuth App, not broad repository PATs. This implementation requests no extra scopes.
Set GITHUB_CLIENT_ID as a non-secret Worker variable, and store the client secret via:

```sh
npx wrangler secret put GITHUB_CLIENT_SECRET
```

Enter the secret at the prompt; never put it in a command argument, source, browser
storage or `.dev.vars` committed to Git. Review [GitHub authorization-code/PKCE
requirements](https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps).
Production callback/state/cookies require real owner-controlled testing.

## 4. Migrate and deploy the disabled API, then Pages

These are remote changes; run only after explicit publication authorization:

```sh
# From cloud/, with reviewed production configuration:
npx wrangler d1 migrations apply sentinel-metadata --remote
npx wrangler deploy
# From repository root:
python3.12 web/build.py
python3.12 web/dashboard_page.py
cd web
../cloud/node_modules/.bin/wrangler pages project create YOUR_PAGES_PROJECT
../cloud/node_modules/.bin/wrangler pages deploy dist --project-name YOUR_PAGES_PROJECT
```

If the Pages project already exists, skip project create. Pages Functions live in
`web/functions`; the deployment command must run from `web/`. In Pages project
Settings → Bindings, add service binding `API` to `sentinel-ai-cloud`, then redeploy
Pages so the binding applies. Configure production only; preview projects must not
share production databases/secrets. No wildcard CORS or browser-chosen upstream exists.
The frontend should render while API requests503 until activation.

Before controlled activation: configure real download/repository/disclosure links in
`web/build.py`, rebuild pages, verify static headers and API service binding. Then
set PRODUCTION_ENABLED=true only for the owner-controlled production smoke test and
redeploy the Worker. If any gate fails, restore false immediately. DEV_MODE must remain
false, and `/api/dev/login` must be404. Never expose the local administrator dashboard.

## 5. Production health and security validation

Verify real GitHub login/logout, Secure HttpOnly __Host cookies, exact callback/Origin,
CSRF rejection, session expiration, pairing single-use, two-account isolation, token
rotation/revocation, native keyring storage, HTTPS upload and event deletion. Confirm
no secrets in browser storage/logging and no source/private paths in static assets.
Inspect actual D1 metrics and Worker CPU, retention cron and free-plan behavior. The
local E2E report is not evidence that these production checks succeeded.

## 6. Publish a verified installation release

The [four-platform candidate workflow has passed](release-validation-v0.3.0-rc.1.md).
Use artifacts from the reviewed successful run; a new build is needed only if release
inputs change. The workflow builds artifacts only and does not publish. Review successful platform tests,
download artifacts, verify manifests/SHA256 and installer behavior. Do not label any
unexecuted matrix platform as verified. Native Windows has no verified artifact.

Create a **draft** GitHub release `v0.3.0-rc.1` via the repository Releases UI, attach
only reviewed `.tar.gz` and `.sha256` files, and link the readiness/security report.
Preview contents and release notes before explicitly publishing. Update the site's
previously disabled buttons to the exact reviewed release URLs and redeploy it.
Artifacts here are unsigned/unnotarized. SHA256+local manifest are not cryptographic
build attestations. Consider GitHub artifact attestations in a separately reviewed
release-only workflow with id-token/attestations write permissions; none are claimed now.

## 7. Monitoring and rollback

Watch Cloudflare Worker errors/CPU and D1 rows/storage; avoid raw request/body logging.
Protect OAuth callback query strings from request logging. At exhaustion, keep the
Free plan, reduce ingest/refresh rates, wait for reset and communicate cloud staleness.
Do not upgrade automatically. Back up metadata privately before schema changes.

For an unsafe deployment, disable production API first, roll back Worker and Pages to
reviewed versions in provider UI, and restore only a compatible D1 backup. Reapply
revocations so backups cannot resurrect stolen credentials. Keep local enforcement
running independently. See incident-response.md for account/device/artifact compromise.
