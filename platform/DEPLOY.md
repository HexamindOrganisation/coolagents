# Deploying Hexgate (prod + staging on one machine)

Two environments share one box. Each is an isolated Compose **project**
(`hexgate-prod`, `hexgate-staging`) built from the same
[`docker-compose.deploy.yml`](docker-compose.deploy.yml) — its own Postgres,
ClickHouse, keystore, and network. Each env's **api** serves both the JSON API
(`/v1/*`) and that env's dashboard SPA same-origin, listening plain HTTP on a
**loopback port** (prod `7000`, staging `7200`). There is no separate edge
container — the SPA is baked into the API image and served by it.

The box **already runs a reverse proxy** that owns 80/443 and terminates TLS.
Hexgate does not ship its own front proxy — you point the existing one at the
two loopback ports by hostname.

```
                            one machine (one IP)
 Internet ──:443──▶  the box's existing reverse proxy — TLS
   app.hexgate.ai          │  Host: app.hexgate.ai          → 127.0.0.1:7000
   app.staging.hexgate.ai  │  Host: app.staging.hexgate.ai  → 127.0.0.1:7200
                  ┌───────┴───────┐            ┌───────────────┐
                  │ hexgate-prod  │            │hexgate-staging│
                  │  api→pg,ch    │            │  api→pg,ch    │
                  └───────────────┘            └───────────────┘
```

The reverse proxy must be able to reach the host loopback (it's host-installed
or runs with host networking). A bridged proxy container can't see
`127.0.0.1:7000` — in that case change the `api` port binding in the compose to
publish on a shared Docker network or a non-loopback port instead.

Images build **on the box** — no registry. amd64 throughout (the API bundles
the amd64-only OPA binary; the image also runs a Node build stage to bundle the
dashboard SPA).

## 1. DNS

Point both hostnames at the box's IP **before** first start (the reverse
proxy's TLS issuance checks them):

```
app.hexgate.ai          A   <box-IP>
app.staging.hexgate.ai  A   <box-IP>
```

**80 and 443** are owned by the box's reverse proxy. The 7000/7200 ports stay
loopback — never exposed.

## 2. Layout (two checkouts)

So staging can run ahead of prod, check each environment out separately:

```bash
git clone <repo> /srv/hexgate-prod    && cd /srv/hexgate-prod    && git checkout <release-tag>
git clone <repo> /srv/hexgate-staging && cd /srv/hexgate-staging && git checkout main
```

Project names are fixed in the Makefile, so isolation holds regardless of
directory.

## 3. Configure

`platform/.env.<stage>` is **pulled from the Scaleway secret `/hexgate/<stage>`**
(opaque, full env file as payload), never hand-copied.

**Admin, one-time:** create `/hexgate/<stage>` as an opaque secret in `fr-par`
from the `platform/.env.sample` template — `HEXGATE_POSTGRES_PASSWORD`,
`HEXGATE_CLICKHOUSE_PASSWORD` (`openssl rand -hex 32`), any `RESEND_API_KEY` /
Google OAuth values. Editing it adds a version; pull takes the latest.

**Box prerequisites:** `scw` + `jq`, with read-only Secret Manager creds
(`scw init`, or `SCW_ACCESS_KEY` / `SCW_SECRET_KEY` / `SCW_DEFAULT_PROJECT_ID`).
Region defaults to `fr-par` (`SCW_DEFAULT_REGION`), folder to `/hexgate`
(`HEXGATE_SECRET_PATH`).

```bash
make platform-env-pull STAGE=prod      # writes platform/.env.prod (also auto-run by platform-up if absent)
```

Then add two routes to the box's reverse proxy (one-time), so each hostname
terminates TLS and proxies to its loopback port:

```
app.hexgate.ai          → 127.0.0.1:7000   (except path /v1/traces → 127.0.0.1:7001)
app.staging.hexgate.ai  → 127.0.0.1:7200   (except path /v1/traces → 127.0.0.1:7201)
```

The `/v1/traces` path routes to the stage's `HEXGATE_OTLP_PORT` — the
collector's OTLP/HTTP receiver — and must match BEFORE the hostname's
catch-all route (in Caddy a `handle /v1/traces` block above the general
`reverse_proxy`; in nginx an exact `location = /v1/traces`). This is what
lets the SDK's default endpoint (`<api url>/v1/traces`) work with zero
client config. Everything else in the stack (Postgres, ClickHouse,
Redpanda) binds no host ports; Redpanda in particular is PLAINTEXT with no
auth — never publish it.

(In Caddy this is two `reverse_proxy` site blocks; in nginx, two `server`
blocks with `proxy_pass`. Forward `X-Forwarded-Proto: https` — the API trusts
it, via uvicorn `--proxy-headers`, for correct https OAuth callbacks. `/v1`
includes WebSocket endpoints, so the proxy must pass upgrades — Caddy does this
automatically; nginx needs the `Upgrade`/`Connection` headers set.)

## 4. Launch — env stacks, then wire up the proxy

```bash
# /srv/hexgate-prod
make platform-up STAGE=prod
# /srv/hexgate-staging
make platform-up STAGE=staging
# then reload the box's reverse proxy so it routes to 7000/7200
```

Bring the env stacks up before the proxy routes them, so TLS issuance doesn't
race the upstreams. First boot per env: ClickHouse runs `schema.sql` once, the
API runs `init_db()` (no migration step) and serves the SPA immediately.

Verify:

```bash
docker ps                                    # hexgate-prod-* and hexgate-staging-* healthy
curl -sf https://app.hexgate.ai/v1/health    # → 200
curl -sf https://app.staging.hexgate.ai/v1/health
```

## 5. First admin (per env)

`HEXGATE_SEED=skip` → no seeded admin. Self-register on each env:

```bash
curl -X POST https://app.hexgate.ai/v1/auth/register \
  -H 'content-type: application/json' -d '{"email":"you@example.com","password":"<strong>"}'
```

(or Google sign-in if `HEXGATE_GOOGLE_CLIENT_ID/SECRET` are set — register the
`/v1/auth/google/callback` URL for each hostname).

## 6. Upgrades

```bash
cd /srv/hexgate-<stage> && git pull   # or checkout a new tag for prod
make platform-up STAGE=<stage>        # rebuilds changed images, recreates containers
```

Promote a release: tag it, `git checkout` it in the prod checkout, re-run
`make platform-up STAGE=prod`.

Upgrades reuse the env already on the box. If the secret changed, refresh it
first: `make platform-env-pull STAGE=<stage>`.

## Operations

**Back up these volumes** (per env, prefixed `hexgate-prod_` / `hexgate-staging_`):

| Volume | Holds | If lost |
|---|---|---|
| `pg-data` | control-plane DB | total data loss |
| `ch-data` | audit log | audit history lost |
| `hexgate-keys` | signing/session keystore | every token/session/bundle invalidated |

The box's reverse proxy holds the TLS certs — back those up per its own docs
(losing them risks Let's Encrypt rate limits on re-issue).

**Single API instance per env** — the in-process WS relay can't span workers or
hosts (`platform/api/Dockerfile`). Scale up, not out.

**Schema changes** apply only on an empty volume; changing one after first boot
needs a manual migration.

## Consumer SDK

Point the SDK at the env's public origin (no `/v1`, no port — the proxy handles
both):

```bash
export HEXGATE_API_URL=https://app.hexgate.ai     # or app.staging.hexgate.ai
export HEXGATE_API_KEY=fty_live_...                    # token minted in that env's dashboard
```
