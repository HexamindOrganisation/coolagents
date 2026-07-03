# Hexgate control-plane API image. Build from the REPO ROOT (platform/api has
# an in-repo path dep on the hexgate SDK), amd64-only (deploy arch):
#   docker build --platform linux/amd64 -f platform/api/Dockerfile -t hexgate-api .
# Serves the dashboard SPA same-origin (no separate edge container) — the build
# stage below bakes platform/dashboard/dist into the image. The repo-root
# .dockerignore excludes the dashboard source, so platform/api/Dockerfile.dockerignore
# overrides it to keep that source in the build context.

# ---- build the dashboard SPA ---------------------------------------------
# node 20 + pnpm 9 match CI. The bundle uses relative /v1 + location.host, so
# one build is domain-agnostic and served same-origin by the API below.
FROM node:20-bookworm-slim AS dashboard
ENV PNPM_HOME=/pnpm
ENV PATH=$PNPM_HOME:$PATH
RUN corepack enable && corepack prepare pnpm@9 --activate
WORKDIR /app
# Manifest + lock first so the dep layer caches independently of source.
COPY platform/dashboard/package.json platform/dashboard/pnpm-lock.yaml ./
RUN --mount=type=cache,target=/pnpm/store \
    pnpm install --frozen-lockfile
COPY platform/dashboard/ ./
# Vite inlines VITE_* into the bundle at build time, so the preview banner is a
# BUILD ARG, not a runtime env. Off unless the build passes it (compose sources
# it from .env.<env>). Empty default keeps local/dev builds clean.
ARG VITE_PREVIEW_BANNER=
ENV VITE_PREVIEW_BANNER=$VITE_PREVIEW_BANNER
RUN pnpm build

# ---- control-plane API ---------------------------------------------------
FROM ghcr.io/astral-sh/uv:python3.13-bookworm-slim

# OPA: the control plane shells out to it to sign policy bundles. Match CI.
# Pin by SHA256 so a corrupted/tampered/MITM'd download fails the build (this
# binary signs production policy bundles). Update the checksum with the version.
ADD --checksum=sha256:00d114b94fdb1606a48cccdfc73c9ccdc62c38721150131ae578d5ff3df5c084 \
    https://openpolicyagent.org/downloads/v0.70.0/opa_linux_amd64_static /usr/local/bin/opa
RUN chmod +x /usr/local/bin/opa && opa version

WORKDIR /app

# SDK source (needed to build the hexgate wheel).
COPY pyproject.toml README.md LICENSE ./
COPY hexgate ./hexgate

# Deps in their own layer so they cache until the lock changes. package=false +
# --no-editable: only deps (incl. the SDK) land in the venv; the API runs from
# source (copied below).
COPY platform/api/pyproject.toml platform/api/uv.lock ./platform/api/
WORKDIR /app/platform/api
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev --no-editable

# API source last so edits don't bust the deps layer.
COPY platform/api ./

# Built dashboard, served same-origin by the API (spa.mount_spa reads this path
# via HEXGATE_DASHBOARD_DIST). Under /app so the chown below covers it.
COPY --from=dashboard /app/dist /app/static
ENV HEXGATE_DASHBOARD_DIST=/app/static

# Drop root: a compromised API process must not run as uid 0 with write access
# to the /keys signing-key volume. The named hexgate-keys volume inherits the
# ownership of /keys from the image on first mount, so create it pre-owned by
# the unprivileged user. HOME=/app (owned below) keeps uv's cache writable.
ENV HOME=/app
RUN groupadd --gid 10001 hexgate \
    && useradd --uid 10001 --gid 10001 --no-create-home --home-dir /app hexgate \
    && mkdir -p /keys \
    && chown -R hexgate:hexgate /app /keys
USER hexgate

EXPOSE 8000

# Liveness only: /health has no dependency checks (unlike /ready, which 503s on
# unreachable ClickHouse) so a degraded-but-running container isn't killed.
# urllib over curl/wget — neither is in the slim base, but python is.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD ["python", "-c", "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://localhost:8000/health', timeout=4).status==200 else 1)"]

# Single worker: the WS relay holds connections in-process, can't span workers.
# --no-sync: use the venv built above, no runtime re-resolution.
# --proxy-headers: trust X-Forwarded-Proto/For from the box's reverse proxy
# (TLS terminates upstream), so request.url is https for OAuth callbacks + link
# generation. The proxy MUST set X-Forwarded-Proto: https.
CMD ["uv", "run", "--no-sync", "uvicorn", "hexgate_api.main:app", \
     "--host", "0.0.0.0", "--port", "8000", "--workers", "1", \
     "--proxy-headers", "--forwarded-allow-ips", "*"]
