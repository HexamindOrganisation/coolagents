# hexgate-collector deploy image (service `collector` in
# platform/docker-compose.deploy.yml; local dev keeps running the binary
# natively via `make collector-run`). The Go source here is committed ocb
# output (`make collector-generate`), so this is a plain `go build` — no
# builder tool at image-build time.

# Match go.mod's directive; bump together.
FROM golang:1.25-bookworm AS build

WORKDIR /src

# Manifests first so the module download caches until a dependency changes.
# builder-config.yaml `replaces` the biscuit-auth extension to its in-tree
# path, so its manifest must exist before `go mod download` parses go.mod.
COPY go.mod go.sum ./
COPY extension/hexgatebiscuitauth/go.mod extension/hexgatebiscuitauth/go.sum ./extension/hexgatebiscuitauth/
RUN --mount=type=cache,target=/go/pkg/mod go mod download

COPY . .
# CGO off: nothing here needs cgo, and a static binary keeps the runtime
# image's libc out of the compatibility equation.
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -o /out/hexgate-collector .

# Slim-not-distroless on purpose: the compose healthcheck is a bash /dev/tcp
# probe (the ocb manifest builds no health extension into the collector, so
# there is no HTTP endpoint to hit).
FROM debian:bookworm-slim

COPY --from=build /out/hexgate-collector /usr/local/bin/hexgate-collector
# The image ships the same config.yaml dev runs; every deploy-varying value in
# it (bind addresses, brokers, DSN, public key path) is an ${env:...} lookup,
# set by the compose service.
COPY config.yaml /etc/hexgate/config.yaml

# Non-root, and a DIFFERENT uid than the api image's hexgate user (10001): on
# the shared /keys volume this user can read the 0644 hexgate.pub but not the
# 0600 hexgate.priv — the collector must never be able to sign keys.
RUN groupadd --gid 10002 collector \
    && useradd --uid 10002 --gid 10002 --no-create-home --home-dir /nonexistent collector
USER collector

EXPOSE 4317 4318

ENTRYPOINT ["/usr/local/bin/hexgate-collector"]
CMD ["--config=/etc/hexgate/config.yaml"]
