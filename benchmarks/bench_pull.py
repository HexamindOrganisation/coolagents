"""Bench B — policy pull latency (network + a real API key).

Measures what the SDK spends pulling a policy from the platform
(``app.hexgate.ai`` by default via ``resolve_api_url``). The point is to
separate the *deterministic* crypto cost from the *variable* network cost —
conflating them yields a number that means nothing.

Requires ``HEXGATE_API_KEY`` in the environment (or ``.env``). Optionally set
``HEXGATE_PUBLIC_KEY`` to skip the JWKS round-trip. Run:

    uv run python -m benchmarks.bench_pull [AGENT_NAME] [--samples N] [--json out.json]

Segments measured:
  * ``key_verify+jwks``  — one-off: biscuit signature verify + (unless a
                           public key is configured) the JWKS fetch.
  * ``verify_only``      — deterministic, NO network: decode + verify a
                           captured bundle payload (base64 + Ed25519 + sha256).
                           Skipped when the platform served no compiled bundle.
  * ``pull_cold_200``    — full ``fetch()``: round-trip + decode + verify.
  * ``pull_warm_304``    — conditional policy ``fetch()`` (If-None-Match → 304),
                           in isolation. Skipped on the no-bundle branch.
  * ``ban_warm_304``     — same conditional GET against ``/v1/bans``.
  * ``policy+ban_b2b``   — both back to back: the real per-turn refresh cost.
"""

from __future__ import annotations

import argparse
import os
import sys

from benchmarks._report import Stats, emit_json, measure, measure_once, print_table
from hexgate.bootstrap import bootstrap
from hexgate.cloud.client import HexgateClient, HexgateError
from hexgate.config.env import resolve_api_key, resolve_api_url
from hexgate.security.bans import PlatformBanSource
from hexgate.security.source import (
    PlatformPolicySource,
    decode_and_verify_platform_bundle,
)

DEFAULT_AGENT_NAME = "devops_agent"
# Network is slow and the platform may rate-limit; a few dozen samples
# characterize the spread without hammering prod.
DEFAULT_SAMPLES = 30
NETWORK_WARMUP = 2
# verify_only is local crypto: loop it hard, but cap warmup so small
# iteration counts don't warm longer than they measure.
VERIFY_ONLY_ITERATIONS = 1000
VERIFY_ONLY_WARMUP_CAP = 50


def _one_time_stats(agent_name: str) -> tuple[Stats, HexgateClient]:
    """Fresh client → first verified touch. Times biscuit verify + (unless a
    public key is preconfigured) the JWKS fetch. Returns a *warmed* client
    the later segments reuse, so its key is verified exactly once."""
    client = HexgateClient.from_env()
    stats = measure_once("key_verify+jwks", client.biscuit_facts)
    return stats, client


def _verify_only_stats(
    client: HexgateClient, agent_name: str, iterations: int
) -> tuple[list[Stats], bool]:
    """Capture one real payload, then loop decode+verify locally — pure
    crypto, zero network variance. This is the honest 'what does bundle
    verification cost' number.

    Returns ``(stats, has_bundle)``; ``has_bundle`` is False when no
    compiled bundle was served, so the caller can skip the 304-only rows."""
    payload, _ = client.get_agent(agent_name)
    if payload is None:
        raise HexgateError("unconditional get_agent returned no payload")
    pub = client.public_key_bytes()
    bundle = decode_and_verify_platform_bundle(payload, pub)
    if bundle is None:
        print(
            f"note: platform served no compiled bundle for {agent_name!r} "
            "(pydantic-fallback shape) — skipping verify_only.",
            file=sys.stderr,
        )
        return [], False
    return [
        measure(
            "verify_only",
            lambda: decode_and_verify_platform_bundle(payload, pub),
            iterations=iterations,
            warmup=min(iterations, VERIFY_ONLY_WARMUP_CAP),
        )
    ], True


def _cold_pull_stats(client: HexgateClient, agent_name: str, samples: int) -> Stats:
    """Force a 200 every sample by using a fresh source (no cached etag),
    so each call pays the full round-trip + decode + verify."""

    def cold() -> None:
        PlatformPolicySource(client, agent_name).fetch()

    return measure("pull_cold_200", cold, iterations=samples, warmup=NETWORK_WARMUP)


def _warm_refresh_stats(
    client: HexgateClient, agent_name: str, samples: int, has_bundle: bool
) -> list[Stats]:
    """Policy 304, ban 304, and both back to back — the real per-turn cost,
    matching invoke's sequential `_refresh_policy_safely` then `_check_ban`
    (never gathered, so additive). Sources primed once → every timed call
    sends If-None-Match. Skipped on the no-bundle branch (never 304s)."""
    if not has_bundle:
        print(
            f"note: no compiled bundle for {agent_name!r} — no 304 hot path, "
            "skipping warm-refresh rows.",
            file=sys.stderr,
        )
        return []

    policy = PlatformPolicySource(client, agent_name)
    policy.fetch()  # prime etag
    rows = [
        measure(
            "pull_warm_304", policy.fetch, iterations=samples, warmup=NETWORK_WARMUP
        )
    ]

    # PlatformBanSource is fail-soft; confirm the feed serves an etag first, or
    # the ban rows would time a fast empty-return, not a conditional GET.
    _, ban_etag = client.get_bans()
    if ban_etag is None:
        print(
            "note: /v1/bans served no etag — skipping ban + back-to-back rows.",
            file=sys.stderr,
        )
        return rows

    ban = PlatformBanSource(client)
    ban.fetch()  # prime etag

    def back_to_back() -> None:
        policy.fetch()
        ban.fetch()

    rows.append(
        measure("ban_warm_304", ban.fetch, iterations=samples, warmup=NETWORK_WARMUP)
    )
    rows.append(
        measure(
            "policy+ban_b2b", back_to_back, iterations=samples, warmup=NETWORK_WARMUP
        )
    )
    return rows


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("agent_name", nargs="?", default=DEFAULT_AGENT_NAME)
    parser.add_argument("--samples", type=int, default=DEFAULT_SAMPLES)
    parser.add_argument("--json", metavar="PATH", help="write raw stats as JSON")
    args = parser.parse_args()

    bootstrap()
    if not resolve_api_key():
        print(
            "error: HEXGATE_API_KEY not set — export it (or add it to .env) to "
            "run the pull benchmark.",
            file=sys.stderr,
        )
        return 1

    url = resolve_api_url()
    has_pubkey = bool(os.environ.get("HEXGATE_PUBLIC_KEY"))
    print(f"target: {url}  agent: {args.agent_name}")
    print(
        f"public key preconfigured: {has_pubkey} (JWKS fetch {'skipped' if has_pubkey else 'included in key_verify+jwks'})"
    )

    try:
        one_time, client = _one_time_stats(args.agent_name)
        rows: list[Stats] = [one_time]
        verify_rows, has_bundle = _verify_only_stats(
            client, args.agent_name, iterations=VERIFY_ONLY_ITERATIONS
        )
        rows += verify_rows
        rows.append(_cold_pull_stats(client, args.agent_name, args.samples))
        rows += _warm_refresh_stats(client, args.agent_name, args.samples, has_bundle)
    except (HexgateError, RuntimeError, OSError) as exc:
        # RuntimeError: invalid bundle; OSError: read-timeout the client
        # doesn't wrap. Both would otherwise crash instead of exiting clean.
        print(f"error talking to the platform: {exc}", file=sys.stderr)
        return 1

    print_table(f"Bench B — policy pull latency ({args.samples} network samples)", rows)
    print(
        "note: pull_* rows include real network variance — read min vs p99, "
        "not p50 alone, as the SDK's fixed overhead."
    )
    if args.json:
        emit_json("bench_pull", rows, args.json)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
