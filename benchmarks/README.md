# Hexgate latency benchmarks

Measures the latency the SDK adds around an agent's tool calls, split into the
two deterministic costs plus an optional end-to-end sanity check. Each bench is
a standalone script (stdlib only — `time.perf_counter_ns` + `statistics`), so
there's nothing to install beyond the SDK's own env.

All benches print a p50/p95/p99/max table and accept `--json PATH` to dump raw
nanosecond stats for diffing a later run against this one.

## Bench A — enforcement latency (`bench_enforce.py`)

**Local, no secrets, no network.** The purest signal: once a policy's WASM is
loaded, what does one `decide()` cost? Needs `opa` on PATH (used once at
startup to compile `examples/devops_policy.yaml`).

```
uv run python -m benchmarks.bench_enforce [--iterations N] [--json out.json]
```

Segments:
- `wasm_instantiate` — one-off `WasmPolicy.from_bytes` cost.
- `wasm_cache_hit` — `from_bytes_cached` on a warm hash (the per-turn refresh
  path when the wasm hasn't changed).
- `engine:<case>` — raw `PolicyBundle.evaluate` per workload case.
- `enforcer:<case>` — `PolicyEnforcer.decide` per case; the delta vs the
  matching `engine:` row is the `Decision`-build + audit/observer wrapper tax.

The workload draws four cases from the devops policy so each branch of the
compiled decision tree runs: a fast allow, a constrained allow, a
constraint-violation deny, and a default-policy deny. The bench asserts each
case's outcome before timing — a policy change that breaks the mix fails loudly
rather than benchmarking the wrong branch.

## Bench B — policy pull latency (`bench_pull.py`)

**Needs `HEXGATE_API_KEY`** (read from env or `.env`); targets `app.hexgate.ai`
by default via the SDK's normal URL resolution. Set `HEXGATE_PUBLIC_KEY` to
skip the JWKS round-trip.

```
uv run python -m benchmarks.bench_pull [AGENT_NAME] [--samples N] [--json out.json]
```

Segments:
- `key_verify+jwks` — one-off: biscuit signature verify + (unless a public key
  is configured) the JWKS fetch. Dominated by the first-TLS cold start.
- `verify_only` — **deterministic, no network**: decode + verify a captured
  bundle payload (base64 + Ed25519 + sha256), looped. The honest "what does
  bundle verification cost" number. Skipped when the platform served no
  compiled bundle (pydantic-fallback shape).
- `pull_cold_200` — full `fetch()`: round-trip + decode + verify (fresh source
  each sample forces a 200).
- `pull_warm_304` — conditional `fetch()` with `If-None-Match` → 304. This is
  the actual per-chat-turn refresh cost.

`pull_*` rows carry real network variance — read min vs p99, not p50 alone, as
the SDK's fixed overhead. `verify_only` is the part that stays constant across
runs and machines.

## Indicative numbers

From one dev-machine run (Apple Silicon, `app.hexgate.ai`) — **illustrative,
not a contract**; re-run on the target host:

| segment | p50 |
|---|---|
| `wasm_instantiate` (one-off) | ~135 ms |
| `wasm_cache_hit` | < 1 µs |
| enforcement `decide()` (per tool call) | ~200–300 µs |
| `verify_only` (per pull, deterministic) | ~1.8 ms |
| `pull_warm_304` (per chat turn) | ~50 ms (network-bound) |
| `pull_cold_200` (on policy change) | ~76 ms (network-bound) |
| `key_verify+jwks` (one-off, cold) | ~375 ms (network-bound) |

Takeaway: the deterministic overhead hexgate adds per tool call is
sub-millisecond (a few hundred µs of WASM eval); the recurring pull cost is a
~50 ms conditional GET per turn, dominated by network round-trip, not by the
SDK's crypto (~1.8 ms).
