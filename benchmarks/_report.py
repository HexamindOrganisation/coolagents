"""Shared timing + reporting for the hexgate latency benchmarks.

Deterministic, dependency-free: ``time.perf_counter_ns`` for wall time and
``statistics`` for the percentiles. Both real benches (``bench_enforce`` and
``bench_pull``) import :func:`measure` / :func:`Stats` so a nanosecond is
timed and reported the same way everywhere — the only honest way to compare
two runs across commits.
"""

from __future__ import annotations

import json
import statistics
from collections.abc import Callable
from dataclasses import asdict, dataclass
from time import perf_counter_ns

NS_PER_US = 1_000.0
NS_PER_MS = 1_000_000.0


@dataclass(frozen=True)
class Stats:
    """Summary of one timed segment. All durations in nanoseconds."""

    label: str
    n: int
    mean: float
    p50: float
    p95: float
    p99: float
    minimum: float
    maximum: float
    stdev: float

    @classmethod
    def from_samples(cls, label: str, samples_ns: list[float]) -> "Stats":
        ordered = sorted(samples_ns)
        return cls(
            label=label,
            n=len(ordered),
            mean=statistics.fmean(ordered),
            p50=_percentile(ordered, 50),
            p95=_percentile(ordered, 95),
            p99=_percentile(ordered, 99),
            minimum=ordered[0],
            maximum=ordered[-1],
            stdev=statistics.pstdev(ordered) if len(ordered) > 1 else 0.0,
        )


def _percentile(ordered: list[float], pct: int) -> float:
    """Nearest-rank percentile over an already-sorted list."""
    if not ordered:
        return 0.0
    rank = max(0, min(len(ordered) - 1, round(pct / 100 * len(ordered)) - 1))
    return ordered[rank]


def measure(
    label: str,
    fn: Callable[[], object],
    *,
    iterations: int,
    warmup: int,
) -> Stats:
    """Run ``fn`` ``warmup`` times untimed, then ``iterations`` times timed.

    The warmup absorbs one-off costs that would otherwise skew the first
    sample — JIT paths, wasmtime page-in, cold DNS/TLS on the first HTTP
    hop — so the reported percentiles describe steady state, not startup.
    """
    for _ in range(warmup):
        fn()
    samples: list[float] = []
    for _ in range(iterations):
        start = perf_counter_ns()
        fn()
        samples.append(float(perf_counter_ns() - start))
    return Stats.from_samples(label, samples)


def measure_once(label: str, fn: Callable[[], object]) -> Stats:
    """Time a single invocation — for one-off costs (WASM instantiation,
    client key-verify + JWKS fetch) that don't have a steady state to
    average and would be misleading to loop."""
    start = perf_counter_ns()
    fn()
    elapsed = float(perf_counter_ns() - start)
    return Stats.from_samples(label, [elapsed])


def _fmt(ns: float) -> str:
    """Human unit: µs under a millisecond, ms above."""
    if ns < NS_PER_MS:
        return f"{ns / NS_PER_US:.2f} µs"
    return f"{ns / NS_PER_MS:.2f} ms"


def print_table(title: str, rows: list[Stats]) -> None:
    label_width = max((len(r.label) for r in rows), default=5)
    header = (
        f"{'segment':<{label_width}}  {'n':>6}  {'mean':>11}  "
        f"{'p50':>11}  {'p95':>11}  {'p99':>11}  {'max':>11}"
    )
    print(f"\n{title}")
    print("=" * len(header))
    print(header)
    print("-" * len(header))
    for r in rows:
        print(
            f"{r.label:<{label_width}}  {r.n:>6}  {_fmt(r.mean):>11}  "
            f"{_fmt(r.p50):>11}  {_fmt(r.p95):>11}  {_fmt(r.p99):>11}  "
            f"{_fmt(r.maximum):>11}"
        )
    print()


def emit_json(title: str, rows: list[Stats], path: str) -> None:
    """Write raw nanosecond stats to ``path`` so a later run can be diffed
    against this one (the whole point of keeping a benchmark)."""
    payload = {"title": title, "segments": [asdict(r) for r in rows]}
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)
    print(f"wrote {path}")
