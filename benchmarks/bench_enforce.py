"""Bench A — policy enforcement latency (local, no secrets, no network).

The purest deterministic signal in the SDK: once a bundle's WASM is loaded,
what does one ``decide()`` cost? No platform, no LLM, no I/O — just the
wasmtime evaluation and the enforcer wrapper around it.

Requires ``opa`` on PATH (used once at startup to compile the example policy
to WASM via ``build_signed_bundle``). Run:

    uv run python -m benchmarks.bench_enforce [--json out.json]

Segments measured:
  * ``wasm_instantiate``   — one-off ``WasmPolicy.from_bytes`` cost.
  * ``wasm_cache_hit``     — ``from_bytes_cached`` on a warm hash (refresh path).
  * ``engine:<case>``      — raw ``PolicyBundle.evaluate`` per workload case.
  * ``enforcer:<case>``    — ``PolicyEnforcer.decide`` per case (adds the
                             Decision + audit/observer wrapper). The delta vs
                             the matching ``engine:`` row is the wrapper tax.
"""

from __future__ import annotations

import argparse
import shutil
import sys
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from benchmarks._report import (
    Stats,
    emit_json,
    measure,
    measure_once,
    print_table,
)
from hexgate.runtime.context import User
from hexgate.security.bundle import PolicyBundle, build_signed_bundle
from hexgate.security.decision import Decision, DecisionOutcome
from hexgate.security.enforcer import PolicyEnforcer
from hexgate.security.wasm_engine import WasmPolicy, _wasm_policy_cache

WARMUP = 500
ITERATIONS = 10_000
AGENT_NAME = "devops_agent"
POLICY_PATH = Path(__file__).resolve().parent.parent / "examples" / "devops_policy.yaml"


def _noop_observer(_decision: Decision) -> None:
    """Wired only so ``decide()`` takes the ``copy.deepcopy(args)`` branch
    every audited production enforcer takes; else the wrapper tax is
    understated. Local-only, so it adds nothing beyond the copy."""


@dataclass(frozen=True)
class Case:
    """One workload call plus the outcome the policy is expected to produce,
    so a silent policy change that breaks the mix is caught, not benchmarked."""

    label: str
    role: str
    tool: str
    args: Mapping[str, Any]
    expected: DecisionOutcome


# Drawn from examples/devops_policy.yaml so each branch of the compiled
# decision tree is exercised — a fast allow, a constrained allow, and two
# distinct deny paths (constraint violation vs default_policy).
WORKLOAD: tuple[Case, ...] = (
    Case("allow_mixin", "default", "read_logs", {}, DecisionOutcome.ALLOW),
    Case(
        "allow_constrained",
        "operator",
        "scale_deployment",
        {"service": "web-api", "env": "staging", "replicas": 5},
        DecisionOutcome.ALLOW,
    ),
    Case(
        "deny_constraint",
        "operator",
        "scale_deployment",
        {"service": "web-api", "env": "staging", "replicas": 50},
        DecisionOutcome.DENY,
    ),
    Case(
        "deny_default",
        "default",
        "restart_service",
        {"service": "web-api", "env": "dev"},
        DecisionOutcome.DENY,
    ),
)


def _build_bundle() -> PolicyBundle:
    """Compile the example policy to a real WASM bundle (needs opa)."""
    policy_yaml = POLICY_PATH.read_text(encoding="utf-8")
    signed = build_signed_bundle(policy_yaml, source_name=POLICY_PATH.name)
    if signed.wasm_bytes is None:
        raise RuntimeError("build_signed_bundle produced no wasm — opa missing?")
    return PolicyBundle.from_parts(
        wasm_bytes=signed.wasm_bytes,
        manifest_bytes=signed.manifest_bytes,
    )


def _verify_workload(bundle: PolicyBundle) -> None:
    """Fail fast if the policy no longer produces the outcomes the mix
    assumes — a benchmark over the wrong branches is worse than none."""
    for case in WORKLOAD:
        verdict = bundle.evaluate(role=case.role, tool=case.tool, args=case.args)
        if verdict.outcome is not case.expected:
            raise RuntimeError(
                f"workload case {case.label!r} expected {case.expected} but "
                f"policy returned {verdict.outcome}; update WORKLOAD or policy."
            )


def _instantiation_stats(
    wasm_bytes: bytes, wasm_hash: str, iterations: int
) -> list[Stats]:
    _wasm_policy_cache.clear()
    cold = measure_once("wasm_instantiate", lambda: WasmPolicy.from_bytes(wasm_bytes))
    # Prime the content-addressed cache, then time the hit — the per-turn
    # refresh path when the wasm hasn't changed (the common case).
    WasmPolicy.from_bytes_cached(wasm_bytes, wasm_hash)
    warm = measure(
        "wasm_cache_hit",
        lambda: WasmPolicy.from_bytes_cached(wasm_bytes, wasm_hash),
        iterations=iterations,
        warmup=WARMUP,
    )
    return [cold, warm]


def _engine_stats(bundle: PolicyBundle, iterations: int) -> list[Stats]:
    rows: list[Stats] = []
    for case in WORKLOAD:
        rows.append(
            measure(
                f"engine:{case.label}",
                lambda c=case: bundle.evaluate(role=c.role, tool=c.tool, args=c.args),
                iterations=iterations,
                warmup=WARMUP,
            )
        )
    return rows


def _enforcer_stats(bundle: PolicyBundle, iterations: int) -> list[Stats]:
    rows: list[Stats] = []
    for case in WORKLOAD:
        # No audit_sender (no network emit), but a no-op observer so
        # decide() still deep-copies args — the production wrapper tax.
        enforcer = PolicyEnforcer(
            bundle, agent_name=AGENT_NAME, decision_observer=_noop_observer
        )
        user = User(user_id="bench", role=case.role)
        with user.sync_scope():
            rows.append(
                measure(
                    f"enforcer:{case.label}",
                    lambda c=case: enforcer.decide(c.tool, c.args),
                    iterations=iterations,
                    warmup=WARMUP,
                )
            )
    return rows


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", metavar="PATH", help="write raw stats as JSON")
    parser.add_argument(
        "--iterations", type=int, default=ITERATIONS, help="timed iterations per case"
    )
    args = parser.parse_args()

    if shutil.which("opa") is None:
        print(
            "error: opa not on PATH — install via `brew install opa` to compile "
            "the policy for this benchmark.",
            file=sys.stderr,
        )
        return 1

    iterations = args.iterations

    print(f"compiling {POLICY_PATH.name} → wasm (opa)…")
    bundle = _build_bundle()
    _verify_workload(bundle)
    assert bundle.wasm_hash is not None

    rows: list[Stats] = []
    rows += _instantiation_stats(bundle.wasm_bytes, bundle.wasm_hash, iterations)
    rows += _engine_stats(bundle, iterations)
    rows += _enforcer_stats(bundle, iterations)

    print_table(f"Bench A — enforcement latency ({iterations:,} iterations/case)", rows)
    if args.json:
        emit_json("bench_enforce", rows, args.json)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
