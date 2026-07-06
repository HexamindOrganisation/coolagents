"""Generative differential testing for the constraint DSL.

This is the load-bearing test for the DSL: it treats the grammar as a language
with two implementations that must agree. A seeded generator emits *arbitrary
valid* constraints (operands, comparisons, functions, quantifiers, and/or/not,
constants — composed freely), and for every generated constraint × many random
argument sets it asserts two properties:

  * compiles-always: the whole generated policy builds under opa (a bad codegen,
    e.g. an invalid Rego rule, fails the build) — this alone would have caught
    the historical `not in` → `not not …` bug;
  * equivalence: the pydantic engine and the compiled WASM engine return the
    identical decision.

It's the composition/interaction space that hand-written fixtures can't cover.
Constraints are generated as *source strings* so the parser is exercised too.
Seeds are fixed, so any failure is deterministic and reproducible (the assert
message prints the exact constraint + args).

Type mismatches (e.g. comparing an int field to a string) are intentionally
allowed: both engines must fail those closed *identically*, which is itself a
valuable parity check.
"""

from __future__ import annotations

import random
import shutil

import pytest

from hexgate.security import WasmPolicy, compile_to_wasm, load_policy_set_from_dict
from hexgate.security.rego import compile_to_rego

pytestmark = pytest.mark.skipif(shutil.which("opa") is None, reason="opa not on PATH")


# --- generation universe ----------------------------------------------------
# Constraint literals and argument values are drawn from overlapping domains so
# comparisons flip (pass/fail) across argument samples.
SCALARS = ("f0", "f1", "f2", "f3")  # scalar fields  → args.f0 …
LISTS = ("g0", "g1")  # list-of-scalar fields (quant / in / count)
OBJLISTS = ("h0", "h1")  # list-of-object fields (quant over .price / .name)
INTS = (0, 1, 2, 3, 5, 10)
STRS = ("a", "b", "USD", "admin")
CONSTS = {"ci": 5, "cs": "USD", "cl": [1, 2, 3]}
CMP_OPS = ("==", "!=", "<", "<=", ">", ">=")
RE2_PATTERNS = ("^a", "b$", "[0-9]+", "^[a-z]+$", "US")


def _lit(rng: random.Random) -> str:
    kind = rng.random()
    if kind < 0.5:
        return str(rng.choice(INTS))
    if kind < 0.8:
        return f'"{rng.choice(STRS)}"'
    if kind < 0.9:
        return rng.choice(("true", "false"))
    return "null"


def _numeric_rhs(rng: random.Random) -> str:
    return rng.choice(
        [str(rng.choice(INTS)), f"args.{rng.choice(SCALARS)}", "consts.ci"]
    )


def _gen_cmp(rng: random.Random) -> str:
    kind = rng.random()
    if kind < 0.4:  # numeric-ish comparison
        left = rng.choice(
            [f"args.{rng.choice(SCALARS)}", f"count(args.{rng.choice(LISTS)})"]
        )
        return f"{left} {rng.choice(CMP_OPS)} {_numeric_rhs(rng)}"
    if kind < 0.6:  # string equality / cross-field
        rhs = rng.choice(
            [f'"{rng.choice(STRS)}"', "consts.cs", f"args.{rng.choice(SCALARS)}"]
        )
        return f"args.{rng.choice(SCALARS)} {rng.choice(('==', '!='))} {rhs}"
    if kind < 0.75:  # role / tool facts
        return f'{rng.choice(("role", "tool"))} == "{rng.choice(STRS)}"'
    # membership
    op = rng.choice(("in", "not in"))
    rhs = rng.choice([f"[{rng.choice(INTS)}, {rng.choice(INTS)}]", "consts.cl"])
    return f"args.{rng.choice(SCALARS)} {op} {rhs}"


def _gen_func(rng: random.Random, target: str = None) -> str:
    tgt = target or f"args.{rng.choice(SCALARS)}"
    fn = rng.choice(("startswith", "endswith", "contains", "matches"))
    val = rng.choice(RE2_PATTERNS) if fn == "matches" else rng.choice(STRS)
    return f'{fn}({tgt}, "{val}")'


def _gen_count(rng: random.Random) -> str:
    rhs = rng.choice([str(rng.choice(INTS)), "consts.ci"])
    return f"count(args.{rng.choice(LISTS)}) {rng.choice(CMP_OPS)} {rhs}"


def _gen_element_primary(rng: random.Random, obj: bool) -> str:
    """A primary over the current quantifier element (`.` / `.field`)."""
    target = f".{rng.choice(('price', 'name'))}" if obj else "."
    kind = rng.random()
    if kind < 0.45:
        return f"{target} {rng.choice(CMP_OPS)} {_lit(rng)}"
    if kind < 0.7:
        return f"{target} {rng.choice(('in', 'not in'))} [{rng.choice(INTS)}, {rng.choice(INTS)}]"
    return _gen_func(rng, target)


def _gen_quant(rng: random.Random) -> str:
    obj = rng.random() < 0.5
    coll = f"args.{rng.choice(OBJLISTS if obj else LISTS)}"
    return f"{rng.choice(('every', 'any'))}({coll}, {_gen_element_primary(rng, obj)})"


def _gen_primary(rng: random.Random) -> str:
    return rng.choice((_gen_cmp, _gen_func, _gen_count, _gen_quant))(rng)


def _gen_expr(rng: random.Random, depth: int) -> str:
    if depth <= 0 or rng.random() < 0.5:
        return _gen_primary(rng)
    choice = rng.random()
    if choice < 0.3:
        return f"not ({_gen_expr(rng, depth - 1)})"
    if choice < 0.5:
        return f"({_gen_expr(rng, depth - 1)})"
    joiner = "and" if choice < 0.75 else "or"
    return f"{_gen_expr(rng, depth - 1)} {joiner} {_gen_expr(rng, depth - 1)}"


def _gen_args(rng: random.Random) -> dict:
    args: dict = {}
    for f in SCALARS:
        r = rng.random()
        if r < 0.15:
            continue  # absent → exercise fail-closed
        if r < 0.55:
            args[f] = rng.choice(INTS)
        elif r < 0.8:
            args[f] = rng.choice(STRS)
        elif r < 0.9:
            args[f] = rng.choice((True, False))
        else:
            args[f] = None
    for g in LISTS:
        if rng.random() < 0.15:
            continue
        args[g] = [rng.choice(INTS + STRS) for _ in range(rng.randint(0, 3))]
    for h in OBJLISTS:
        if rng.random() < 0.15:
            continue
        args[h] = [
            {"price": rng.choice(INTS), "name": rng.choice(STRS)}
            for _ in range(rng.randint(0, 3))
        ]
    return args


def _wasm_outcome(wasm: WasmPolicy, tool: str, args: dict) -> str:
    d = wasm.decide(role="member", tool=tool, args=args)
    if d.allow:
        return "allow"
    if d.requires_approval:
        return "needs_approval"
    return "deny"


@pytest.mark.parametrize("seed", range(8))
def test_generative_parity(seed: int) -> None:
    """pydantic == compiled-WASM for freely-composed constraints + random args."""
    rng = random.Random(seed)
    n_constraints = 40
    arg_samples = 8

    constraints = {f"t{i}": _gen_expr(rng, depth=3) for i in range(n_constraints)}
    policy = {
        "version": 1,
        "roles": {
            "default": {
                "consts": CONSTS,
                "tools": {
                    tool: {"mode": "allow", "constraints": [c]}
                    for tool, c in constraints.items()
                },
            }
        },
    }

    ps = load_policy_set_from_dict(policy)
    # compiles-always: a bad emitted rule fails this build for the whole seed.
    wasm = WasmPolicy.from_bytes(compile_to_wasm(compile_to_rego(policy)).wasm)

    for tool, source in constraints.items():
        for _ in range(arg_samples):
            args = _gen_args(rng)
            py = ps.evaluate(role="member", tool=tool, args=args).outcome.value
            wasm_out = _wasm_outcome(wasm, tool, args)
            assert py == wasm_out, (
                f"seed={seed} divergence\n  constraint: {source!r}\n"
                f"  args: {args}\n  pydantic={py} wasm={wasm_out}"
            )
