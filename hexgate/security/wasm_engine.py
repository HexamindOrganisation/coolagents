"""Evaluate a Hexgate policy bundle's ``policy.wasm`` via wasmtime-py.

This module is the runtime counterpart to :mod:`hexgate.security.rego_wasm`:
that one *compiles* YAML → Rego → WASM, this one *evaluates* WASM →
:class:`RegoVerdict`. The two together give us "same compiler the platform
runs, same evaluator the agent runs" with no implementation drift.

How OPA's WASM ABI works (short version)
----------------------------------------

The module exports a small C-shaped API:

  * ``opa_malloc(size) -> addr``                          — bump-allocate in WASM memory
  * ``opa_eval(0, ep, 0, in_addr, in_len, heap, 0) -> addr`` — fast-path evaluator
  * ``opa_heap_ptr_get() / opa_heap_ptr_set(addr)``       — heap bookmarking (cheap reset)
  * ``entrypoints() -> addr``                             — JSON map name → entrypoint id

It imports a few callbacks we must provide: ``opa_abort`` (fatal error
handler), ``opa_builtin0..4`` (used when policies invoke Rego builtins
like ``time.now`` or ``regex.match``), and ``env.memory`` (the linear
memory we share with the module).

Our policies don't use any builtins — the constraint grammar is closed
under comparisons and ``in`` — so the builtin callbacks raise if ever
called. Surface that as a clear ``WasmEvalError`` rather than a wasmtime
trap so callers see "policy uses an unsupported feature" instead of a
cryptic crash.

Heap discipline across calls
----------------------------

Every ``decide()`` call follows the same arc: reset heap to the base
recorded at init time, write the input JSON via ``opa_malloc``, run
``opa_eval``, read the result string from memory, return. The reset
guarantees the heap doesn't grow unbounded across thousands of decisions,
and it makes each call independent of previous ones (no carry-over state).

Thread safety
-------------

``wasmtime.Store`` is not thread-safe, and the runtime attaches one
shared ``WasmPolicy`` to every guarded tool — so parallel tool calls
(LangGraph can fan them out) would otherwise race on the same store's
memory + heap pointer. ``evaluate`` therefore serializes the whole
write-input → eval → read-result sequence under a per-instance lock.
Decisions are microseconds, so the contention is negligible.
"""

from __future__ import annotations

import json
import threading
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import wasmtime

# OPA bundles encode a major + minor ABI version as exported wasm globals.
# We only know how to drive ABI v1 (the spec covered above); a major bump
# means refusing to load rather than mis-evaluating.
_SUPPORTED_ABI_MAJOR = 1


class WasmEvalError(RuntimeError):
    """Raised when the wasm policy cannot be loaded or its evaluation fails.

    Includes: ABI version mismatch, missing entrypoint, opa_abort being
    invoked by the policy, evaluator returning a non-list result, the
    policy invoking an unsupported builtin.
    """


@dataclass(frozen=True)
class RegoVerdict:
    """Raw verdict from evaluating the compiled Rego/WASM module.

    The low-level ``{allow, requires_approval, violations}`` shape OPA
    emits — mapped into an engine-agnostic
    :class:`~hexgate.security.decision.Verdict` by
    :func:`~hexgate.security.policy.evaluate_tool_call_wasm`.

    Mirrors the ``decision`` rule the Phase 1 compiler emits:

      * ``allow`` — true when an ``allow`` rule body matched.
      * ``requires_approval`` — true when an ``approval_required`` rule fired
        (mutually exclusive with ``allow`` in well-formed policies).
      * ``violations`` — raw constraint strings from the YAML that this
        decision violated. Empty when ``allow`` is true or when no rule
        with constraints matched at all (e.g. pure-deny tools).
    """

    allow: bool
    requires_approval: bool
    violations: list[str]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


DEFAULT_ENTRYPOINT = "hexgate/policy/decision"


class WasmPolicy:
    """A loaded, evaluable Hexgate policy WASM bundle.

    Construct with ``WasmPolicy.from_bytes(wasm)`` or
    ``WasmPolicy.from_bundle_path(dir)``. Each instance owns its own
    wasmtime ``Store`` + ``Instance``; one ``decide()`` call per
    tool-call is the intended usage.
    """

    def __init__(
        self,
        store: wasmtime.Store,
        memory: wasmtime.Memory,
        exports: Any,
        entrypoint_id: int,
        base_heap_ptr: int,
    ) -> None:
        self._store = store
        self._memory = memory
        self._exports = exports
        self._entrypoint_id = entrypoint_id
        self._base_heap_ptr = base_heap_ptr
        # Serializes evaluate() — the shared store isn't thread-safe and the
        # same WasmPolicy is attached to every guarded tool (see module docs).
        self._lock = threading.Lock()

    @classmethod
    def from_bytes(
        cls, wasm: bytes, *, entrypoint: str = DEFAULT_ENTRYPOINT
    ) -> "WasmPolicy":
        """Load a wasm policy from raw module bytes."""
        if not wasm.startswith(b"\x00asm"):
            raise WasmEvalError("input is not a WebAssembly module (bad magic header)")

        engine = wasmtime.Engine()
        store = wasmtime.Store(engine)
        module = wasmtime.Module(engine, wasm)

        memory = wasmtime.Memory(store, wasmtime.MemoryType(wasmtime.Limits(2, None)))
        imports = _build_imports(store, module, memory)
        instance = wasmtime.Instance(store, module, imports)
        exports = instance.exports(store)

        cls._assert_abi_compatible(store, exports)
        entrypoint_id = cls._lookup_entrypoint_id(store, exports, memory, entrypoint)
        base_heap_ptr = exports["opa_heap_ptr_get"](store)

        return cls(
            store=store,
            memory=memory,
            exports=exports,
            entrypoint_id=entrypoint_id,
            base_heap_ptr=base_heap_ptr,
        )

    @classmethod
    def from_bytes_cached(
        cls,
        wasm: bytes,
        wasm_hash: str,
        *,
        entrypoint: str = DEFAULT_ENTRYPOINT,
    ) -> "WasmPolicy":
        """Return a cached :class:`WasmPolicy` for ``wasm_hash``, instantiating
        it (via :meth:`from_bytes`) on the first miss.

        The hot path for policy refresh is "the bundle changed; the wasm
        didn't" — most policy edits leave the wasm bytes alone or the dev
        re-saves an identical policy. A content-addressed cache by
        ``wasm_hash`` makes those refreshes ~free (no wasmtime
        re-instantiation). The per-hash lock prevents N concurrent first-
        loads from racing into N stores for the same hash.
        """
        return _wasm_policy_cache.get_or_load(
            wasm_hash, lambda: cls.from_bytes(wasm, entrypoint=entrypoint)
        )

    @classmethod
    def from_bundle_path(
        cls, path: Path | str, *, entrypoint: str = DEFAULT_ENTRYPOINT
    ) -> "WasmPolicy":
        """Load from a bundle directory containing ``policy.wasm``.

        The bundle layout is the one ``hexgate policy build`` emits:
        ``<dir>/<stem>.wasm`` next to ``<dir>/<stem>.bundle.json``. We
        accept either the directory or the wasm file directly.
        """
        p = Path(path)
        if p.is_dir():
            # The build CLI uses the source stem (e.g. "policy" or "billing").
            # Pick the only .wasm in the directory; ambiguous otherwise.
            wasm_files = sorted(p.glob("*.wasm"))
            if not wasm_files:
                raise WasmEvalError(f"no .wasm file found in {p}")
            if len(wasm_files) > 1:
                raise WasmEvalError(
                    f"multiple .wasm files in {p}: {[f.name for f in wasm_files]} — "
                    "pass an explicit path"
                )
            p = wasm_files[0]
        if not p.is_file():
            raise WasmEvalError(f"no such file: {p}")
        return cls.from_bytes(p.read_bytes(), entrypoint=entrypoint)

    def decide(
        self,
        *,
        role: str,
        tool: str,
        args: dict[str, Any],
        ctx: dict[str, Any] | None = None,
    ) -> RegoVerdict:
        """Evaluate one tool-call decision.

        Composes ``input = {role, tool, args, ctx}``, runs the entrypoint, and
        returns the parsed ``RegoVerdict``. ``ctx`` is the caller's ABAC bag,
        read by compiled ``input.ctx.*`` conditions; it mirrors the pydantic
        engine's ``ctx`` context key. The eval is hermetic — heap is reset
        before the call so repeated decisions don't accumulate state.
        """
        return self.evaluate(
            {"role": role, "tool": tool, "args": args, "ctx": ctx or {}}
        )

    def evaluate(self, input_obj: dict[str, Any]) -> RegoVerdict:
        """Lower-level: evaluate with an arbitrary input dict.

        Mostly useful for tests that want to probe odd shapes. Production
        callers should use :meth:`decide`.

        The whole heap-reset → write-input → eval → read-result sequence
        runs under a lock: the wasmtime store is shared across every
        guarded tool, so concurrent calls would otherwise corrupt each
        other's memory + heap pointer.
        """
        store = self._store
        mem = self._memory
        exports = self._exports

        with self._lock:
            # Reset to the base heap pointer so this call doesn't leak into the next.
            exports["opa_heap_ptr_set"](store, self._base_heap_ptr)

            input_bytes = json.dumps(input_obj).encode("utf-8")
            input_addr = exports["opa_malloc"](store, len(input_bytes))
            mem.write(store, input_bytes, input_addr)
            heap_after_input = exports["opa_heap_ptr_get"](store)

            result_addr = exports["opa_eval"](
                store,
                0,  # reserved
                self._entrypoint_id,  # entrypoint id
                0,  # data addr (no external data)
                input_addr,
                len(input_bytes),
                heap_after_input,
                0,  # format: 0 = JSON output
            )
            raw = _read_c_string(store, mem, result_addr)
        parsed = json.loads(raw)
        return _parse_decision(parsed)

    # ---- helpers ----

    @staticmethod
    def _assert_abi_compatible(store: wasmtime.Store, exports: Any) -> None:
        """Refuse to evaluate if the bundle's ABI is newer than we support."""
        global_ = exports.get("opa_wasm_abi_version")
        if global_ is None:
            return  # very old bundles — let the load proceed (best-effort)
        major = global_.value(store)
        if major != _SUPPORTED_ABI_MAJOR:
            raise WasmEvalError(
                f"bundle wasm ABI v{major} is incompatible with this runtime "
                f"(expected v{_SUPPORTED_ABI_MAJOR}); recompile with a matching "
                "opa version."
            )

    @staticmethod
    def _lookup_entrypoint_id(
        store: wasmtime.Store,
        exports: Any,
        memory: wasmtime.Memory,
        entrypoint: str,
    ) -> int:
        """Resolve the entrypoint *name* (a string like ``foo/bar/decision``)
        to the integer ID OPA assigned to it inside this bundle."""
        ep_value_addr = exports["entrypoints"](store)
        ep_json_addr = exports["opa_json_dump"](store, ep_value_addr)
        ep_map = json.loads(_read_c_string(store, memory, ep_json_addr))
        if entrypoint not in ep_map:
            raise WasmEvalError(
                f'entrypoint "{entrypoint}" not in bundle (available: {sorted(ep_map)})'
            )
        return ep_map[entrypoint]


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------


def _build_imports(
    store: wasmtime.Store, module: wasmtime.Module, memory: wasmtime.Memory
) -> list[Any]:
    """Match the module's import list in declaration order.

    wasmtime requires the imports array to match the module's declared
    imports positionally, so we walk module.imports and emit each one.
    Unknown imports are an error — bundles produced by ``opa build``
    only declare the ones below.
    """
    abort_func = wasmtime.Func(
        store,
        wasmtime.FuncType([wasmtime.ValType.i32()], []),
        _opa_abort_stub,
    )
    builtin_funcs = _make_builtin_stubs(store)

    imports: list[Any] = []
    for imp in module.imports:
        if imp.name == "memory":
            imports.append(memory)
        elif imp.name == "opa_abort":
            imports.append(abort_func)
        elif imp.name.startswith("opa_builtin"):
            idx = int(imp.name[len("opa_builtin") :])
            imports.append(builtin_funcs[idx])
        else:
            raise WasmEvalError(
                f"bundle imports {imp.module}.{imp.name} which the host does "
                "not provide — recompile the policy or extend the host shim."
            )
    return imports


def _make_builtin_stubs(store: wasmtime.Store) -> dict[int, wasmtime.Func]:
    """Stubs for opa_builtin0..opa_builtin4.

    A policy hits one of these when it invokes a Rego builtin (``regex.match``,
    ``time.now_ns``, etc.). Our constraint grammar deliberately does not
    expose builtins, so reaching one here means the policy is doing
    something the runtime can't enforce — fail loudly.
    """
    funcs: dict[int, wasmtime.Func] = {}
    for arity_offset in range(5):
        arity = (
            2 + arity_offset
        )  # builtin0 takes (id, ctx); builtin4 takes (id, ctx, a, b, c, d)

        def _stub(*args: int, _arity: int = arity_offset) -> int:
            builtin_id = args[0] if args else -1
            raise WasmEvalError(
                f"policy invoked unsupported Rego builtin "
                f"(builtin{_arity}, id={builtin_id}); the Hexgate "
                "constraint grammar does not expose builtins."
            )

        funcs[arity_offset] = wasmtime.Func(
            store,
            wasmtime.FuncType(
                [wasmtime.ValType.i32()] * arity,
                [wasmtime.ValType.i32()],
            ),
            _stub,
        )
    return funcs


def _opa_abort_stub(addr: int) -> None:
    """opa_abort is called by the wasm module on a fatal Rego error.

    The address points to a UTF-8 message in wasm memory, but the host
    doesn't have a handle here to read it. Surface the abort as a
    typed error — most callers don't care about the exact message.
    """
    raise WasmEvalError(f"opa_abort invoked (message at addr {addr})")


def _read_c_string(store: wasmtime.Store, memory: wasmtime.Memory, addr: int) -> str:
    """Read a null-terminated UTF-8 string from wasm memory.

    Pulls the memory region as a Python ``bytes`` view, finds the null
    terminator, decodes. Reading byte-by-byte via ``mem.read`` is correct
    but slow for long result strings (decision JSON can be a few KB).
    """
    data = memory.data_ptr(store)
    size = memory.data_len(store)
    if addr >= size:
        raise WasmEvalError(f"string address {addr} out of memory bounds {size}")
    end = addr
    while end < size and data[end] != 0:
        end += 1
    return bytes(data[addr:end]).decode("utf-8")


def _parse_decision(raw: Any) -> RegoVerdict:
    """Pull ``{allow, requires_approval, violations}`` out of opa_eval's output.

    OPA's fast-path eval wraps the result in a list-of-one: ``[{"result": {...}}]``.
    Defensive against the shape because malformed wasm or a mid-flight ABI
    bump would surface here rather than corrupt downstream callers.
    """
    if not isinstance(raw, list) or not raw:
        raise WasmEvalError(f"opa_eval returned a non-list result: {raw!r}")
    first = raw[0]
    if not isinstance(first, dict) or "result" not in first:
        raise WasmEvalError(
            f"opa_eval result lacks the expected 'result' key: {first!r}"
        )
    payload = first["result"]
    if not isinstance(payload, dict):
        raise WasmEvalError(f"opa_eval result.result is not an object: {payload!r}")
    return RegoVerdict(
        allow=bool(payload.get("allow", False)),
        requires_approval=bool(payload.get("requires_approval", False)),
        violations=list(payload.get("violations", []) or []),
    )


# ---------------------------------------------------------------------------
# Content-addressed WasmPolicy cache (used by from_bytes_cached)
# ---------------------------------------------------------------------------


class _WasmPolicyCache:
    """Tiny LRU keyed by ``wasm_hash``.

    Policy refreshes typically receive a bundle whose wasm bytes haven't
    changed (the dev edited an unrelated field, the policy compiled to
    the same module, or it's the same agent we already loaded once). The
    cache makes that case ~free — a dict hit instead of a fresh wasmtime
    instantiation (~50–100ms). Per-key locks prevent N concurrent first-
    loads from racing into N stores for the same hash.

    Memory bound: 16 entries × ~150 KB per ``WasmPolicy`` instance = a
    handful of MB worst-case, plenty for any realistic agent count.
    """

    _MAX_ENTRIES = 16

    def __init__(self) -> None:
        self._policies: "OrderedDict[str, WasmPolicy]" = OrderedDict()
        # One Lock for cache mutation, plus a per-hash Lock that prevents
        # cache stampedes during the first concurrent load of a hash.
        self._mutex = threading.Lock()
        self._inflight: dict[str, threading.Lock] = {}

    def get_or_load(
        self, wasm_hash: str, loader: Callable[[], "WasmPolicy"]
    ) -> "WasmPolicy":
        # Fast path: already cached. Move-to-end to keep LRU semantics.
        with self._mutex:
            cached = self._policies.get(wasm_hash)
            if cached is not None:
                self._policies.move_to_end(wasm_hash)
                return cached
            # Reserve a per-hash lock so concurrent first-loads serialize.
            slot = self._inflight.setdefault(wasm_hash, threading.Lock())

        with slot:
            # Re-check under the slot lock — another caller may have populated
            # the cache while we waited.
            with self._mutex:
                cached = self._policies.get(wasm_hash)
                if cached is not None:
                    self._policies.move_to_end(wasm_hash)
                    return cached

            # Heavy work happens outside the global mutex so other hashes
            # aren't blocked by this hash's wasmtime instantiation.
            policy = loader()

            with self._mutex:
                self._policies[wasm_hash] = policy
                self._policies.move_to_end(wasm_hash)
                while len(self._policies) > self._MAX_ENTRIES:
                    self._policies.popitem(last=False)
                self._inflight.pop(wasm_hash, None)
            return policy

    def clear(self) -> None:
        """Reset the cache. Mostly useful in tests."""
        with self._mutex:
            self._policies.clear()
            self._inflight.clear()


_wasm_policy_cache = _WasmPolicyCache()
