"""Unit tests for the Google ADK → hexgate StreamEvent normalizer.

Drives ``normalize_google_events`` with hand-built fakes shaped like ADK
``Event``s (``partial``, ``content.parts[].text/thought``, ``error_code``, and
the ``get_function_calls`` / ``get_function_responses`` helpers). No live model.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from types import SimpleNamespace
from typing import Any

from hexgate.adapters.google.streaming import normalize_google_events
from hexgate.streaming import (
    BlockDeltaEvent,
    BlockType,
    ErrorEvent,
    EventType,
    RunEndEvent,
    ToolCallState,
    ToolEndEvent,
    ToolStartEvent,
)


def _event(
    *,
    parts: list[Any] | None = None,
    partial: bool = False,
    calls: list[Any] | None = None,
    responses: list[Any] | None = None,
    error_code: str | None = None,
    error_message: str | None = None,
) -> SimpleNamespace:
    content = SimpleNamespace(parts=parts) if parts is not None else None
    return SimpleNamespace(
        content=content,
        partial=partial,
        error_code=error_code,
        error_message=error_message,
        get_function_calls=lambda: calls or [],
        get_function_responses=lambda: responses or [],
    )


def _text(text: str, *, partial: bool = True, thought: bool = False) -> SimpleNamespace:
    return _event(parts=[SimpleNamespace(text=text, thought=thought)], partial=partial)


def _call(call_id: str | None, name: str, args: dict) -> SimpleNamespace:
    return _event(calls=[SimpleNamespace(id=call_id, name=name, args=args)])


def _response(call_id: str | None, name: str, response: Any) -> SimpleNamespace:
    return _event(responses=[SimpleNamespace(id=call_id, name=name, response=response)])


async def _aiter(events: list[Any]) -> AsyncIterator[Any]:
    for event in events:
        yield event


async def _collect(events: list[Any], *, query: str = "hi") -> list[Any]:
    return [e async for e in normalize_google_events(_aiter(events), query=query)]


async def test_partial_text_streams_and_aggregate_is_deduped() -> None:
    out = await _collect(
        [
            _text("Hel", partial=True),
            _text("lo", partial=True),
            _text("Hello", partial=False),  # SSE aggregate — must be skipped
        ]
    )
    deltas = [e for e in out if isinstance(e, BlockDeltaEvent)]
    assert [d.text for d in deltas] == ["Hel", "lo"]
    run_end = next(e for e in out if isinstance(e, RunEndEvent))
    assert run_end.result.message == "Hello"


async def test_thought_part_opens_reasoning_block() -> None:
    out = await _collect([_text("planning", partial=True, thought=True)])
    delta = next(e for e in out if isinstance(e, BlockDeltaEvent))
    assert delta.block_type == BlockType.REASONING


async def test_function_call_becomes_tool_start() -> None:
    out = await _collect([_call("c1", "refund_order", {"amount": 5})])
    start = next(e for e in out if isinstance(e, ToolStartEvent))
    assert start.tool_id == "c1"
    assert start.tool_name == "refund_order"
    assert start.arguments == {"amount": 5}


async def test_missing_call_id_correlates_via_fifo() -> None:
    # An id-less call/response pair correlates through the shared FIFO (a
    # synthesized id), not the tool name (which would collide across calls).
    out = await _collect(
        [_call(None, "lookup", {}), _response(None, "lookup", {"ok": True})]
    )
    start = next(e for e in out if isinstance(e, ToolStartEvent))
    end = next(e for e in out if isinstance(e, ToolEndEvent))
    assert start.tool_id == end.tool_id
    assert start.tool_name == "lookup"
    assert end.tool_name == "lookup"


async def test_two_idless_calls_to_same_tool_do_not_collide() -> None:
    # Two id-less calls to the same tool in one aggregate must get distinct
    # tool_ids (FIFO), not collide on the shared name.
    out = await _collect(
        [
            _event(
                calls=[
                    SimpleNamespace(id=None, name="t", args={"n": 1}),
                    SimpleNamespace(id=None, name="t", args={"n": 2}),
                ]
            ),
            _event(
                responses=[
                    SimpleNamespace(id=None, name="t", response="a"),
                    SimpleNamespace(id=None, name="t", response="b"),
                ]
            ),
        ]
    )
    starts = [e for e in out if isinstance(e, ToolStartEvent)]
    ends = [e for e in out if isinstance(e, ToolEndEvent)]
    assert len({s.tool_id for s in starts}) == 2  # distinct, not collided
    # FIFO pairs start[i] with end[i].
    assert [s.tool_id for s in starts] == [e.tool_id for e in ends]


async def test_aggregate_only_text_is_emitted() -> None:
    # A turn whose text arrives only in the non-partial aggregate (no partial
    # chunks) must still render.
    out = await _collect([_text("the whole answer", partial=False)])
    deltas = [e for e in out if isinstance(e, BlockDeltaEvent)]
    assert [d.text for d in deltas] == ["the whole answer"]
    run_end = next(e for e in out if isinstance(e, RunEndEvent))
    assert run_end.result.message == "the whole answer"


async def test_function_response_ok_false_marks_failed() -> None:
    out = await _collect(
        [
            _call("c1", "refund_order", {}),
            _response("c1", "refund_order", {"ok": False, "error": {"message": "no"}}),
        ]
    )
    end = next(e for e in out if isinstance(e, ToolEndEvent))
    assert end.state == ToolCallState.FAILED
    assert end.output_summary == "no"


async def test_function_response_plain_is_completed() -> None:
    out = await _collect([_call("c1", "t", {}), _response("c1", "t", {"status": "ok"})])
    end = next(e for e in out if isinstance(e, ToolEndEvent))
    assert end.state == ToolCallState.COMPLETED


async def test_error_code_event_emits_error() -> None:
    out = await _collect(
        [_event(error_code="SAFETY", error_message="blocked by filter")]
    )
    err = next(e for e in out if isinstance(e, ErrorEvent))
    assert "blocked by filter" in err.message
    # Non-terminal: the run still closes cleanly.
    assert isinstance(out[-1], RunEndEvent)


async def test_session_evicted_on_new_conversation(
    monkeypatch: Any,
) -> None:
    """A new conversation mints a fresh ADK session and evicts the previous one,
    so a long-lived serve process doesn't leak sessions across resets."""
    from hexgate.adapters.google.streaming import GoogleServeDriver

    class _StubRunner:
        def __init__(self, **_kw: Any) -> None:
            pass

    monkeypatch.setattr("hexgate.adapters.google.runner.HexgateRunner", _StubRunner)

    driver = GoogleServeDriver(agent=object(), app_name="app")

    first = await driver._ensure_session("u", ["only-one"])  # turns<=1 → new
    same = await driver._ensure_session("u", ["a", "b", "c"])  # continue
    assert same == first
    assert ("u", first) in driver._created

    fresh = await driver._ensure_session("u", ["reset"])  # turns<=1 → new + evict
    assert fresh != first
    assert ("u", first) not in driver._created  # old one evicted
    assert ("u", fresh) in driver._created


async def test_partial_function_call_is_deduped() -> None:
    # Progressive SSE emits a function call in partial chunks AND the aggregate;
    # only the non-partial aggregate should produce a tool start.
    out = await _collect(
        [
            _event(calls=[SimpleNamespace(id="c1", name="t", args={})], partial=True),
            _event(calls=[SimpleNamespace(id="c1", name="t", args={})], partial=False),
        ]
    )
    starts = [e for e in out if isinstance(e, ToolStartEvent)]
    assert len(starts) == 1


async def test_astream_decouples_audit_session_from_adk_session(
    monkeypatch: Any,
) -> None:
    # The caller's session_id + ttl pass through to the audit context unchanged,
    # while the ADK session id is minted internally and handed to run_async via
    # its own parameter (so audit stays correlatable and ADK memory is managed
    # separately).
    from hexgate.adapters.google.streaming import GoogleServeDriver
    from hexgate.runtime import HexgateContext

    captured: dict[str, Any] = {}

    class _StubRunner:
        def __init__(self, **_kw: Any) -> None:
            pass

        async def run_async(
            self,
            *,
            new_message: Any,
            hexgate_context: Any,
            session_id: Any = None,
            **_k: Any,
        ) -> AsyncIterator[Any]:
            captured["ctx"] = hexgate_context
            captured["adk_session_id"] = session_id
            if False:  # pragma: no cover — empty async generator
                yield None

    monkeypatch.setattr("hexgate.adapters.google.runner.HexgateRunner", _StubRunner)
    driver = GoogleServeDriver(agent=object(), app_name="app")

    ctx = HexgateContext(
        user_id="alice", user_roles=["billing"], session_id="sess-9", ttl_seconds=42
    )
    _ = [e async for e in driver.astream(["hi"], ctx, "hi")]

    run_ctx = captured["ctx"]
    assert run_ctx.user_id == "alice"
    assert run_ctx.user_roles == ["billing"]
    assert run_ctx.session_id == "sess-9"  # caller's id → audit, unchanged
    assert run_ctx.ttl_seconds == 42  # carried through, not dropped
    # ADK gets a minted id, distinct from the caller-facing session id.
    assert captured["adk_session_id"] and captured["adk_session_id"] != "sess-9"


async def test_full_sequence_brackets_run() -> None:
    out = await _collect(
        [
            _text("Look", partial=True),
            _call("c1", "get_order_status", {"order_id": "42"}),
            _response("c1", "get_order_status", "shipped"),
            _text(" done", partial=True),
        ]
    )
    kinds = [e.event_type for e in out]
    assert kinds[0] == EventType.RUN_START
    assert kinds[-1] == EventType.RUN_END
    assert EventType.TOOL_START in kinds
    assert EventType.TOOL_END in kinds
