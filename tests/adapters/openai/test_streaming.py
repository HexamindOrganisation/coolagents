"""Unit tests for the OpenAI Agents → hexgate StreamEvent normalizer.

Drives ``normalize_openai_events`` with hand-built fakes shaped like the
``agents`` SDK's stream events (``RawResponsesStreamEvent`` /
``RunItemStreamEvent`` and the ``ToolCallItem`` / ``ToolCallOutputItem`` fields
the normalizer reads via ``getattr``). No live model.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from types import SimpleNamespace
from typing import Any

from hexgate.adapters.openai.streaming import normalize_openai_events
from hexgate.streaming import (
    BlockDeltaEvent,
    BlockType,
    ErrorEvent,
    EventType,
    RunEndEvent,
    RunStartEvent,
    ToolCallState,
    ToolEndEvent,
    ToolStartEvent,
)


def _text_delta(item_id: str, delta: str) -> SimpleNamespace:
    """A raw_response_event carrying an output-text delta."""
    data = SimpleNamespace(
        type="response.output_text.delta", item_id=item_id, delta=delta
    )
    return SimpleNamespace(type="raw_response_event", data=data)


def _reasoning_delta(item_id: str, delta: str) -> SimpleNamespace:
    data = SimpleNamespace(
        type="response.reasoning_text.delta", item_id=item_id, delta=delta
    )
    return SimpleNamespace(type="raw_response_event", data=data)


def _reasoning_summary_delta(item_id: str, delta: str) -> SimpleNamespace:
    """The summarized-reasoning variant the o-series / gpt-5 emit by default."""
    data = SimpleNamespace(
        type="response.reasoning_summary_text.delta", item_id=item_id, delta=delta
    )
    return SimpleNamespace(type="raw_response_event", data=data)


def _tool_called(call_id: str, name: str, arguments_json: str) -> SimpleNamespace:
    """A run_item_stream_event(name=tool_called) with a ToolCallItem-shaped item."""
    raw_item = SimpleNamespace(call_id=call_id, name=name, arguments=arguments_json)
    item = SimpleNamespace(
        type="tool_call_item", raw_item=raw_item, tool_name=name, call_id=call_id
    )
    return SimpleNamespace(type="run_item_stream_event", name="tool_called", item=item)


def _tool_output(call_id: str, output: Any) -> SimpleNamespace:
    item = SimpleNamespace(
        type="tool_call_output_item",
        raw_item={"call_id": call_id},
        call_id=call_id,
        output=output,
    )
    return SimpleNamespace(type="run_item_stream_event", name="tool_output", item=item)


async def _aiter(events: list[Any]) -> AsyncIterator[Any]:
    for event in events:
        yield event


async def _collect(events: list[Any], *, query: str = "hi") -> list[Any]:
    return [
        event async for event in normalize_openai_events(_aiter(events), query=query)
    ]


async def test_full_sequence_text_tool_text() -> None:
    out = await _collect(
        [
            _text_delta("m1", "Hel"),
            _text_delta("m1", "lo"),
            _tool_called("c1", "refund_order", '{"amount": 5}'),
            _tool_output("c1", {"ok": True}),
            _text_delta("m2", " done"),
        ]
    )
    kinds = [e.event_type for e in out]

    # Run brackets the whole stream.
    assert kinds[0] == EventType.RUN_START
    assert kinds[-1] == EventType.RUN_END
    assert isinstance(out[0], RunStartEvent) and out[0].query == "hi"

    # A tool call closes the open text block before the tool events.
    assert kinds == [
        EventType.RUN_START,
        EventType.BLOCK_START,
        EventType.BLOCK_DELTA,
        EventType.BLOCK_DELTA,
        EventType.BLOCK_END,
        EventType.TOOL_START,
        EventType.TOOL_END,
        EventType.BLOCK_START,
        EventType.BLOCK_DELTA,
        EventType.BLOCK_END,
        EventType.RUN_END,
    ]

    # Sequence numbers are strictly monotonic.
    seqs = [e.sequence for e in out]
    assert seqs == sorted(seqs) and len(set(seqs)) == len(seqs)


async def test_tool_start_end_correlate_and_label() -> None:
    out = await _collect(
        [
            _tool_called("call-42", "refund_order", '{"amount": 5, "currency": "USD"}'),
            _tool_output("call-42", {"ok": True}),
        ]
    )
    start = next(e for e in out if isinstance(e, ToolStartEvent))
    end = next(e for e in out if isinstance(e, ToolEndEvent))

    # Same tool_id links start↔end; args parsed from the JSON string to a dict.
    assert start.tool_id == "call-42"
    assert start.tool_name == "refund_order"
    assert start.arguments == {"amount": 5, "currency": "USD"}
    # tool_output carries no name; it is labeled from the recorded call.
    assert end.tool_id == "call-42"
    assert end.tool_name == "refund_order"
    assert end.state == ToolCallState.COMPLETED


async def test_bad_json_args_degrade_to_empty_dict() -> None:
    out = await _collect([_tool_called("c1", "t", "not json")])
    start = next(e for e in out if isinstance(e, ToolStartEvent))
    assert start.arguments == {}


async def test_reasoning_delta_opens_reasoning_block() -> None:
    out = await _collect([_reasoning_delta("r1", "thinking...")])
    delta = next(e for e in out if isinstance(e, BlockDeltaEvent))
    assert delta.block_type == BlockType.REASONING
    assert delta.text == "thinking..."


async def test_run_end_assembles_message_and_steps() -> None:
    out = await _collect(
        [
            _text_delta("m1", "Hello"),
            _text_delta("m1", " world"),
            _tool_called("c1", "search", "{}"),
            _tool_output("c1", "result-text"),
        ]
    )
    run_end = next(e for e in out if isinstance(e, RunEndEvent))
    assert run_end.result.message == "Hello world"
    # One text step + one tool-call step persisted.
    step_kinds = {step.type for step in run_end.result.steps}
    assert "text_step" in step_kinds
    assert "tool_call_step" in step_kinds


async def test_fatal_stream_error_emits_terminal_error_event() -> None:
    async def _boom() -> AsyncIterator[Any]:
        yield _text_delta("m1", "partial")
        raise RuntimeError("kaboom")

    out = [event async for event in normalize_openai_events(_boom(), query="q")]

    # The stream terminates on an ErrorEvent — no RunEnd after a fatal error.
    assert isinstance(out[-1], ErrorEvent)
    assert "kaboom" in out[-1].message
    assert not any(isinstance(e, RunEndEvent) for e in out)
    # The open text block was finalized before the error.
    assert out[-1].event_type == EventType.ERROR


async def test_reasoning_summary_delta_opens_reasoning_block() -> None:
    # Summarized reasoning (the o-series / gpt-5 default) must render too.
    out = await _collect([_reasoning_summary_delta("r1", "let me think")])
    delta = next(e for e in out if isinstance(e, BlockDeltaEvent))
    assert delta.block_type == BlockType.REASONING
    assert delta.text == "let me think"


async def test_structured_failure_output_marks_tool_failed() -> None:
    # A hexgate GuardedTool refusal surfaces as {"ok": false, "error": {...}};
    # it must render as FAILED, not a green completed call.
    out = await _collect(
        [
            _tool_called("c1", "refund_order", "{}"),
            _tool_output("c1", {"ok": False, "error": {"message": "denied by policy"}}),
        ]
    )
    end = next(e for e in out if isinstance(e, ToolEndEvent))
    assert end.state == ToolCallState.FAILED
    assert end.output_summary == "denied by policy"


async def test_empty_stream_is_bracketed_by_run_start_and_end() -> None:
    out = await _collect([])
    assert [e.event_type for e in out] == [EventType.RUN_START, EventType.RUN_END]


async def test_non_serializable_tool_output_still_serializes_run_end() -> None:
    class _Weird:
        pass

    out = await _collect([_tool_called("c1", "t", "{}"), _tool_output("c1", _Weird())])
    run_end = next(e for e in out if isinstance(e, RunEndEvent))
    # Must not raise PydanticSerializationError — serve ships this over the wire.
    dumped = run_end.model_dump_json()
    assert "tool_call_step" in dumped


async def test_callless_tool_start_end_share_tool_id() -> None:
    # Hosted calls can omit call_id; start and end must still correlate.
    out = await _collect(
        [_tool_called(None, "shell", "{}"), _tool_output(None, "ok")]  # type: ignore[arg-type]
    )
    start = next(e for e in out if isinstance(e, ToolStartEvent))
    end = next(e for e in out if isinstance(e, ToolEndEvent))
    assert start.tool_id == end.tool_id
    assert end.tool_name == "shell"


async def test_astream_openai_uses_async_run_streamed() -> None:
    # serve must drive the runner off-loop via arun_streamed (await), never the
    # blocking sync run_streamed, or the serve event loop stalls per turn.
    from hexgate.adapters.openai.streaming import astream_openai
    from hexgate.runtime import HexgateContext

    calls = {"arun": 0, "run": 0}

    class _Result:
        async def stream_events(self) -> AsyncIterator[Any]:
            if False:  # pragma: no cover — empty async generator
                yield None

    class _Runner:
        async def arun_streamed(self, agent: Any, inp: Any, **_k: Any) -> _Result:
            calls["arun"] += 1
            return _Result()

        def run_streamed(self, *_a: Any, **_k: Any) -> _Result:
            calls["run"] += 1  # pragma: no cover — must not be reached
            return _Result()

    out = [
        e
        async for e in astream_openai(
            _Runner(),
            object(),
            [],
            hexgate_context=HexgateContext(user_id=""),
            query="q",
        )
    ]
    assert calls == {"arun": 1, "run": 0}
    # Still produces a bracketed (empty) run.
    assert out[0].event_type == EventType.RUN_START
    assert out[-1].event_type == EventType.RUN_END
