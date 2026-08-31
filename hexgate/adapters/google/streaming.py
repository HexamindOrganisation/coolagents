"""Google ADK → hexgate ``StreamEvent`` normalizer + serve driver.

Maps ADK ``Event``s (``runner.run_async`` output) onto the framework-agnostic
:class:`~hexgate.streaming.StreamEvent` contract. The accumulator bookkeeping
lives in :mod:`hexgate.streaming._accumulator`; this module defines the ADK
``consume`` mapping and the serve driver.

Two ADK specifics shape this:

* **Session-based history.** ADK holds conversation history in a
  ``session_service``; a run takes only the new user message and a
  ``(user_id, session_id)``. :class:`GoogleServeDriver` owns an in-memory
  session and mints a fresh id at the start of a conversation (first turn or
  after a dashboard reset, detected via ``len(agent_input) <= 1``), giving
  multi-turn memory that resets cleanly.
* **SSE double-emit.** Progressive streaming (``StreamingMode.SSE``, default-on
  in ADK) marks every intermediate chunk ``partial=True`` — streamed text *and*
  function-call chunks (whose id is empty mid-stream) — then re-emits the whole
  thing in a ``partial=False`` aggregate. To dedupe, ``consume`` takes text from
  the partials (streaming) and tool calls/responses only from the aggregate
  (complete call, stable id), matching ADK's own "skip partial function call
  events" flow.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import TYPE_CHECKING, Any
from uuid import uuid4

from hexgate.runtime import HexgateContext
from hexgate.streaming import BlockType, StreamEvent
from hexgate.streaming._accumulator import StreamAccumulator, run_normalizer

if TYPE_CHECKING:
    from hexgate.approvals import ApprovalHandler


class _GoogleRunAccumulator(StreamAccumulator):
    """Map ADK ``Event``s onto the shared accumulator."""

    def consume(self, event: Any) -> list[StreamEvent]:
        emitted: list[StreamEvent] = []

        error_code = getattr(event, "error_code", None)
        if error_code:
            # A non-terminal ErrorEvent, mirroring how the LangChain adapter
            # surfaces a mid-run tool error. ADK sets error_code on terminal
            # finish reasons (safety/blocked), so in practice no content follows.
            message = getattr(event, "error_message", None) or str(error_code)
            emitted.extend(self.emit_error(message))

        # Text/reasoning: emit only the not-yet-seen suffix of each part. This
        # dedupes progressive SSE's double-emit (the partial=False aggregate
        # re-sends the whole segment the partials already streamed → suffix is
        # empty), renders aggregate-only text (no partials → the whole thing is
        # the suffix), and keeps a text preamble ahead of a tool call in the
        # same event, all without partial/aggregate branching for text.
        for is_thought, text in self._text_parts(event):
            key = "reasoning" if is_thought else "text"
            block_type = BlockType.REASONING if is_thought else BlockType.TEXT
            seen = self.current_block_text(key)
            delta = text[len(seen) :] if text.startswith(seen) else text
            if delta:
                emitted.extend(self.emit_delta(key, block_type, delta))

        # Tools only from the non-partial aggregate: progressive SSE marks
        # intermediate function-call chunks partial=True (empty id, partial
        # args) and re-emits the complete call in the aggregate, so taking them
        # only here mirrors ADK's own "skip partial function call events" flow.
        if not getattr(event, "partial", False):
            get_calls = getattr(event, "get_function_calls", None)
            for call in (get_calls() if callable(get_calls) else None) or []:
                # id as-is (None when empty) so the shared FIFO correlates
                # id-less calls; never fall back to the name, which would make
                # two calls to the same tool collide on one id.
                emitted.extend(
                    self.emit_tool_start(
                        getattr(call, "id", None),
                        getattr(call, "name", None) or "tool",
                        dict(getattr(call, "args", None) or {}),
                    )
                )
            get_responses = getattr(event, "get_function_responses", None)
            for response in (
                get_responses() if callable(get_responses) else None
            ) or []:
                emitted.extend(
                    self.emit_tool_end(
                        getattr(response, "id", None),
                        getattr(response, "response", None),
                    )
                )

        return emitted

    @staticmethod
    def _text_parts(event: Any) -> list[tuple[bool, str]]:
        """Return ``(is_thought, text)`` for each non-empty text part."""
        content = getattr(event, "content", None)
        parts: list[tuple[bool, str]] = []
        for part in getattr(content, "parts", None) or []:
            text = getattr(part, "text", None)
            if text:
                parts.append((bool(getattr(part, "thought", False)), text))
        return parts


async def normalize_google_events(
    events: AsyncIterator[Any], *, query: str
) -> AsyncIterator[StreamEvent]:
    """Normalize an ADK ``run_async`` event stream into ``StreamEvent``s."""
    async for event in run_normalizer(
        _GoogleRunAccumulator(query), events, error_log="google serve stream failed"
    ):
        yield event


class GoogleServeDriver:
    """Owns the ADK runner + in-memory session for one serve connection.

    Built once by ``build_runtime_from_local_agent``; :meth:`astream` is bound as
    the runtime's framework-agnostic streaming seam.
    """

    def __init__(
        self,
        *,
        agent: Any,
        app_name: str,
        approval_handler: ApprovalHandler | None = None,
        api_key: str | None = None,
    ) -> None:
        from google.adk.sessions import InMemorySessionService

        from hexgate.adapters.google.runner import HexgateRunner

        self._session_service = InMemorySessionService()
        self._app_name = app_name
        self._runner = HexgateRunner(
            agent=agent,
            app_name=app_name,
            session_service=self._session_service,
            approval_handler=approval_handler,
            api_key=api_key,
        )
        self._session_id: str | None = None
        self._created: set[tuple[str, str]] = set()

    async def _ensure_session(self, user_id: str, agent_input: Any) -> str:
        """Return the internal ADK session id, minting a fresh one at
        conversation start.

        This id keys ADK's conversation store only; it is deliberately kept out
        of the caller-facing ``HexgateContext.session_id`` (see :meth:`astream`).
        ``len(agent_input) <= 1`` marks the first message of a conversation
        (including right after a dashboard reset clears ChatState), so a new id
        there resets ADK memory in lockstep with the UI, and the previous
        session is evicted so a long-lived process doesn't accumulate sessions.
        """
        turns = len(agent_input) if isinstance(agent_input, (list, tuple)) else 0
        if self._session_id is None or turns <= 1:
            await self._evict_current_session()
            self._session_id = str(uuid4())
        key = (user_id, self._session_id)
        if key not in self._created:
            await self._session_service.create_session(
                app_name=self._app_name, user_id=user_id, session_id=self._session_id
            )
            self._created.add(key)
        return self._session_id

    async def _evict_current_session(self) -> None:
        """Delete the current conversation's session(s) from the ADK store."""
        if self._session_id is None:
            return
        for user_id, session_id in list(self._created):
            if session_id != self._session_id:
                continue
            try:
                await self._session_service.delete_session(
                    app_name=self._app_name, user_id=user_id, session_id=session_id
                )
            except Exception:  # noqa: BLE001 — best-effort cleanup, never fatal
                pass
            self._created.discard((user_id, session_id))

    async def astream(
        self, agent_input: Any, ctx: HexgateContext | None, query: str
    ) -> AsyncIterator[StreamEvent]:
        from google.adk.agents.run_config import RunConfig, StreamingMode
        from google.genai import types

        # The ADK session (conversation memory) is managed internally and kept
        # separate from the caller-facing context: the caller's own session_id
        # passes through to audit unchanged (correlatable across frameworks),
        # while the minted ADK id is handed to run_async via its own parameter.
        # Role/attributes/ttl carry through for policy + attenuation.
        user_id = ctx.user_id if ctx and ctx.user_id else "serve"
        adk_session_id = await self._ensure_session(user_id, agent_input)
        run_ctx = HexgateContext(
            user_id=user_id,
            user_roles=list(ctx.user_roles) if ctx else [],
            session_id=ctx.session_id if ctx else None,
            ttl_seconds=ctx.ttl_seconds if ctx else None,
            attributes=dict(ctx.attributes) if ctx else {},
        )
        new_message = types.Content(role="user", parts=[types.Part(text=query)])

        async def _events() -> AsyncIterator[Any]:
            async for event in self._runner.run_async(
                new_message=new_message,
                hexgate_context=run_ctx,
                session_id=adk_session_id,
                run_config=RunConfig(streaming_mode=StreamingMode.SSE),
            ):
                yield event

        async for normalized in normalize_google_events(_events(), query=query):
            yield normalized
