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
            message = getattr(event, "error_message", None) or str(error_code)
            emitted.extend(self.emit_error(message))

        # Text and tools are gated on ``partial`` in opposite directions to
        # dedupe the SSE double-emit: progressive SSE marks every intermediate
        # chunk partial=True (streamed text, and function-call chunks with an
        # empty id) and re-emits the whole thing in a partial=False aggregate.
        # Take text from the partials (streaming) and tools only from the
        # aggregate (complete call, stable id), mirroring ADK's own flow
        # ("skip partial function call events", base_llm_flow).
        if getattr(event, "partial", False):
            content = getattr(event, "content", None)
            for part in getattr(content, "parts", None) or []:
                text = getattr(part, "text", None)
                if not text:
                    continue
                if getattr(part, "thought", False):
                    emitted.extend(
                        self.emit_delta("reasoning", BlockType.REASONING, text)
                    )
                else:
                    emitted.extend(self.emit_delta("text", BlockType.TEXT, text))
            return emitted

        get_calls = getattr(event, "get_function_calls", None)
        for call in (get_calls() if callable(get_calls) else None) or []:
            emitted.extend(
                self.emit_tool_start(
                    getattr(call, "id", None) or getattr(call, "name", None),
                    getattr(call, "name", None) or "tool",
                    dict(getattr(call, "args", None) or {}),
                )
            )

        get_responses = getattr(event, "get_function_responses", None)
        for response in (get_responses() if callable(get_responses) else None) or []:
            emitted.extend(
                self.emit_tool_end(
                    getattr(response, "id", None) or getattr(response, "name", None),
                    getattr(response, "response", None),
                )
            )

        return emitted


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

    async def _ensure_session(
        self, user_id: str, agent_input: Any, explicit: str | None
    ) -> str:
        """Return the ADK session id to run under, creating it if new.

        When the Playground supplies a ``session_id`` (via attenuation) it is
        honored as-is, so the same id lands in ADK and in the audit row and a
        conversation stays correlatable across frameworks. Otherwise a fresh id
        is minted at conversation start (``len(agent_input) <= 1`` — the first
        message, including right after a dashboard reset clears ChatState),
        resetting ADK memory in lockstep with the UI; the previous minted
        session is evicted so a long-lived process doesn't accumulate sessions.
        """
        if explicit is not None:
            session_id = explicit
        else:
            turns = len(agent_input) if isinstance(agent_input, (list, tuple)) else 0
            if self._session_id is None or turns <= 1:
                await self._evict_current_session()
                self._session_id = str(uuid4())
            session_id = self._session_id
        key = (user_id, session_id)
        if key not in self._created:
            await self._session_service.create_session(
                app_name=self._app_name, user_id=user_id, session_id=session_id
            )
            self._created.add(key)
        return session_id

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

        # ADK needs a non-empty user id; normalize identity + guarantee a
        # session id, carrying the caller's role/attributes/ttl through for
        # policy + attenuation. A Playground-supplied session_id is honored so
        # audit rows stay correlatable; otherwise one is minted per conversation.
        user_id = ctx.user_id if ctx and ctx.user_id else "serve"
        explicit_session = ctx.session_id if ctx and ctx.session_id else None
        session_id = await self._ensure_session(user_id, agent_input, explicit_session)
        run_ctx = HexgateContext(
            user_id=user_id,
            user_roles=list(ctx.user_roles) if ctx else [],
            session_id=session_id,
            ttl_seconds=ctx.ttl_seconds if ctx else None,
            attributes=dict(ctx.attributes) if ctx else {},
        )
        new_message = types.Content(role="user", parts=[types.Part(text=query)])

        async def _events() -> AsyncIterator[Any]:
            async for event in self._runner.run_async(
                new_message=new_message,
                hexgate_context=run_ctx,
                run_config=RunConfig(streaming_mode=StreamingMode.SSE),
            ):
                yield event

        async for normalized in normalize_google_events(_events(), query=query):
            yield normalized
