"""Framework-agnostic MCP toolset: enumerate tools, forward calls, own the
transport lifecycle.

The proxy layer produces :class:`MCPToolProxy` descriptors — one per MCP
tool exposed by the connected servers. Each descriptor carries the
LLM-facing metadata (name / description / JSON Schema) and an async
``call(**kwargs) -> dict`` that forwards to the live MCP session and
returns the ``{"ok": True | False, ...}`` envelope shape native
``@agent_tool`` functions use.

To hand these tools to an agent framework, wrap the toolset via the
adapter of your choice:

    from hexgate.adapters.langchain.mcp import wrap_mcp_toolset
    async with MCPToolset(slack_cfg) as mcp:
        tools = wrap_mcp_toolset(mcp)  # list[langchain BaseTool]

For back-compat, :meth:`MCPToolset.tools` still returns LangChain tools
directly — pre-adapter-split callers keep working.
"""

from __future__ import annotations

import contextlib
import json
import logging
from collections.abc import Awaitable, Callable, Iterable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

import httpx
import jsonschema
from mcp.types import CallToolResult, Tool

from hexgate.mcp.client import MCPClient, MCPConnectionError
from hexgate.mcp.config import MCPServerConfig

if TYPE_CHECKING:
    from langchain_core.tools import BaseTool

logger = logging.getLogger("hexgate.mcp.proxy")


class _ToolsetState:
    """Shared mutable state every proxy closure reads.

    Holds the live client + an ``open`` flag. ``MCPToolset._close`` flips
    ``open=False`` before tearing the client down so a post-close call
    surfaces a clear "toolset is closed" envelope rather than the cryptic
    "use ``async with MCPClient(config)``" error the underlying client
    would produce (the user never instantiated an ``MCPClient`` — they
    used ``MCPToolset``).
    """

    __slots__ = ("client", "open")

    def __init__(self, client: MCPClient) -> None:
        self.client = client
        self.open = True


@dataclass(frozen=True, slots=True)
class MCPToolProxy:
    """Framework-agnostic descriptor for one MCP tool.

    Adapters (LangChain, OpenAI Agents, Pydantic AI, Google ADK) read
    only the four fields below; nothing about the underlying
    :class:`MCPClient` or :class:`_ToolsetState` leaks out. Wrap into a
    framework-native tool via that adapter's ``wrap_mcp_toolset(...)``.

    ``call`` is the async closure produced by :func:`_build_proxy`. It
    handles pre-call JSON-Schema validation, exception mapping, and
    envelope shaping — everything the framework would otherwise have to
    reimplement.
    """

    qualified_name: str
    description: str
    input_schema: dict[str, Any]
    call: Callable[..., Awaitable[dict[str, Any]]]


class MCPToolset:
    """Holds open connections to one or more MCP servers + exposes tools.

    Async context manager — entering opens every server (the catalog
    fetch is sequential today; one slow server gates the rest, which is
    fine at our typical N=1-3 servers). Exiting closes everything
    symmetrically via a single :class:`contextlib.AsyncExitStack`, so a
    ``CancelledError`` between two opens can't leak a half-spawned
    subprocess and a partial open failure tears down what already
    succeeded.

    Usage::

        async with MCPToolset(slack_cfg, github_cfg) as mcp:
            # LangChain path (back-compat shortcut):
            agent, handler = create_agent(model="gpt-5.4", tools=mcp.tools)

            # OR any other adapter, via its wrap_mcp_toolset:
            from hexgate.adapters.openai.mcp import wrap_mcp_toolset
            openai_tools = wrap_mcp_toolset(mcp)
    """

    def __init__(self, *configs: MCPServerConfig) -> None:
        if not configs:
            raise ValueError("MCPToolset() requires at least one MCPServerConfig")
        names = [c.name for c in configs]
        duplicates = sorted({n for n in names if names.count(n) > 1})
        if duplicates:
            # OpenAI's function-calling API rejects duplicate function
            # names (BadRequestError) — catch it at construction with a
            # clear message rather than waiting for the LLM call to fail.
            raise ValueError(
                f"MCPToolset(): duplicate server name(s) {duplicates!r} — each "
                "server's tools are namespaced under its name, so two configs "
                "with the same name would produce duplicate qualified tool "
                "names. Rename one of them."
            )
        self._configs = configs
        self._stack: contextlib.AsyncExitStack | None = None
        self._proxies: list[MCPToolProxy] = []
        self._states: list[_ToolsetState] = []

    async def __aenter__(self) -> "MCPToolset":
        # AsyncExitStack registers cleanup ATOMICALLY with __aenter__ — the
        # subprocess/HTTP transport can't be acquired-but-untracked even
        # under CancelledError between the lines.
        self._stack = contextlib.AsyncExitStack()
        try:
            for config in self._configs:
                client = await self._stack.enter_async_context(MCPClient(config))
                catalog = await client.list_tools()
                logger.info(
                    "mcp: %s registered %d tool(s): %s",
                    config.name,
                    len(catalog),
                    ", ".join(t.name for t in catalog) or "(none)",
                )
                state = _ToolsetState(client)
                self._states.append(state)
                # Mark the state closed when the stack tears down — pushing
                # a callback onto the same stack so the open flag flips
                # before the client's __aexit__ runs.
                self._stack.push_async_callback(_mark_closed, state)
                for mcp_tool in catalog:
                    self._proxies.append(_build_proxy(state, config, mcp_tool))
        except BaseException:
            # aclose() suppresses inner errors; if cancellation hit us we
            # still re-raise the original. Drop the stack reference so
            # __aexit__ is a no-op.
            stack = self._stack
            self._stack = None
            with contextlib.suppress(BaseException):
                if stack is not None:
                    await stack.aclose()
            raise
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: Any,
    ) -> bool | None:
        stack = self._stack
        self._stack = None
        # Clear BOTH _proxies and _states so a re-entered toolset doesn't
        # accumulate phantom state objects from earlier sessions. (The
        # AsyncExitStack itself is single-use, so re-enter mostly means
        # "tests that reuse the instance"; the clears keep that path
        # honest rather than relying on no-one ever doing it.)
        self._proxies.clear()
        self._states.clear()
        if stack is None:
            return None
        # Forward exc_info so the inner transports take the right
        # cancellation path (stdio's graceful-vs-kill decision), AND
        # return whatever the stack returns so an inner CM's suppression
        # decision is preserved.
        return await stack.__aexit__(exc_type, exc, tb)

    @property
    def proxies(self) -> list[MCPToolProxy]:
        """The combined tool catalog across every attached server, as
        framework-agnostic descriptors. Feed to any adapter's
        ``wrap_mcp_toolset(mcp)`` to get framework-native tools."""
        return list(self._proxies)

    @property
    def tools(self) -> "list[BaseTool]":
        """LangChain BaseTools, one per proxy. Back-compat shortcut for
        code written before per-adapter wrappers existed — equivalent to
        ``wrap_mcp_toolset(self)`` from
        :mod:`hexgate.adapters.langchain.mcp`."""
        from hexgate.adapters.langchain.mcp import wrap_mcp_toolset

        return wrap_mcp_toolset(self)


async def _mark_closed(state: _ToolsetState) -> None:
    state.open = False


def _build_proxy(
    state: _ToolsetState, config: MCPServerConfig, mcp_tool: Tool
) -> MCPToolProxy:
    """One :class:`MCPToolProxy` that forwards calls to ``state.client``.

    Closure captures the shared state + the tool's server-local name;
    LLM-visible name is the qualified ``mcp-<server>-<tool>`` form so it
    can't collide with native tools or tools from a second MCP server.
    """
    qualified = config.qualified_tool_name(mcp_tool.name)
    inner_name = mcp_tool.name
    # MCP gives us JSON Schema; adapters (LangChain / OpenAI Agents /
    # etc.) each decide how to feed it into their tool constructor. We
    # validate args ourselves against this schema BEFORE forwarding so a
    # missing-required-arg call returns a structured error envelope
    # instead of a wasted server round-trip.
    #
    # `is None` (not `or`) — an empty dict `{}` is a VALID JSON Schema
    # meaning "accept anything". Falsy-or would replace it with the
    # type=object fallback below, narrowing what the server actually
    # advertised and changing the LLM-visible spec.
    schema = (
        mcp_tool.inputSchema
        if mcp_tool.inputSchema is not None
        else {"type": "object", "properties": {}}
    )
    description = mcp_tool.description or f"{qualified} (no description provided)"
    validator = _validator_for(schema, qualified)

    async def call(**kwargs: Any) -> dict[str, Any]:
        if not state.open:
            return _error_envelope(
                "use_after_close",
                f"MCPToolset for {qualified!r} is closed — the `async with "
                "MCPToolset(...)` block has already exited. Build a fresh "
                "toolset and a fresh agent.",
                qualified,
            )
        if validator is not None:
            try:
                validator.validate(kwargs)
            except jsonschema.ValidationError as exc:
                # Catches missing required args + bad types BEFORE the
                # server round-trip — closes the "LLM omits a field, the
                # remote rejects, agent loop wastes a turn" pattern.
                return _error_envelope(
                    "schema_validation_error",
                    f"arguments do not match the tool's inputSchema: {exc.message}",
                    qualified,
                )
        try:
            result = await state.client.call_tool(inner_name, kwargs)
        except MCPConnectionError as exc:
            return _error_envelope("not_connected", str(exc), qualified)
        except httpx.HTTPError as exc:
            # Transport-level network failure (HTTP transport). Surface as
            # a structured error so the agent can decide to retry rather
            # than the run aborting.
            return _error_envelope("transport_error", str(exc), qualified)
        except Exception as exc:
            # Catches the SDK's RuntimeError on output-schema validation
            # failures + any other surprise the transport may raise. The
            # agent's loop then sees a tool message instead of an exception
            # killing the run — same contract @agent_tool functions get
            # via ``failure_mode="result"``.
            return _error_envelope(
                exc.__class__.__name__.lower(), str(exc) or repr(exc), qualified
            )
        return _result_to_envelope(qualified, result)

    call.__name__ = qualified
    return MCPToolProxy(
        qualified_name=qualified,
        description=description,
        input_schema=schema,
        call=call,
    )


def _validator_for(
    schema: dict, qualified: str
) -> jsonschema.protocols.Validator | None:
    """Build a JSON Schema validator for an MCP tool's inputSchema.

    Returns ``None`` if the schema is unusable (e.g. not an object schema,
    no fields to validate) — that's the same loose contract adapters
    accept and we don't want to be stricter than the LLM-facing spec.
    """
    try:
        validator_cls = jsonschema.validators.validator_for(schema)
        validator_cls.check_schema(schema)
    except jsonschema.SchemaError as exc:
        # The server advertised a malformed schema — log loud so the
        # operator can ask the server vendor, but don't refuse to run.
        logger.warning(
            "mcp: %s has an invalid inputSchema, skipping pre-call validation: %s",
            qualified,
            exc,
        )
        return None
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "mcp: %s — couldn't build a schema validator (%s); pre-call "
            "validation disabled.",
            qualified,
            exc,
        )
        return None
    return validator_cls(schema)


def _result_to_envelope(qualified: str, result: CallToolResult) -> dict[str, Any]:
    """Match the @agent_tool ``{"ok": True, "content": ...}`` shape.

    The native :func:`hexgate.tools.decorators.agent_tool` decorator
    wraps every return in this envelope (see ``decorators.py``); MCP
    proxies do the same so callers can discriminate ``ok`` uniformly
    instead of branching on tool origin.

    Content sources, in priority order:
      1. ``structuredContent`` — MCP's first-class typed return path.
         Rendered as JSON text so the LLM sees the structure even
         without a content block.
      2. Text content blocks — joined with newlines.
      3. ``(no textual content)`` — last resort so the LLM message
         isn't empty.

    ``isError=true`` flips the envelope to ``{"ok": False, "error": …}``
    with the same content so the agent doesn't treat a failed call as
    success.
    """
    parts: list[str] = []
    if result.structuredContent is not None:
        parts.append(_render_structured(result.structuredContent))
    parts.extend(_iter_text_blocks(result.content))
    body = "\n".join(p for p in parts if p) or "(no textual content)"
    if result.isError:
        return _error_envelope("tool_error", body, qualified)
    return {"ok": True, "content": body}


def _iter_text_blocks(content: Iterable[Any]) -> Iterable[str]:
    """Pull every readable text payload out of a CallToolResult.content list.

    Covers TextContent (``.text``) and EmbeddedResource where the embedded
    resource carries text (``.resource.text``). Image / binary resource
    content is skipped for v1 — richer return types land in a follow-up.
    """
    for block in content:
        text = getattr(block, "text", None)
        if isinstance(text, str):
            yield text
            continue
        resource = getattr(block, "resource", None)
        if resource is not None:
            inner = getattr(resource, "text", None)
            if isinstance(inner, str):
                yield inner


def _render_structured(payload: Any) -> str:
    """Render a structuredContent payload as JSON text for the LLM."""
    try:
        return json.dumps(payload, ensure_ascii=False, sort_keys=True)
    except (TypeError, ValueError):
        return repr(payload)


def _error_envelope(kind: str, message: str, qualified: str) -> dict[str, Any]:
    """Match the {"ok": False, "error": {...}} shape native tools produce.

    Only ``transport_error`` is retryable. MCP's ``isError=true`` covers
    deterministic application failures (permissions denied, not found,
    bad input that passed schema validation) — those reproduce on
    retry and shouldn't carry a retryable=True hint that might mislead a
    future consumer into busy-looping. Aligns with native
    :meth:`Decision.as_error_payload`, which always emits
    ``retryable: False``.
    """
    return {
        "ok": False,
        "error": {
            "type": kind,
            "message": message,
            "tool_name": qualified,
            "retryable": kind == "transport_error",
        },
    }
