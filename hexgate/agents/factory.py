"""Create thin LangChain agent helpers for hexgate."""

from __future__ import annotations

import asyncio
import logging
import os
from collections.abc import AsyncIterator, Callable, Mapping, Sequence
from pathlib import Path
from typing import TYPE_CHECKING, Any, Self, TypeAlias

if TYPE_CHECKING:
    # Seam-attribute types referenced only in annotations. Imported under
    # TYPE_CHECKING to avoid the runtime cycle (security.* and cloud.* both
    # eventually import from this module).
    from hexgate.cloud.client import HexgateClient
    from hexgate.guards.types import Guard, GuardObserver
    from hexgate.security.agent_gate import AgentGate
    from hexgate.security.bans import BanGate
    from hexgate.security.binding import PolicyBinding
    from hexgate.security.enforcer import DecisionObserver, PolicyEnforcer
    from hexgate.security.source import PolicySource

from langchain.agents import create_agent as create_langchain_agent
from langchain.agents.middleware.types import AgentMiddleware
from langchain.agents.structured_output import ResponseFormat
from langchain_core.caches import BaseCache
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import BaseMessage
from langchain_core.messages.system import SystemMessage
from langchain_core.runnables.schema import StreamEvent as LangChainStreamEvent
from langchain_core.tools import BaseTool
from langgraph.checkpoint.base import BaseCheckpointSaver
from langgraph.graph.state import CompiledStateGraph
from langgraph.store.base import BaseStore
from pydantic import BaseModel

# BC re-export — canonical home is hexgate.approvals (framework-agnostic).
from hexgate.approvals import ApprovalHandler  # noqa: F401 — re-export
from hexgate.config.env import resolve_api_key
from hexgate.runtime import (
    LocalWorkspace,
    ToolUseContext,
    Workspace,
    reset_current_tool_use_context,
    set_current_tool_use_context,
)
from hexgate.streaming import StreamEvent, new_root_run_id, normalize_langchain_events
from hexgate.tracing.langfuse import (
    CallbackHandler,
    get_langfuse_handler,
    get_langfuse_runnable_config,
    observe,
)

LangChainAgentGraph: TypeAlias = CompiledStateGraph
ToolSpec: TypeAlias = BaseTool | Callable[..., Any] | dict[str, Any]
AgentState: TypeAlias = dict[str, Any]
AgentInput: TypeAlias = str | Sequence[object] | Mapping[str, object] | BaseModel
DEFAULT_SYSTEM_PROMPT = (
    "You are a helpful assistant built on a tool-using agent runtime.\n\n"
    "Your job is to answer clearly and directly, using the tools available to "
    "you only when they materially improve accuracy.\n\n"
    "Guidelines:\n"
    "- Use tools when a task needs information or an action you can't do from "
    "context alone.\n"
    "- Prefer the fewest tool calls needed.\n"
    "- Keep answers concise and well supported.\n"
    "- Do not mention internal traces or runtime mechanics.\n"
)


def _build_langchain_agent(
    model: str | BaseChatModel,
    tools: Sequence[ToolSpec],
    system_prompt: str | SystemMessage | None,
    *,
    middleware: Sequence[AgentMiddleware[Any, Any]] = (),
    response_format: ResponseFormat[Any] | type[Any] | dict[str, Any] | None = None,
    state_schema: type[Any] | None = None,
    context_schema: type[Any] | None = None,
    checkpointer: BaseCheckpointSaver | None = None,
    store: BaseStore | None = None,
    interrupt_before: list[str] | None = None,
    interrupt_after: list[str] | None = None,
    debug: bool = False,
    name: str | None = None,
    cache: BaseCache[Any] | None = None,
) -> LangChainAgentGraph:
    """Build the underlying LangChain compiled graph."""
    return create_langchain_agent(
        model=model,
        tools=tools,
        system_prompt=system_prompt,
        middleware=middleware,
        response_format=response_format,
        state_schema=state_schema,
        context_schema=context_schema,
        checkpointer=checkpointer,
        store=store,
        interrupt_before=interrupt_before,
        interrupt_after=interrupt_after,
        debug=debug,
        name=name,
        cache=cache,
    )


def _resolve_prompt_path(prompt_path: str | Path) -> Path:
    """Resolve a prompt path relative to the package root when needed."""
    path = Path(prompt_path)
    if path.is_absolute():
        return path
    if path.exists():
        return path
    return Path(__file__).parent.parent / path


def load_system_prompt(system_prompt: str | Path | None) -> str | None:
    """Load prompt contents when the input refers to a prompt file."""
    if system_prompt is None:
        return None
    if isinstance(system_prompt, Path):
        return _resolve_prompt_path(system_prompt).read_text(encoding="utf-8")
    if system_prompt.endswith((".txt", ".jinja", ".md")):
        return _resolve_prompt_path(system_prompt).read_text(encoding="utf-8")
    return system_prompt


def _coerce_message_text(content: object) -> str | None:
    """Return readable text content from a message-like payload."""
    if isinstance(content, str):
        return content
    if not isinstance(content, list):
        return None

    parts: list[str] = []
    for item in content:
        if isinstance(item, str):
            parts.append(item)
            continue
        if not isinstance(item, dict):
            continue
        text = item.get("text")
        if isinstance(text, str):
            parts.append(text)
    return "".join(parts) or None


def _extract_query_from_messages(messages: Sequence[object]) -> str:
    """Return the last user message text from a message list when possible."""
    for message in reversed(messages):
        if isinstance(message, BaseMessage):
            if getattr(message, "type", None) != "human":
                continue
            text = _coerce_message_text(message.content)
            if text:
                return text
            continue
        if isinstance(message, Mapping):
            role = message.get("role")
            if role not in {"user", "human"}:
                continue
            text = _coerce_message_text(message.get("content"))
            if text:
                return text
            continue
        if (
            isinstance(message, tuple)
            and len(message) >= 2
            and message[0] in {"user", "human"}
        ):
            text = _coerce_message_text(message[1])
            if text:
                return text
    return ""


def normalize_input(input: AgentInput) -> AgentState:
    """Normalize wrapper-friendly input into LangChain agent state."""
    if isinstance(input, str):
        return {"messages": [{"role": "user", "content": input}]}
    if isinstance(input, BaseModel):
        return dict(input.model_dump(exclude_none=True))
    if isinstance(input, Mapping):
        return dict(input)
    return {"messages": list(input)}


def extract_input_text(input: AgentInput) -> str:
    """Extract readable user text from wrapper-friendly input."""
    if isinstance(input, str):
        return input
    if isinstance(input, BaseModel):
        return extract_input_text(input.model_dump(exclude_none=True))
    if isinstance(input, Mapping):
        query = input.get("query")
        if isinstance(query, str):
            return query
        messages = input.get("messages")
        if isinstance(messages, Sequence) and not isinstance(messages, str):
            return _extract_query_from_messages(messages)
        return ""
    return _extract_query_from_messages(input)


# One-shot dedupe for the "local agent with active context scope" warning
# inside `_resolve_user_facts`. The dashboard playground hits this once
# per turn (and the platform-served sessions never hit it at all), so
# without a flag the warning floods the log on every chat message.
_warned_local_agent_user_scope: bool = False


def _resolve_user_facts(agent: HexgateAgent) -> dict[str, list[str | int]] | None:
    """Lazily attenuate when a :class:`HexgateContext` scope is active.

    Returns the extracted facts dict for the active context, or ``None`` if
    no context scope is in play, the agent isn't cloud-bound, or attenuation
    fails (logged as a warning — the agent runs without facts and any
    predicate requiring them will fail-closed).
    """
    from hexgate.runtime.context import get_current_context

    context = get_current_context()
    if context is None:
        return None
    client = agent.hexgate_client
    if client is None:
        # Local agent or test stub — a context scope is set but there's nothing
        # to attenuate against. Surface a *single* warning so devs see why their
        # `requires_user` predicate isn't firing on a local-loaded agent, then
        # stay quiet: every subsequent turn would re-fire the same message
        # otherwise (3-5x per chat session in the dashboard playground was
        # the symptom).
        global _warned_local_agent_user_scope
        if not _warned_local_agent_user_scope:
            import logging

            logging.getLogger(__name__).warning(
                "HexgateContext scope active but agent has no hexgate_client; "
                "biscuit_facts will be empty (use load_hexgate_agent for "
                "attenuation). Subsequent occurrences in this process are "
                "suppressed."
            )
            _warned_local_agent_user_scope = True
        return None
    from hexgate.cloud.attenuate import attenuate_for_user
    from hexgate.cloud.biscuit import (
        TokenError,
        TokenSignatureError,
        extract_facts,
        parse_envelope,
    )

    try:
        pub = client.public_key_bytes()
        child_envelope = attenuate_for_user(
            client.config.api_key,
            pub,
            user=context.user_id,
            # Only the first role is attested; the enforcer evaluates them all.
            # See attenuate_for_user's docstring for why closing that is its own
            # change.
            role=context.user_roles[0] if context.user_roles else None,
            ttl_seconds=context.ttl_seconds,
        )
        _, _, biscuit_b64 = parse_envelope(child_envelope)
        return extract_facts(biscuit_b64, pub)
    except (TokenError, TokenSignatureError) as exc:
        import logging

        logging.getLogger(__name__).warning(
            "user-scope attenuation failed: %s; agent runs without facts", exc
        )
        return None


def _resolve_tool_use_context(
    agent: HexgateAgent,
    tool_use_context: ToolUseContext | None,
) -> ToolUseContext:
    """Return the runtime tool context for a run.

    Resolution order for the workspace:
    1. ``tool_use_context.workspace`` — caller-supplied at invocation time.
    2. ``agent.workspace`` — wired in at ``create_agent(...)``-time.
    3. ``LocalWorkspace(Path.cwd())`` — last-resort default.

    When ``tool_use_context`` is None and a
    :class:`~hexgate.runtime.HexgateContext` scope is active, this also runs
    lazy biscuit attenuation against the agent's bound ``hexgate_client`` and
    folds the resulting facts into the fresh context. An explicit
    ``tool_use_context`` argument always wins — that's how callers pass their
    own facts in (e.g. tests, or production code that wants to bypass the
    context scope for a specific call).
    """
    agent_name = getattr(agent, "name", None)
    agent_workspace = getattr(agent, "workspace", None)
    fallback_workspace = agent_workspace or LocalWorkspace(Path.cwd())
    if tool_use_context is not None:
        if tool_use_context.agent_name is None:
            tool_use_context.agent_name = agent_name
        if tool_use_context.workspace is None:
            tool_use_context.workspace = fallback_workspace
        return tool_use_context
    return ToolUseContext(
        workspace=fallback_workspace,
        agent_name=agent_name,
        biscuit_facts=_resolve_user_facts(agent),
    )


class HexgateAgent:
    """A small wrapper around a LangChain agent graph with room for layering."""

    def __init__(
        self,
        *,
        graph: LangChainAgentGraph,
        model: str | BaseChatModel,
        tools: Sequence[ToolSpec],
        system_prompt: str | SystemMessage | None,
        middleware: Sequence[AgentMiddleware[Any, Any]] = (),
        response_format: ResponseFormat[Any] | type[Any] | dict[str, Any] | None = None,
        state_schema: type[Any] | None = None,
        context_schema: type[Any] | None = None,
        checkpointer: BaseCheckpointSaver | None = None,
        store: BaseStore | None = None,
        interrupt_before: list[str] | None = None,
        interrupt_after: list[str] | None = None,
        debug: bool = False,
        name: str | None = None,
        cache: BaseCache[Any] | None = None,
        workspace: Workspace | None = None,
        binding: PolicyBinding | None = None,
        hexgate_client: HexgateClient | None = None,
        ban_gate: BanGate | None = None,
        agent_gate: AgentGate | None = None,
    ) -> None:
        # Private: run only via ainvoke/astream_events, which apply policy
        # refresh + the ban gate. Reaching self._graph directly skips both.
        self._graph = graph
        # Local import: hexgate.adapters.langchain's package __init__ pulls in
        # tools.py -> agents.approvals -> agents.factory (this module) at
        # import time, so a module-level import here would be circular —
        # same cycle enforce_policy()'s GuardedTool import already dodges.
        from hexgate.adapters.langchain.usage import HexgateUsageCallbackHandler

        self.model = model
        self.tools = list(tools)
        self.system_prompt = system_prompt
        self.middleware = tuple(middleware)
        self.response_format = response_format
        self.state_schema = state_schema
        self.context_schema = context_schema
        self.checkpointer = checkpointer
        self.store = store
        self.interrupt_before = interrupt_before
        self.interrupt_after = interrupt_after
        self.debug = debug
        self.name = name
        self.cache = cache
        self.workspace = workspace
        # Enforcement seam: the binding (enforcer + optional refresh source)
        # that enforce_policy attaches and refresh_policy swaps in place;
        # threaded through with_tools rebuilds. hexgate_client is separate —
        # load_hexgate_agent attaches it for lazy cloud-side attenuation.
        self._binding: PolicyBinding | None = binding
        self.hexgate_client: HexgateClient | None = hexgate_client
        # Kill-switch gate; attached by load_hexgate_agent (platform path only —
        # no gate without a control plane). Threaded through with_tools rebuilds.
        self._ban_gate: BanGate | None = ban_gate
        # Admission gate; attached by enforce_policy alongside the binding (local,
        # no control plane needed). Threaded through with_tools rebuilds. Whether it
        # actually refuses is decided per run from the current policy.
        self._agent_gate: AgentGate | None = agent_gate
        # api_key intentionally omitted — create_agent has no explicit api_key param
        # (only hexgate_client, attached post-init by _bind_policy). If one is added,
        # thread it through here too, or usage events will keep silently resolving
        # from HEXGATE_API_KEY instead of the caller's explicit key.
        self._usage_handler = HexgateUsageCallbackHandler(agent_name=name or "default")

    def _with_usage_callback(self, config: dict[str, Any]) -> dict[str, Any]:
        """Append the usage callback handler to ``config['callbacks']``."""
        merged = dict(config)
        callbacks = list(merged.get("callbacks") or [])
        if self._usage_handler not in callbacks:
            callbacks.append(self._usage_handler)
        merged["callbacks"] = callbacks
        return merged

    async def ainvoke(
        self, payload: dict[str, Any], config: dict[str, Any]
    ) -> dict[str, Any]:
        """Delegate invocation to the underlying graph.

        Refreshes the attached policy source before delegating — see
        :func:`_refresh_policy_safely`. The refresh seam lives here (not
        only in :func:`invoke_agent`) so a direct caller of
        ``agent.ainvoke(...)`` gets hot-reload too, instead of silently
        running with stale policy.
        """
        await _refresh_policy_safely(self)
        await self._check_ban()
        await self._check_admission()
        return await self._graph.ainvoke(
            payload, config=self._with_usage_callback(config)
        )

    async def astream_events(
        self,
        payload: dict[str, Any],
        config: dict[str, Any],
        *,
        version: str,
    ) -> AsyncIterator[LangChainStreamEvent]:
        """Delegate event streaming to the underlying graph.

        Refreshes the attached policy source before delegating, same as
        :meth:`ainvoke`. Wrapping both methods means hot-reload fires
        regardless of which entry point a caller picks.
        """
        await _refresh_policy_safely(self)
        await self._check_ban()
        await self._check_admission()
        async for event in self._graph.astream_events(
            payload, config=self._with_usage_callback(config), version=version
        ):
            yield event

    async def _check_ban(self) -> None:
        """Refuse a banned agent/user before the graph runs, if a gate is
        attached. Context comes from the active :class:`HexgateContext` scope
        (this path is ambient, unlike the framework adapters which pass it
        explicitly)."""
        if self._ban_gate is None:
            return
        from hexgate.runtime.context import get_current_context

        await self._ban_gate.check_async(get_current_context())

    async def _check_admission(self) -> None:
        """Refuse a caller not admitted by policy before the graph runs, if an
        admission gate is attached. The gate reads the active
        :class:`HexgateContext` scope for the caller's role; a policy with no
        admission block makes this a no-op."""
        if self._agent_gate is None:
            return
        await self._agent_gate.check_admission_async()

    def with_tools(self, tools: Sequence[ToolSpec]) -> Self:
        """Rebuild the runtime with a new tool list."""
        graph = _build_langchain_agent(
            model=self.model,
            tools=tools,
            system_prompt=self.system_prompt,
            middleware=self.middleware,
            response_format=self.response_format,
            state_schema=self.state_schema,
            context_schema=self.context_schema,
            checkpointer=self.checkpointer,
            store=self.store,
            interrupt_before=self.interrupt_before,
            interrupt_after=self.interrupt_after,
            debug=self.debug,
            name=self.name,
            cache=self.cache,
        )
        # Thread the binding + client through the rebuild so refresh and
        # lazy user attenuation keep working after with_tools.
        return type(self)(
            graph=graph,
            model=self.model,
            tools=tools,
            system_prompt=self.system_prompt,
            middleware=self.middleware,
            response_format=self.response_format,
            state_schema=self.state_schema,
            context_schema=self.context_schema,
            checkpointer=self.checkpointer,
            store=self.store,
            interrupt_before=self.interrupt_before,
            interrupt_after=self.interrupt_after,
            debug=self.debug,
            name=self.name,
            cache=self.cache,
            workspace=self.workspace,
            binding=self._binding,
            hexgate_client=self.hexgate_client,
            ban_gate=self._ban_gate,
            agent_gate=self._agent_gate,
        )

    def enforce_policy(
        self,
        policy: object,
        *,
        approval_handler: ApprovalHandler | None = None,
        source: PolicySource | None = None,
        decision_observer: "DecisionObserver | None" = None,
        guards: "Sequence[Guard] | None" = None,
        guard_observer: "GuardObserver | None" = None,
    ) -> Self:
        """Return a new agent with Gate 1 policy enforcement applied.

        ``policy`` may be a YAML path, a ``policies/`` directory,
        :class:`AgentPolicy`, :class:`PolicySet`, a
        :class:`~hexgate.security.PolicyBundle` (the WASM enforcement
        path), or ``None`` (no-op). Role resolves at call time from the
        active :class:`HexgateContext`. ``approval_handler`` (callable or ``bool``)
        resolves NEEDS_APPROVAL inline; ``None`` renders structured errors.

        ``source`` is the refresh source the returned agent's binding
        carries — pass one for hot reload (see :func:`_bind_policy` /
        ``load_hexgate_agent``); the default ``None`` freezes ``policy``
        so a later :meth:`refresh_policy` can't swap it back out.

        ``decision_observer`` (callable) receives every :class:`Decision`
        after it's built — ``hexgate chat`` uses it to render denies /
        approvals inline; default ``None`` is silent.

        ``guards`` is a flat list of guards authored with ``@before_tool`` /
        ``@after_tool``; they run around each guarded tool call (before-guards
        observe, rewrite args, or halt before ``decide``; after-guards observe
        or halt). The list is split into pre/post internally, order preserved
        within each. Guards ride the same ``GuardedTool`` the enforcer does, so
        they survive hot reload with the tools. ``guard_observer`` receives a
        provenance :class:`~hexgate.guards.types.GuardEvent` when a guard acts.
        Default ``None`` runs no guards.

        The ``(policy, source)`` matrix:

          * ``(engine, source)`` → enforce + attach the refresh source.
          * ``(engine, None)``   → enforce, frozen (no refresh).
          * ``(None,   None)``   → no-op; returns an unguarded rebuild.
          * ``(None,   source)`` → **rejected** (``ValueError``): a refresh
            source with nothing to enforce is a caller mistake (likely a
            forgotten ``policy``), and would otherwise leave the agent
            silently unguarded.
        """
        from langchain_core.tools import BaseTool

        from hexgate.adapters.langchain.tools import GuardedTool
        from hexgate.guards.types import build_pipeline
        from hexgate.security.binding import PolicyBinding
        from hexgate.security.bundle import PolicyBundle
        from hexgate.security.enforcer import build_enforcer
        from hexgate.security.policy_set import PolicySet, load_policy_set

        # Split the flat guard list into the internal pre/post pipeline once.
        pipeline = build_pipeline(guards, observer=guard_observer)

        enforcer: PolicyEnforcer | None
        if policy is None:
            if source is not None:
                raise ValueError(
                    "enforce_policy(None, source=...) passes a refresh source "
                    "with no policy to enforce — the agent would be left "
                    "unguarded. Pass a policy, or drop the source."
                )
            if pipeline is None or pipeline.is_empty:
                # Nothing to enforce and no guards to run (an observer-only
                # pipeline can't fire without guards): return unguarded. Clear any
                # admission gate a prior enforce_policy attached, or with_tools
                # would carry it forward and the "unguarded" agent would still
                # refuse admission.
                unguarded = self.with_tools(list(self.tools))
                unguarded._agent_gate = None
                return unguarded
            enforcer = None  # guards-only gating, no policy engine
        else:
            if isinstance(policy, (PolicyBundle, PolicySet)):
                engine = policy
            else:
                engine = load_policy_set(policy)
            enforcer = build_enforcer(
                engine,
                agent_name=self.name or "default",
                decision_observer=decision_observer,
            )

        # One wrap loop for both paths, so the guards-only path can't drift from
        # the policy path (e.g. silently dropping approval_handler): a
        # GuardedTool with enforcer=None gates via guards alone and still honors
        # a guard Halt(NEEDS_APPROVAL).
        wrapped: list[ToolSpec] = []
        for tool_spec in self.tools:
            if isinstance(tool_spec, BaseTool):
                wrapped.append(
                    GuardedTool.wrap(
                        tool_spec,
                        enforcer=enforcer,
                        approval_handler=approval_handler,
                        pipeline=pipeline,
                    )
                )
            else:
                wrapped.append(tool_spec)
        rebuilt = self.with_tools(wrapped)
        if enforcer is not None:
            from hexgate.security.agent_gate import resolve_agent_gate

            # The binding pairs the enforcer the tools just closed over with the
            # refresh source, so refresh_policy() can swap the policy in place.
            rebuilt._binding = PolicyBinding(enforcer, source)
            # The admission gate shares that same enforcer, so a refresh that
            # swaps the policy is reflected on the next run entry too.
            rebuilt._agent_gate = resolve_agent_gate(
                enforcer, approval_handler=approval_handler
            )
        else:
            # Guards-only path: no enforcer, so no admission. Clear any gate a
            # prior enforce_policy left, which with_tools would otherwise carry.
            rebuilt._agent_gate = None
        return rebuilt

    def refresh_policy(self) -> None:
        """Pull the current policy from the attached source and swap it in.

        Runs at the top of every agent run (:meth:`ainvoke` /
        :meth:`astream_events`). Delegates to the binding (ETag/304,
        identity check, fail-soft); no-op without one.
        """
        if self._binding is not None:
            self._binding.refresh()


AgentGraph: TypeAlias = HexgateAgent


def enforce_policy(
    agent: AgentGraph,
    policy: object,
    *,
    approval_handler: ApprovalHandler | None = None,
    source: PolicySource | None = None,
    decision_observer: "DecisionObserver | None" = None,
    guards: "Sequence[Guard] | None" = None,
    guard_observer: "GuardObserver | None" = None,
) -> AgentGraph:
    """Functional alias for :meth:`HexgateAgent.enforce_policy`."""
    return agent.enforce_policy(
        policy,
        approval_handler=approval_handler,
        source=source,
        decision_observer=decision_observer,
        guards=guards,
        guard_observer=guard_observer,
    )


@observe(name="create_hexgate_agent")
def create_agent(
    model: str | BaseChatModel,
    tools: Sequence[ToolSpec],
    system_prompt: str | Path | SystemMessage | None = DEFAULT_SYSTEM_PROMPT,
    *,
    session_id: str | None = None,
    user_id: str | None = None,
    tags: list[str] | None = None,
    middleware: Sequence[AgentMiddleware[Any, Any]] = (),
    response_format: ResponseFormat[Any] | type[Any] | dict[str, Any] | None = None,
    state_schema: type[Any] | None = None,
    context_schema: type[Any] | None = None,
    checkpointer: BaseCheckpointSaver | None = None,
    store: BaseStore | None = None,
    interrupt_before: list[str] | None = None,
    interrupt_after: list[str] | None = None,
    debug: bool = False,
    name: str | None = None,
    cache: BaseCache[Any] | None = None,
    workspace: Workspace | None = None,
    bind_policy: bool | None = None,
    approval_handler: ApprovalHandler | None = None,
    guards: "Sequence[Guard] | None" = None,
    guard_observer: "GuardObserver | None" = None,
) -> tuple[AgentGraph, CallbackHandler]:
    """Create a hexgate agent as a thin wrapper over LangChain.

    ``bind_policy``: ``True`` always binds (raises without a name); ``False``
    never binds; ``None`` (auto) binds only on an explicit governance signal —
    ``HEXGATE_LOCAL_POLICY`` set, or ``HEXGATE_API_KEY`` **plus**
    ``HEXGATE_BIND_AGENTS=1`` (the platform path is opt-in, so a key present
    for another agent can't surprise-404 an unregistered prototype at
    construction). Binding gates the tools and attaches a refresh source, like
    ``load_hexgate_agent``. ``approval_handler`` applies on that path.

    ``guards`` is a flat list of guards authored with ``@before_tool`` /
    ``@after_tool`` (see :meth:`HexgateAgent.enforce_policy`). They wrap each
    tool whether or not a policy binds — with the resolved policy when it does,
    guards-only when it does not. ``guard_observer`` receives a provenance
    ``GuardEvent`` when a guard acts.
    """
    # Validate at the public boundary, before the (relatively expensive) graph
    # build, so the error lands at the call site rather than deep in dispatch.
    if bind_policy is True and not name:
        raise ValueError(
            "create_agent(bind_policy=True) requires name=... — the agent "
            "name is the policy lookup key on the platform."
        )
    resolved_system_prompt = (
        system_prompt
        if isinstance(system_prompt, SystemMessage)
        else load_system_prompt(system_prompt)
    )
    graph = _build_langchain_agent(
        model=model,
        tools=tools,
        system_prompt=resolved_system_prompt,
        middleware=middleware,
        response_format=response_format,
        state_schema=state_schema,
        context_schema=context_schema,
        checkpointer=checkpointer,
        store=store,
        interrupt_before=interrupt_before,
        interrupt_after=interrupt_after,
        debug=debug,
        name=name,
        cache=cache,
    )
    agent = HexgateAgent(
        graph=graph,
        model=model,
        tools=tools,
        system_prompt=resolved_system_prompt,
        middleware=middleware,
        response_format=response_format,
        state_schema=state_schema,
        context_schema=context_schema,
        checkpointer=checkpointer,
        store=store,
        interrupt_before=interrupt_before,
        interrupt_after=interrupt_after,
        debug=debug,
        name=name,
        cache=cache,
        workspace=workspace,
    )
    if _should_bind_policy(bind_policy, name):
        agent = _bind_policy(  # type: ignore[arg-type]
            agent, name, approval_handler, guards=guards, guard_observer=guard_observer
        )
    elif guards:
        # No policy binding, but guards still wrap each tool (guards-only).
        agent = agent.enforce_policy(
            None,
            guards=guards,
            guard_observer=guard_observer,
            approval_handler=approval_handler,
        )

    handler = get_langfuse_handler(
        session_id=session_id,
        user_id=user_id,
        tags=tags or ["hexgate", str(model)],
    )
    return agent, handler


def _should_bind_policy(bind_policy: bool | None, name: str | None) -> bool:
    """Decide whether :func:`create_agent` binds policy at creation.

    ``True`` always binds; ``False`` never binds. ``None`` (auto) binds only on
    an *explicit* governance signal — never on the mere presence of
    ``HEXGATE_API_KEY``:

      * ``HEXGATE_LOCAL_POLICY`` set → bind. A deliberate local override with
        no platform round-trip, so it can't surprise-404 at construction.
      * ``HEXGATE_API_KEY`` set **and** ``HEXGATE_BIND_AGENTS`` truthy → bind. The
        platform path is opt-in: a key present for some *other* agent must not
        silently turn an unregistered ``create_agent(name=...)`` into a
        construction-time 404. Set ``HEXGATE_BIND_AGENTS=1`` to opt in, or pass
        ``bind_policy=True`` explicitly.

    ``HEXGATE_LOCAL_MODE`` (a truthy value) shorts the auto path to ``False``
    regardless of the other env signals — same one-way kill switch the audit
    sender respects. The explicit ``bind_policy=True`` form is left alone so a
    deliberate caller can still override local mode if they really mean it.

    ``bind_policy=True`` requires a ``name``; that argument check is enforced at
    the :func:`create_agent` boundary, not here (this stays a pure predicate).
    """
    if bind_policy is False:
        return False
    if bind_policy is True:
        return True
    if not name:
        return False
    # Local-mode kill switch: when the bootstrap (or any other caller) has
    # opted into local mode, the auto-detect must not surprise-bind to the
    # platform — that would defeat the whole point of the gate. ``bind_policy=True``
    # is honored above so a deliberate caller can still opt in.
    from hexgate.tracing._senders import _local_mode_active

    if _local_mode_active():
        return False
    if os.environ.get("HEXGATE_LOCAL_POLICY"):
        return True
    from hexgate.security.source import _truthy

    return bool(resolve_api_key()) and _truthy(os.environ.get("HEXGATE_BIND_AGENTS"))


def _bind_policy(
    agent: HexgateAgent,
    name: str,
    approval_handler: ApprovalHandler | None,
    *,
    guards: "Sequence[Guard] | None" = None,
    guard_observer: "GuardObserver | None" = None,
) -> HexgateAgent:
    """Resolve the policy for ``name`` and enforce it on ``agent``.

    Mirrors ``load_hexgate_agent``: resolve → enforce → attach the
    refresh source. Fail-loud — an unregistered agent (platform 404)
    raises; register it first with ``hexgate register``. ``guards`` ride the
    same enforcement so guards wrap the tools alongside the policy.
    """
    from hexgate.security.binding import resolve_policy

    client = None
    if resolve_api_key():
        from hexgate.cloud.client import HexgateClient, HexgateConfig

        client = HexgateClient(HexgateConfig.from_env())

    resolved = resolve_policy(name, client=client)
    enforced = agent.enforce_policy(
        resolved.engine,
        approval_handler=approval_handler,
        source=resolved.source,
        guards=guards,
        guard_observer=guard_observer,
    )
    enforced.hexgate_client = client
    return enforced


_logger = logging.getLogger("hexgate.agents.factory")


async def _refresh_policy_safely(agent: HexgateAgent) -> None:
    """Pull the latest policy from the agent's attached source, off the loop.

    Called by :meth:`HexgateAgent.ainvoke` / :meth:`astream_events` at the
    top of every async invocation, so policy changes land at the next run
    regardless of which entry point a caller picks (the high-level
    :func:`invoke_agent` / :func:`stream_agent_raw` wrappers go through
    those methods too, so they get refresh for free).

    No-op when no source is attached (programmatic construction).

    Actual refresh failures (fetch / verification) are handled in
    :meth:`PolicyBinding.refresh`, which keeps the previous policy and warns
    on the ``hexgate.security.binding`` logger. The ``except`` below is only
    a backstop for unexpected scheduling errors (e.g. ``to_thread``).
    """
    try:
        await asyncio.to_thread(agent.refresh_policy)
    except Exception as exc:  # noqa: BLE001 — refresh must never crash the run
        _logger.warning(
            "unexpected error scheduling policy refresh: %s — keeping "
            "previously loaded policy",
            exc,
        )


@observe(name="invoke_hexgate_agent")
async def invoke_agent(
    agent: AgentGraph,
    handler: CallbackHandler,
    input: AgentInput,
    *,
    tool_use_context: ToolUseContext | None = None,
) -> dict[str, Any]:
    """Invoke the agent for one normalized input payload.

    Policy refresh is handled by :meth:`HexgateAgent.ainvoke` itself,
    so direct callers of that method see the same hot-reload behaviour
    as callers of this wrapper. No double-refresh.
    """
    token = set_current_tool_use_context(
        _resolve_tool_use_context(agent, tool_use_context)
    )
    try:
        return await agent.ainvoke(
            normalize_input(input),
            config=get_langfuse_runnable_config(handler),
        )
    finally:
        reset_current_tool_use_context(token)


async def stream_agent_raw(
    agent: AgentGraph,
    handler: CallbackHandler,
    input: AgentInput,
    *,
    tool_use_context: ToolUseContext | None = None,
) -> AsyncIterator[LangChainStreamEvent]:
    """Stream raw LangChain events from the agent runtime.

    Policy refresh is handled by :meth:`HexgateAgent.astream_events`
    itself — see :func:`invoke_agent` for the matching rationale.
    """
    config = get_langfuse_runnable_config(handler)
    config["run_id"] = new_root_run_id()
    token = set_current_tool_use_context(
        _resolve_tool_use_context(agent, tool_use_context)
    )
    try:
        async for event in agent.astream_events(
            normalize_input(input),
            config=config,
            version="v2",
        ):
            yield event
    finally:
        reset_current_tool_use_context(token)


@observe(name="stream_hexgate_agent")
async def stream_agent(
    agent: AgentGraph,
    handler: CallbackHandler,
    input: AgentInput,
    *,
    tool_use_context: ToolUseContext | None = None,
) -> AsyncIterator[StreamEvent]:
    """Stream normalized runtime events from the agent."""
    raw_events = (
        stream_agent_raw(agent, handler, input)
        if tool_use_context is None
        else stream_agent_raw(agent, handler, input, tool_use_context=tool_use_context)
    )
    async for event in normalize_langchain_events(
        raw_events,
        query=extract_input_text(input),
    ):
        yield event
