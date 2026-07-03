"""Load local and registered agent definitions."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal, TypeAlias

if TYPE_CHECKING:
    from hexgate.security.enforcer import DecisionObserver

import yaml

from hexgate.agents.factory import (
    AgentGraph,
    ApprovalHandler,
    create_agent,
    enforce_policy,
)
from hexgate.agents.models import AgentSpec
from hexgate.cloud.client import HexgateClient, HexgateConfig
from hexgate.config.env import resolve_api_key
from hexgate.security import AgentPolicy, PolicyBundle, load_policy

# HEXGATE_LOCAL_POLICY resolution lives in hexgate.security.source (single
# source of truth for the REQUIRE_SIGNATURE matrix); re-imported here for the
# loaders and back-compat with callers/tests that import it from this module.
from hexgate.security.source import _local_policy_override
from hexgate.tools import (
    bash,
    edit_file,
    fetch,
    glob,
    grep,
    read_file,
    refund_order,
    web_search,
    write_file,
)
from hexgate.tracing.langfuse import CallbackHandler

BUILTIN_TOOLS = {
    "bash": bash,
    "edit_file": edit_file,
    "fetch": fetch,
    "glob": glob,
    "grep": grep,
    "read_file": read_file,
    "refund_order": refund_order,
    "web_search": web_search,
    "write_file": write_file,
}
AgentSource = Literal["local", "registered"]
AgentFactory: TypeAlias = Callable[..., tuple[AgentGraph, CallbackHandler]]
REGISTERED_AGENTS: dict[str, AgentFactory] = {}


def _apply_local_override(
    agent: AgentGraph,
    approval_handler: ApprovalHandler | None,
    decision_observer: "DecisionObserver | None" = None,
) -> AgentGraph | None:
    """Apply ``HEXGATE_LOCAL_POLICY`` to a freshly-built agent, if set.

    Returns the policy-wrapped agent with its source attached, or
    ``None`` when no override is configured — the caller then falls
    back to the normal :func:`enforce_policy` path with the agent's
    own packaged policy.

    ``decision_observer`` is threaded through to the override's
    ``enforce_policy`` call so the chat decision panel keeps working
    when ``HEXGATE_LOCAL_POLICY`` is set — without this, the loader's
    other path (the no-override branch) forwards the observer but this
    one silently drops it.

    Extracted from :func:`load_local_agent` which used this exact block
    verbatim. :func:`load_hexgate_agent`
    deliberately doesn't use this helper — its override interaction is
    more involved (it layers in alongside the platform-served bundle).
    """
    override = _local_policy_override()
    if override is None:
        return None
    bundle, source = override
    return enforce_policy(
        agent,
        bundle,
        approval_handler=approval_handler,
        source=source,
        decision_observer=decision_observer,
    )


def _platform_bundle(payload: dict, client: HexgateClient) -> PolicyBundle | None:
    """Build + verify the signed bundle the platform served, if any.

    Thin one-shot wrapper around the shared decode-and-verify helper in
    :mod:`hexgate.security.source`. Kept here for back-compat with code
    that wants a stateless decode of a single response — the stateful
    refresh path (``If-None-Match``, cache by ``wasm_hash``) lives in
    :class:`~hexgate.security.source.PlatformPolicySource`.
    """
    from hexgate.security.source import decode_and_verify_platform_bundle

    return decode_and_verify_platform_bundle(payload, client.public_key_bytes())


def _load_agent_spec_from_dir(agent_dir: Path) -> AgentSpec:
    """Load an agent spec from a directory containing agent.yaml."""
    spec_path = agent_dir / "agent.yaml"
    payload = yaml.safe_load(spec_path.read_text(encoding="utf-8")) or {}
    return AgentSpec.model_validate(payload)


def local_agents_root(base_dir: str | Path | None = None) -> Path:
    """Return the local project root used for agent discovery."""
    return Path(base_dir or Path.cwd())


def iter_local_agent_dirs(base_dir: str | Path | None = None) -> list[Path]:
    """Discover local agent directories in the project root, ./agents, and ./examples."""
    root = local_agents_root(base_dir)
    discovered: dict[Path, None] = {}

    for child in root.iterdir():
        if child.is_dir() and (child / "agent.yaml").exists():
            discovered[child] = None

    for sub in ("agents", "examples"):
        sub_dir = root / sub
        if sub_dir.exists():
            for child in sub_dir.iterdir():
                if child.is_dir() and (child / "agent.yaml").exists():
                    discovered[child] = None

    return sorted(discovered)


def list_local_agents(base_dir: str | Path | None = None) -> list[str]:
    """List locally discoverable project agents."""
    names: list[str] = []
    for agent_dir in iter_local_agent_dirs(base_dir):
        spec = _load_agent_spec_from_dir(agent_dir)
        names.append(spec.name)
    return sorted(names)


def register_agent(name: str, factory: AgentFactory) -> None:
    """Register a code-defined agent factory under a stable id."""
    REGISTERED_AGENTS[name] = factory


def unregister_agent(name: str) -> None:
    """Remove a previously registered code-defined agent."""
    REGISTERED_AGENTS.pop(name, None)


def clear_registered_agents() -> None:
    """Clear the in-memory code agent registry."""
    REGISTERED_AGENTS.clear()


def list_registered_agents() -> list[str]:
    """List currently registered code-defined agent ids."""
    return sorted(REGISTERED_AGENTS)


def find_local_agent_dir(name: str, base_dir: str | Path | None = None) -> Path:
    """Resolve a local agent name to its directory."""
    for agent_dir in iter_local_agent_dirs(base_dir):
        spec = _load_agent_spec_from_dir(agent_dir)
        if spec.name == name:
            return agent_dir
    raise KeyError(f'Unknown local agent "{name}"')


def load_local_agent_spec(name: str, base_dir: str | Path | None = None) -> AgentSpec:
    """Load a local agent specification by name."""
    return _load_agent_spec_from_dir(find_local_agent_dir(name, base_dir))


def load_local_agent_policy(
    name: str,
    base_dir: str | Path | None = None,
) -> AgentPolicy:
    """Load the policy associated with a local agent."""
    spec = load_local_agent_spec(name, base_dir)
    return load_policy(find_local_agent_dir(name, base_dir) / spec.policy)


def list_available_agents(base_dir: str | Path | None = None) -> list[str]:
    """List merged local and registered agent ids."""
    names = set(list_local_agents(base_dir))
    names.update(list_registered_agents())
    return sorted(names)


def resolve_tools(
    tool_names: list[str],
    extra_tools: Mapping[str, Any] | None = None,
) -> list[Any]:
    """Resolve tool ids against builtin and user-provided tool registries."""
    registry = dict(BUILTIN_TOOLS)
    registry.update(extra_tools or {})

    resolved: list[Any] = []
    for tool_name in tool_names:
        try:
            resolved.append(registry[tool_name])
        except KeyError as exc:
            raise KeyError(f'Unknown tool "{tool_name}"') from exc
    return resolved


def load_local_agent(
    name: str,
    *,
    base_dir: str | Path | None = None,
    session_id: str | None = None,
    user_id: str | None = None,
    tags: list[str] | None = None,
    extra_tools: Mapping[str, Any] | None = None,
    model: str | None = None,
    approval_handler: ApprovalHandler | None = None,
    decision_observer: "DecisionObserver | None" = None,
) -> tuple[AgentGraph, CallbackHandler]:
    """Load and instantiate a local project agent."""
    spec = load_local_agent_spec(name, base_dir)
    agent_dir = find_local_agent_dir(name, base_dir)
    system_prompt = (agent_dir / spec.system_prompt).read_text(encoding="utf-8")
    policy: object = load_policy(agent_dir / spec.policy)
    tools = resolve_tools(spec.tools, extra_tools=extra_tools)
    agent, handler = create_agent(
        model=model or spec.model,
        tools=tools,
        system_prompt=system_prompt,
        session_id=session_id,
        user_id=user_id,
        tags=tags,
        name=spec.name,
        bind_policy=False,  # the loader applies its own policy below
    )
    overridden = _apply_local_override(
        agent, approval_handler, decision_observer=decision_observer
    )
    if overridden is not None:
        return overridden, handler
    return enforce_policy(
        agent,
        policy,
        approval_handler=approval_handler,
        decision_observer=decision_observer,
    ), handler


def load_registered_agent(
    name: str,
    *,
    base_dir: str | Path | None = None,
    session_id: str | None = None,
    user_id: str | None = None,
    tags: list[str] | None = None,
    extra_tools: Mapping[str, Any] | None = None,
    model: str | None = None,
    approval_handler: ApprovalHandler | None = None,
    decision_observer: "DecisionObserver | None" = None,
) -> tuple[AgentGraph, CallbackHandler]:
    """Load a registered code-defined agent by id."""
    try:
        factory = REGISTERED_AGENTS[name]
    except KeyError as exc:
        raise KeyError(f'Unknown registered agent "{name}"') from exc
    agent, handler = factory(
        base_dir=base_dir,
        session_id=session_id,
        user_id=user_id,
        tags=tags,
        extra_tools=extra_tools,
        model=model,
    )
    # Registered factories don't know about the CLI's approval flow / chat
    # decision panel; layer them on after the fact by reaching into the
    # tools' shared enforcer.
    if approval_handler is not None:
        agent = _apply_approval_handler(agent, approval_handler)
    if decision_observer is not None:
        _apply_decision_observer(agent, decision_observer)
    return agent, handler


def _apply_decision_observer(
    agent: AgentGraph, decision_observer: "DecisionObserver"
) -> None:
    """Patch every :class:`GuardedTool`'s enforcer to fire ``decision_observer``.

    For code-registered / spec-loaded agents whose factories built the
    enforcer without seeing the CLI's hook. The expected case is one
    shared enforcer per agent — ``enforce_policy`` constructs one and
    wraps each tool with it — but we patch all distinct enforcers (by
    ``id()``) rather than just the first, so a future refactor that
    builds per-tool enforcers doesn't silently drop events on the
    floor. The shared-instance invariant is then logged (info-level)
    when it's actually shared, and warned (warning-level) when more
    than one distinct enforcer was patched, so the surprise lands.
    """
    import logging

    from hexgate.adapters.langchain.tools import GuardedTool

    log = logging.getLogger(__name__)
    patched_enforcer_ids: set[int] = set()
    for tool_spec in agent.tools:
        if isinstance(tool_spec, GuardedTool):
            tool_spec.enforcer._decision_observer = decision_observer
            patched_enforcer_ids.add(id(tool_spec.enforcer))

    if not patched_enforcer_ids:
        log.warning(
            "decision_observer was supplied but %r has no GuardedTool tools to "
            "attach it to; decision events will not surface for this agent",
            getattr(agent, "name", None) or "agent",
        )
    elif len(patched_enforcer_ids) > 1:
        log.warning(
            "decision_observer attached to %d distinct enforcer instances on %r "
            "(expected one shared enforcer per agent — future refactor?)",
            len(patched_enforcer_ids),
            getattr(agent, "name", None) or "agent",
        )


def _apply_approval_handler(
    agent: AgentGraph, approval_handler: ApprovalHandler | None
) -> AgentGraph:
    """Re-stamp every :class:`GuardedTool` on ``agent`` with ``approval_handler``.

    For code-registered agents whose factories ran ``enforce_policy``
    internally and never saw the CLI's approval callback. Pass the
    ``GuardedTool`` itself (not its inner tool) so the idempotent
    re-wrap branch preserves the existing enforcer. Logs a warning
    when the agent has no ``GuardedTool`` tools (e.g. registered agent
    backed by a non-LangChain framework) so the caller knows the
    handler was silently dropped.
    """
    import logging

    from hexgate.adapters.langchain.tools import GuardedTool

    rewrapped: list[Any] = []
    touched = False
    for tool_spec in agent.tools:
        if isinstance(tool_spec, GuardedTool):
            rewrapped.append(
                GuardedTool.wrap(
                    tool_spec,
                    approval_handler=approval_handler,
                )
            )
            touched = True
        else:
            rewrapped.append(tool_spec)
    if not touched:
        logging.getLogger(__name__).warning(
            "approval_handler was supplied but %r has no GuardedTool tools to apply "
            "it to; approval prompts will not fire for this agent",
            getattr(agent, "name", None) or "agent",
        )
        return agent
    return agent.with_tools(rewrapped)


def resolve_agent_source(name: str, base_dir: str | Path | None = None) -> AgentSource:
    """Return whether an agent id resolves from local or registered definitions."""
    if name in list_local_agents(base_dir):
        return "local"
    if name in list_registered_agents():
        return "registered"
    raise KeyError(f'Unknown agent "{name}"')


def load_hexgate_agent(
    name: str | None = None,
    *,
    project_id: str | None = None,
    base_url: str | None = None,
    api_key: str | None = None,
    session_id: str | None = None,
    tags: list[str] | None = None,
    extra_tools: Mapping[str, Any] | None = None,
    model: str | None = None,
    approval_handler: ApprovalHandler | None = None,
    decision_observer: "DecisionObserver | None" = None,
) -> tuple[AgentGraph, CallbackHandler]:
    """Fetch an agent from Hexgate and return it with policy enforcement applied.

    Mirrors `load_local_agent` but sources the three YAMLs (agent, policy, system)
    from the Hexgate API instead of disk. Tool resolution and enforcement are
    identical — only the bytes' origin differs.

    ``name`` is required. The Phase-7 env-var fallback chain
    (explicit → HEXGATE_AGENT_NAME → "default") was removed when the
    canonical serve path moved to ``build_runtime_from_local_agent``
    (which derives the name from the agent object). Direct callers of
    this API must pass an explicit name.

    The returned agent carries a ``hexgate_client`` attribute referencing the
    :class:`~hexgate.cloud.HexgateClient` used to fetch it; the runtime reads
    this attribute when an :class:`~hexgate.runtime.User` scope is active to
    mint per-request attenuated tokens lazily.
    """
    if not name:
        raise ValueError(
            "load_hexgate_agent(name=...) requires an explicit agent name. "
            "HEXGATE_AGENT_NAME / 'default' fallback was removed in Phase 7."
        )
    resolved_name = name
    config = HexgateConfig.from_env(
        project_id=project_id, base_url=base_url, api_key=api_key
    )
    client = HexgateClient(config)
    payload, initial_etag = client.get_agent(resolved_name)
    if payload is None:
        # Invariant: the first get_agent has no If-None-Match, so a 304
        # is impossible — but use `raise` not `assert` so `python -O`
        # can't strip the check.
        raise RuntimeError(
            "HexgateClient.get_agent returned no payload on initial fetch "
            "(no If-None-Match was sent, so 304 should be impossible)"
        )

    spec = AgentSpec.model_validate(yaml.safe_load(payload["agent_yaml"]) or {})
    system_prompt = payload.get("system_md") or ""

    tools = resolve_tools(spec.tools, extra_tools=extra_tools)

    agent, handler = create_agent(
        model=model or spec.model,
        tools=tools,
        system_prompt=system_prompt,
        session_id=session_id,
        # ``config.project_id`` can be None when the bearer envelope
        # didn't carry the project prefix (Phase 6 made it optional);
        # filter Nones so langchain doesn't get fed a None tag.
        tags=tags or [t for t in ["hexgate", "hexgate-cloud", config.project_id] if t],
        name=spec.name,
        bind_policy=False,  # this loader composes the binding itself below
    )
    # Precedence: HEXGATE_LOCAL_POLICY override → platform (signed bundle,
    # or pydantic on policy_yaml). Decode/verify rules are shared with
    # resolve_policy via platform_policy_from_payload.
    from hexgate.security.binding import platform_policy_from_payload

    override = _local_policy_override()
    if override is not None:
        policy, refresh_source = override
    else:
        policy, refresh_source = platform_policy_from_payload(
            client, resolved_name, payload, initial_etag
        )

    enforced = enforce_policy(
        agent,
        policy,
        approval_handler=approval_handler,
        source=refresh_source,
        decision_observer=decision_observer,
    )
    # Attach the client so the runtime can do lazy attenuation inside an
    # active User scope without the caller having to thread it through.
    enforced.hexgate_client = client
    return enforced, handler


def load_agent(
    name: str | None = None,
    *,
    base_dir: str | Path | None = None,
    session_id: str | None = None,
    user_id: str | None = None,
    tags: list[str] | None = None,
    extra_tools: Mapping[str, Any] | None = None,
    model: str | None = None,
    local_only: bool = False,
    approval_handler: ApprovalHandler | None = None,
    decision_observer: "DecisionObserver | None" = None,
) -> tuple[AgentGraph, CallbackHandler]:
    """Load an agent from Hexgate (when HEXGATE_API_KEY is set), local, or registered.

    ``name`` is required for every path post-Phase 7 — the
    HEXGATE_AGENT_NAME env-var fallback was removed when ``hexgate
    serve`` moved to the uvicorn-style ``module:attr`` spec.

    Pass ``local_only=True`` to force resolution from local / registered
    sources even when ``HEXGATE_API_KEY`` is set in the environment.
    Useful for terminal-chat workflows that don't need cloud-fetched policy.

    ``decision_observer`` is forwarded to every enforced loader (local,
    registered, cloud). Threaded as a kwarg rather than a contextvar so
    the call sites stay explicit — ``hexgate chat`` is the only caller
    passing it today.
    """
    if not local_only and resolve_api_key():
        # load_hexgate_agent dropped its reserved ``user_id`` placeholder
        # in phase 3.5 — per-request user identity comes from a User scope
        # at invocation time, not from the loader.
        return load_hexgate_agent(
            name,
            session_id=session_id,
            tags=tags,
            extra_tools=extra_tools,
            model=model,
            approval_handler=approval_handler,
            decision_observer=decision_observer,
        )
    if name is None:
        raise ValueError("load_agent() requires a name when not using Hexgate Cloud")
    source = resolve_agent_source(name, base_dir)
    if source == "local":
        return load_local_agent(
            name,
            base_dir=base_dir,
            session_id=session_id,
            user_id=user_id,
            tags=tags,
            extra_tools=extra_tools,
            model=model,
            approval_handler=approval_handler,
            decision_observer=decision_observer,
        )
    # resolve_agent_source raises KeyError for unknown ids, so the only
    # remaining source here is "registered".
    return load_registered_agent(
        name,
        base_dir=base_dir,
        session_id=session_id,
        user_id=user_id,
        tags=tags,
        extra_tools=extra_tools,
        model=model,
        approval_handler=approval_handler,
        decision_observer=decision_observer,
    )
