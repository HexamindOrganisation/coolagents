"""Shared CLI building blocks used by both `hexgate chat` and `hexgate serve`."""

from __future__ import annotations

import argparse
import importlib
import importlib.util
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Callable

    from hexgate.agents.factory import AgentInput
    from hexgate.runtime import HexgateContext
    from hexgate.security.enforcer import DecisionObserver
    from hexgate.streaming import StreamEvent

    # The framework-agnostic serve streaming seam: given the turn's input, the
    # caller's (optional) attenuation context, and the user query, yield
    # normalized StreamEvents. Bound per framework in
    # ``build_runtime_from_local_agent`` so ``hexgate serve`` stays framework-blind.
    ServeStreamFn = Callable[
        ["AgentInput", "HexgateContext | None", str], "AsyncIterator[StreamEvent]"
    ]

from rich.console import Console, Group
from rich.panel import Panel
from rich.text import Text

from hexgate.agents.factory import AgentGraph, ApprovalHandler, CallbackHandler
from hexgate.agents.loader import load_agent, resolve_agent_source
from hexgate.config.env import resolve_api_key
from hexgate.config.settings import Settings
from hexgate.security.decision import Decision

ApprovalMode = Literal["ask", "auto-approve", "auto-deny"]


@dataclass
class AgentRuntime:
    """Bundle the runtime pieces needed by the terminal chat and serve loop."""

    agent: AgentGraph
    handler: CallbackHandler
    agent_name: str
    agent_source: str
    model: str
    tools_by_name: dict[str, object]
    # Serve-only: the per-framework normalized streaming seam. ``None`` for
    # runtimes built by ``build_runtime`` (terminal chat), which streams via
    # ``stream_agent`` directly; set by ``build_runtime_from_local_agent``.
    astream_normalized: "ServeStreamFn | None" = None


def build_runtime(
    settings: Settings,
    *,
    agent_name: str,
    base_dir: Path,
    model: str | None,
    local_only: bool = False,
    approval_handler: ApprovalHandler | None = None,
    decision_observer: "DecisionObserver | None" = None,
) -> AgentRuntime:
    """Create the runtime shared by ``hexgate chat`` and ``hexgate serve``.

    ``agent_name`` accepts two forms:

    * Plain id (``"example_agent"``) — resolved via local / registered
      lookup, then enforced through the standard loader. This is the
      existing path.
    * uvicorn-style spec (``"examples.customer_bot:agent"``) — imported
      directly from the module and used as-is. Skips the name resolver
      entirely; the agent object is expected to be a fully-configured
      :class:`HexgateAgent` (typically the user's module already called
      ``.enforce_policy(...)`` before exporting it). Closes the
      "this loads in serve but not chat" footgun — same spec form
      ``hexgate serve`` already accepts.

    ``local_only=True`` keeps the loader off the Hexgate Cloud path even
    when ``HEXGATE_API_KEY`` is present in the environment — what terminal
    chat uses, since it doesn't need cloud-fetched policy or a serve
    tunnel. ``hexgate serve`` passes ``local_only=False`` so policy edits
    in the dashboard land at the next turn boundary. ``approval_handler``
    threads to :func:`load_agent` for inline ``NEEDS_APPROVAL`` resolution.
    ``decision_observer`` likewise threads through — ``hexgate chat``
    uses it to render denies / approvals in the REPL.
    """
    # Spec form (``module.path:attr``) — handled out-of-band from the
    # name resolver. A colon in a plain id is already discouraged
    # (YAML-loaded agent names with colons invite trouble), so the
    # branch is unambiguous and a clean ModuleNotFoundError beats a
    # confusing "agent not found" if the spec is misspelled.
    if ":" in agent_name:
        return _build_runtime_from_spec(
            settings,
            spec=agent_name,
            approval_handler=approval_handler,
            decision_observer=decision_observer,
        )

    resolved_model = model or settings.model
    agent, handler = load_agent(
        agent_name,
        base_dir=base_dir,
        model=resolved_model,
        session_id="hexgate-cli",
        tags=["hexgate", settings.search_engine, resolved_model, agent_name],
        local_only=local_only,
        approval_handler=approval_handler,
        decision_observer=decision_observer,
    )
    # The agent's tools come from its own definition (agent.yaml / factory);
    # the CLI no longer injects a default toolset.
    tools_by_name = {
        getattr(tool, "name", getattr(tool, "__name__", "tool")): tool
        for tool in getattr(agent, "tools", [])
    }
    if not local_only and resolve_api_key():
        agent_source = "hexgate"
    else:
        agent_source = resolve_agent_source(agent_name, base_dir)
    return AgentRuntime(
        agent=agent,
        handler=handler,
        agent_name=agent_name,
        agent_source=agent_source,
        model=resolved_model,
        tools_by_name=tools_by_name,
    )


def _build_runtime_from_spec(
    settings: Settings,
    *,
    spec: str,
    approval_handler: ApprovalHandler | None,
    decision_observer: "DecisionObserver | None",
) -> AgentRuntime:
    """Resolve a ``module:attr`` spec to an :class:`AgentRuntime`, local-only.

    The agent object is taken as-is — no platform round-trip, no manifest
    re-registration, no policy fetch. The user's module is responsible
    for having called ``.enforce_policy(...)`` if they want enforcement;
    chat just wires the CLI's approval handler and decision observer
    into the agent's existing enforcer (reusing the in-place injectors
    from the loader so registered-agent and spec'd-agent share one path)."""
    from hexgate.agents.loader import (
        _apply_approval_handler,
        _apply_decision_observer,
    )
    from hexgate.tracing.langfuse import get_langfuse_handler

    agent_obj = load_spec(spec)
    agent_name = getattr(agent_obj, "name", None) or spec

    if approval_handler is not None:
        agent_obj = _apply_approval_handler(agent_obj, approval_handler)
    if decision_observer is not None:
        _apply_decision_observer(agent_obj, decision_observer)

    handler = get_langfuse_handler(
        session_id="hexgate-cli",
        tags=["hexgate", "spec", agent_name],
    )

    # The agent object carries its own model (str or BaseChatModel);
    # stringify for the welcome banner. Fall back to settings.model
    # if the spec'd object doesn't have a .model attr (unusual but
    # possible for non-HexgateAgent shapes).
    raw_model = getattr(agent_obj, "model", None)
    resolved_model = str(raw_model) if raw_model is not None else settings.model

    tools_by_name = {
        getattr(t, "name", getattr(t, "__name__", "tool")): t
        for t in getattr(agent_obj, "tools", [])
    }
    return AgentRuntime(
        agent=agent_obj,
        handler=handler,
        agent_name=agent_name,
        agent_source="spec",
        model=resolved_model,
        tools_by_name=tools_by_name,
    )


def build_runtime_from_local_agent(
    settings: Settings,
    *,
    agent_obj: Any,
    description: str | None,
    approval_handler: ApprovalHandler | None,
    auto_register: bool,
    console: Console,
) -> AgentRuntime:
    """Build an :class:`AgentRuntime` from a Python-loaded agent object.

    The uvicorn-style serve flow:
      1. ``create_manifest(agent_obj)`` — same dispatch ``hexgate register``
         uses. HexgateAgent / OpenAI / Pydantic-AI agents introspect cleanly;
         raw LangGraph errors out with a clear message (the user should
         wrap with ``create_agent(...)`` or pass ``--tools`` to the legacy
         register flow).
      2. If ``auto_register`` and ``HEXGATE_API_KEY`` is set: POST the manifest
         to ``/v1/agents``. Idempotent — server short-circuits when the
         content_hash hasn't changed. Print "Registered" / "unchanged" so
         the operator sees what just happened.
      3. Dispatch on ``manifest.framework`` to a per-framework builder that
         wires enforcement + a normalized streaming seam
         (``AgentRuntime.astream_normalized``). ``hexgate serve`` itself stays
         framework-blind — it only calls that seam.

    Returns an :class:`AgentRuntime` whose ``agent_name`` is the manifest's name
    (matches what we'll announce to the relay's ``hello`` message).
    """
    from hexgate.cli.register.register import post_manifest
    from hexgate.manifest import create_manifest
    from hexgate.manifest.models import AgentFramework

    manifest = create_manifest(agent_obj, description=description)
    agent_name = manifest.name

    if auto_register and resolve_api_key():
        # Idempotent POST. ``created`` flag in the response distinguishes
        # "first registered" from "manifest unchanged" so we can give the
        # operator a meaningful console line.
        result = post_manifest(manifest)
        if result.get("created"):
            console.print(
                f"[dim]ℹ Registered agent[/] [cyan]{agent_name}[/] "
                f"[dim](v{result.get('version', '?')})[/]"
            )
        else:
            console.print(
                f"[dim]ℹ Agent[/] [cyan]{agent_name}[/] "
                f"[dim]already registered (manifest unchanged)[/]"
            )

    if manifest.framework == AgentFramework.HEXGATE:
        return _build_hexgate_serve_runtime(
            settings,
            agent_obj=agent_obj,
            agent_name=agent_name,
            approval_handler=approval_handler,
        )
    if manifest.framework == AgentFramework.OPENAI:
        return _build_openai_serve_runtime(
            settings,
            agent_obj=agent_obj,
            agent_name=agent_name,
            approval_handler=approval_handler,
        )
    raise NotImplementedError(
        f"hexgate serve does not yet support {manifest.framework.value} agents "
        "— supported frameworks are native (hexgate) and OpenAI. "
        "Google ADK and Pydantic AI serve support is planned."
    )


def _build_hexgate_serve_runtime(
    settings: Settings,
    *,
    agent_obj: Any,
    agent_name: str,
    approval_handler: ApprovalHandler | None,
) -> AgentRuntime:
    """Build the serve runtime for a native (LangChain) HexgateAgent.

    Fetches the platform's (possibly dashboard-edited) policy, wraps the local
    agent's tools with it, and binds a ``stream_agent`` streaming seam. Local
    code stays authoritative for tools/model/prompt; the platform for policy.
    """
    from hexgate.agents.factory import enforce_policy, stream_agent
    from hexgate.cloud.client import HexgateClient, HexgateConfig
    from hexgate.security.binding import platform_policy_from_payload
    from hexgate.tracing.langfuse import get_langfuse_handler

    config = HexgateConfig.from_env()
    client = HexgateClient(config)
    payload, initial_etag = client.get_agent(agent_name)
    if payload is None:
        # Invariant: no If-None-Match was sent, so a 304 is impossible.
        # Raise so `python -O` can't strip the check.
        raise RuntimeError(
            f"HexgateClient.get_agent({agent_name!r}) returned no payload "
            "on initial fetch (no If-None-Match was sent)"
        )

    # platform_policy_from_payload returns the canonical (engine, source)
    # pair: handles signed-bundle vs pydantic fallback, and seeds the
    # PlatformPolicySource with the bundle + ETag so the next refresh is
    # a 304 unless policy changed. Without the source kwarg, refresh_policy()
    # at the top of every stream_agent() is a no-op and dashboard edits
    # only land at the next `hexgate serve` restart.
    policy, refresh_source = platform_policy_from_payload(
        client, agent_name, payload, initial_etag
    )

    enforced = enforce_policy(
        agent_obj,
        policy,
        approval_handler=approval_handler,
        source=refresh_source,
    )

    # Fresh handler for the streaming layer. The user's create_agent() call
    # built its own handler but discarded it; we make a new one bound to
    # this serve session's session_id so traces don't mix across runs.
    handler = get_langfuse_handler(
        session_id="hexgate-serve",
        tags=["hexgate", "hexgate-serve", agent_name],
    )

    def _astream(agent_input: Any, ctx: Any, query: str) -> AsyncIterator[StreamEvent]:
        # stream_agent reads the ambient HexgateContext and derives its own
        # query; open the caller's attenuation scope around it when present,
        # else run with no scope (default role) exactly as before.
        async def _gen() -> AsyncIterator[StreamEvent]:
            if ctx is None:
                async for event in stream_agent(enforced, handler, agent_input):
                    yield event
            else:
                async with ctx:
                    async for event in stream_agent(enforced, handler, agent_input):
                        yield event

        return _gen()

    return AgentRuntime(
        agent=enforced,
        handler=handler,
        agent_name=agent_name,
        agent_source="hexgate",
        model=settings.model,
        tools_by_name={
            getattr(t, "name", getattr(t, "__name__", "tool")): t
            for t in getattr(enforced, "tools", [])
        },
        astream_normalized=_astream,
    )


def _build_openai_serve_runtime(
    settings: Settings,
    *,
    agent_obj: Any,
    agent_name: str,
    approval_handler: ApprovalHandler | None,
) -> AgentRuntime:
    """Build the serve runtime for an OpenAI Agents SDK agent.

    Unlike the native path, the OpenAI ``HexgateRunner`` fetches and hot-reloads
    its own per-run policy binding (ETag/304) and enforces the ban gate, so we
    build the runner once and bind a normalized streaming seam over it — no
    ``enforce_policy`` here, the runner owns enforcement.
    """
    from hexgate.adapters.openai.runner import HexgateRunner
    from hexgate.adapters.openai.streaming import astream_openai
    from hexgate.runtime import HexgateContext
    from hexgate.tracing.langfuse import get_langfuse_handler

    runner = HexgateRunner(approval_handler=approval_handler)
    handler = get_langfuse_handler(
        session_id="hexgate-serve",
        tags=["hexgate", "hexgate-serve", agent_name],
    )

    def _astream(agent_input: Any, ctx: Any, query: str) -> AsyncIterator[StreamEvent]:
        # The runner requires a context to open its enforcement scope; with no
        # dashboard attenuation, run as an anonymous default-role caller (empty
        # user_id, no roles), mirroring the native path's no-scope default.
        return astream_openai(
            runner,
            agent_obj,
            agent_input,
            hexgate_context=ctx or HexgateContext(user_id=""),
            query=query,
        )

    return AgentRuntime(
        agent=agent_obj,
        handler=handler,
        agent_name=agent_name,
        agent_source="hexgate",
        model=settings.model,
        tools_by_name={
            getattr(t, "name", getattr(t, "__name__", "tool")): t
            for t in getattr(agent_obj, "tools", [])
        },
        astream_normalized=_astream,
    )


def load_spec(spec: str) -> Any:
    """Resolve a ``module.path:attr`` spec to its target object.

    The shared loader for ``hexgate register --agent <spec>`` and
    ``hexgate serve <spec>`` — both subcommands take the same shape so
    devs only learn one form. ``file/path.py:attr`` works too via the
    leading ``sys.path.insert(0, '')`` (cwd) trick.

    Raises ``ValueError`` for malformed specs and ``AttributeError``
    for valid specs whose target object doesn't exist on the module.
    """
    module_path, sep, attr = spec.partition(":")
    if not sep or not module_path or not attr:
        raise ValueError(
            f"Invalid spec {spec!r}: expected 'module.path:attr' "
            f"(e.g. my_app.module:my_attr)"
        )

    # cwd on sys.path so a user can run from their project root and
    # spec their own module — same trick uvicorn / pytest pull.
    if "" not in sys.path:
        sys.path.insert(0, "")

    module = importlib.import_module(module_path)
    try:
        return getattr(module, attr)
    except AttributeError as exc:
        raise AttributeError(
            f"Module {module_path!r} has no attribute {attr!r}"
        ) from exc


def load_agent_script(script_path: str | Path) -> Path:
    """Import a Python script that registers code-defined agents."""
    path = Path(script_path).expanduser().resolve()
    module_name = f"hexgate_user_script_{path.stem}"
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Could not load agent script: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return path


def _truncate_approval_value(value: object, *, limit: int = 80) -> str:
    """Return a compact single-line representation for approval prompts."""
    text = str(value).replace("\n", "\\n")
    if len(text) <= limit:
        return text
    return f"{text[: limit - 3]}..."


def prompt_for_approval(console: Console, decision: Decision) -> bool:
    """Prompt the user in the terminal to approve one tool invocation.

    Reads everything from the :class:`Decision`: the proposed tool name,
    arguments, the caller's roles, and agent_name. No external lookup needed.
    """
    arguments = decision.arguments or {}

    header = Text(f"Approval required for {decision.tool_name}", style="bold yellow")
    role_lines = [
        *(
            [Text(f"roles: {', '.join(decision.user_roles)}", style="dim")]
            if decision.user_roles
            else []
        ),
        # The approver is deciding on behalf of that role's policy.
        *(
            [Text(f"granted by: {decision.deciding_role}", style="dim")]
            if decision.deciding_role is not None
            else []
        ),
    ]

    console.print()
    console.print(
        Panel(
            Group(
                header,
                *role_lines,
                *(
                    Text(
                        f"{key}: {_truncate_approval_value(value)}",
                        style="white",
                    )
                    for key, value in arguments.items()
                ),
                Text("Type y to approve or n to deny, then press Enter.", style="dim"),
            ),
            border_style="yellow",
            title="[bold yellow]Approval[/]",
            padding=(0, 1),
        )
    )
    answer = console.input("[bold yellow]Approve? [y/N] [/]").strip().lower()
    console.print()
    return answer in {"y", "yes"}


def build_approval_handler(console: Console, mode: ApprovalMode):
    """Return a CLI approval handler — ``bool`` for auto modes, a
    ``(Decision) -> bool`` callable for ``ask``."""
    if mode == "auto-approve":
        return True
    if mode == "auto-deny":
        return False

    def approval_handler(decision: Decision) -> bool:
        return prompt_for_approval(console, decision)

    return approval_handler


def add_shared_agent_flags(parser: argparse.ArgumentParser) -> None:
    """Register flags shared between `hexgate chat` and `hexgate serve`."""
    parser.add_argument(
        "--agent",
        help=(
            "Agent id (resolved from local / registered / builtin definitions) "
            "OR a uvicorn-style 'module.path:attr' spec to import directly."
        ),
    )
    parser.add_argument(
        "--model", help="Optional model override for the selected agent."
    )
    parser.add_argument(
        "--use",
        help="Python script that registers code-defined agents before loading --agent.",
    )
    parser.add_argument(
        "--approval-mode",
        choices=("ask", "auto-approve", "auto-deny"),
        default="ask",
        help="How the CLI should handle approval-required tools.",
    )
