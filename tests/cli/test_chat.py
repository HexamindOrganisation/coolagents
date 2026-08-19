"""Tests for inline terminal app rendering helpers."""

from __future__ import annotations

import logging
import textwrap
from collections import deque
from pathlib import Path

import pytest
from rich.console import Console, Group

from hexgate.agents import loader
from hexgate.agents.loader import _apply_decision_observer
from hexgate.cli import _common
from hexgate.cli._common import (
    AgentRuntime,
    build_approval_handler as _build_approval_handler,
    load_agent_script as _load_agent_script,
    prompt_for_approval as _prompt_for_approval,
)
from hexgate.cli.chat import (
    DOG_LOGO,
    _drain_decisions,
    _render_current_run,
    _render_decision_panel,
    _render_welcome,
    _tail_text,
)
from hexgate.cli.state import LiveRunState, ToolActivity
from hexgate.config.settings import Settings
from hexgate.security.decision import Decision, DecisionOutcome
from hexgate.streaming import ToolCallState
from hexgate.tools import edit_file, read_file

# Repo root, derived from this test file's location — keeps the
# ``_load_agent_script`` tests below portable across machines / CI.
REPO_ROOT = Path(__file__).resolve().parents[2]
EXAMPLES_DIR = REPO_ROOT / "examples"


def test_tail_text_keeps_last_lines_of_long_output() -> None:
    """Keep only the trailing lines for live rendering."""
    text = "\n".join(f"line {index}" for index in range(1, 21))

    tailed, truncated = _tail_text(text, max_lines=4, max_chars=10_000)

    assert tailed == "line 17\nline 18\nline 19\nline 20"
    assert truncated is True


def test_tail_text_caps_large_character_payloads() -> None:
    """Trim very large text blocks before line tailing."""
    text = "a" * 50 + "tail"

    tailed, truncated = _tail_text(text, max_lines=5, max_chars=8)

    assert tailed == "aaaatail"
    assert truncated is True


def test_tail_text_reports_when_text_is_not_truncated() -> None:
    """Leave short text untouched and mark it as fully visible."""
    tailed, truncated = _tail_text("short answer", max_lines=5, max_chars=100)

    assert tailed == "short answer"
    assert truncated is False


def test_render_welcome_includes_agent_and_model() -> None:
    """Render a startup card with the active runtime metadata."""
    runtime = AgentRuntime(
        agent="agent",  # type: ignore[arg-type]
        handler="handler",  # type: ignore[arg-type]
        agent_name="example_agent",
        agent_source="local",
        model="gpt-5.4",
        tools_by_name={},
    )

    console = Console(record=True, width=100)
    console.print(_render_welcome(runtime))
    rendered = console.export_text()

    assert "example_agent" in rendered
    assert "gpt-5.4" in rendered
    assert "hexgate" in rendered
    assert DOG_LOGO.splitlines()[0].strip() in rendered


def test_render_current_run_uses_tool_arguments_and_timeline_spacing() -> None:
    """Render tool rows with readable labels and connector spacing."""
    runtime = AgentRuntime(
        agent="agent",  # type: ignore[arg-type]
        handler="handler",  # type: ignore[arg-type]
        agent_name="repo_editor",
        agent_source="local",
        model="gpt-5.4",
        tools_by_name={
            read_file.name: read_file,
            edit_file.name: edit_file,
        },
    )
    current_run = LiveRunState(
        query="update napoleon.md",
        is_streaming=False,
        tools=[
            ToolActivity(
                tool_id="tool-1",
                tool_name="read_file",
                status=ToolCallState.COMPLETED,
                arguments={"file_path": "napoleon.md"},
            ),
            ToolActivity(
                tool_id="tool-2",
                tool_name="edit_file",
                status=ToolCallState.COMPLETED,
                arguments={"file_path": "napoleon.md"},
            ),
        ],
    )

    console = Console(record=True, width=100)
    console.print(Group(*_render_current_run(runtime, current_run, live=True)))
    rendered = console.export_text()

    assert "reading napoleon.md" in rendered
    assert "editing napoleon.md" in rendered
    assert "│" in rendered


def test_render_current_run_uses_spinner_for_thinking_state() -> None:
    """Render a live spinner when the assistant is still thinking."""
    runtime = AgentRuntime(
        agent="agent",  # type: ignore[arg-type]
        handler="handler",  # type: ignore[arg-type]
        agent_name="repo_editor",
        agent_source="local",
        model="gpt-5.4",
        tools_by_name={},
    )
    current_run = LiveRunState(
        query="think a bit",
        is_streaming=True,
    )

    console = Console(record=True, width=100)
    console.print(Group(*_render_current_run(runtime, current_run, live=True)))
    rendered = console.export_text()

    assert "thinking..." in rendered


def test_build_approval_handler_supports_auto_modes() -> None:
    """Map CLI approval modes to simple boolean handlers when possible."""
    console = Console(record=True, width=100)

    assert _build_approval_handler(console, "auto-approve") is True
    assert _build_approval_handler(console, "auto-deny") is False


def test_prompt_for_approval_asks_user_with_tool_arguments() -> None:
    """Render a compact approval prompt and return the user's decision."""
    console = Console(record=True, width=100)
    captured_prompts: list[str] = []

    def fake_input(prompt: str) -> str:
        captured_prompts.append(prompt)
        return "y"

    console.input = fake_input  # type: ignore[method-assign]

    decision = Decision(
        outcome=DecisionOutcome.NEEDS_APPROVAL,
        agent_name="test-agent",
        tool_name="write_file",
        user_roles=("support",),
        deciding_role="support",
        reason='Policy requires approval for tool "write_file"',
        error_type="approval_required",
        arguments={
            "file_path": "napoleon.md",
            "content": "new section",
        },
    )

    approved = _prompt_for_approval(console, decision)

    rendered = console.export_text()

    assert approved is True
    assert "Approval required for write_file" in rendered
    assert "roles: support" in rendered
    assert "granted by: support" in rendered
    assert "file_path: napoleon.md" in rendered
    assert "content: new section" in rendered
    assert "Type y to approve or n to deny, then press Enter." in rendered
    assert captured_prompts == ["[bold yellow]Approve? [y/N] [/]"]


def test_load_agent_script_registers_code_agents() -> None:
    """Importing a registration script should populate the code agent registry."""
    loader.clear_registered_agents()

    _load_agent_script(str(EXAMPLES_DIR / "file_agents.py"))

    assert "workspace_explorer" in loader.list_registered_agents()
    assert "repo_editor" in loader.list_registered_agents()


def test_load_research_agent_script_registers_update_researcher() -> None:
    """Importing the research example script should register the update researcher agent."""
    loader.clear_registered_agents()

    _load_agent_script(str(EXAMPLES_DIR / "research_agents.py"))

    assert "update_researcher" in loader.list_registered_agents()


def test_load_bash_file_agent_script_registers_repo_operator() -> None:
    """Importing the bash+file example script should register the repo operator agent."""
    loader.clear_registered_agents()

    _load_agent_script(str(EXAMPLES_DIR / "bash_file_agents.py"))

    assert "repo_operator" in loader.list_registered_agents()


# ---------------------------------------------------------------------------
# Decision panel — surfaces denies / approvals in the REPL
# ---------------------------------------------------------------------------


def _decision(
    outcome: DecisionOutcome,
    *,
    reason: str = "",
    error_type: str | None = None,
    role: str | None = None,
    violations: tuple[str, ...] = (),
    hint: object | None = None,
) -> Decision:
    """Build a Decision directly — bypasses the engine + verdict path
    for tests that only care about the rendered output."""
    return Decision(
        outcome=outcome,
        agent_name="r",
        tool_name="read_file",
        user_roles=(role,) if role is not None else (),
        deciding_role=role if outcome is DecisionOutcome.NEEDS_APPROVAL else None,
        reason=reason,
        error_type=error_type,
        violations=violations,
        hint=hint,
    )


def test_render_decision_panel_returns_none_for_allow() -> None:
    """ALLOW is muted: a chatty REPL with one panel per tool call is
    noise. The whole point of the feed is 'what got blocked.'"""
    assert _render_decision_panel(_decision(DecisionOutcome.ALLOW)) is None


def test_render_decision_panel_for_deny_shows_reason_and_violations() -> None:
    """A DENY panel must surface the reason, error_type, role, and any
    violation strings — that's the diagnostic payload a dev needs."""
    decision = _decision(
        DecisionOutcome.DENY,
        reason="path escapes workspace",
        error_type="policy_denied",
        role="analyst",
        violations=("path_outside_glob", "read_denied_for_role"),
    )

    console = Console(record=True, width=100)
    console.print(_render_decision_panel(decision))
    rendered = console.export_text()

    assert "deny" in rendered
    assert "read_file" in rendered
    assert "path escapes workspace" in rendered
    assert "policy_denied" in rendered
    assert "analyst" in rendered
    assert "path_outside_glob" in rendered
    assert "read_denied_for_role" in rendered


def test_render_decision_panel_for_needs_approval() -> None:
    """NEEDS_APPROVAL renders distinctly (different glyph, different
    border) but carries the same diagnostic payload as DENY."""
    decision = _decision(
        DecisionOutcome.NEEDS_APPROVAL,
        reason="bash_run requires sign-off",
        error_type="approval_required",
    )

    console = Console(record=True, width=100)
    console.print(_render_decision_panel(decision))
    rendered = console.export_text()

    assert "needs_approval" in rendered
    assert "bash_run requires sign-off" in rendered
    assert "approval_required" in rendered


def test_render_decision_panel_handles_minimal_decision() -> None:
    """A DENY with no reason / violations / role still renders without
    crashing — defensive against engines that omit detail fields."""
    console = Console(record=True, width=100)
    console.print(_render_decision_panel(_decision(DecisionOutcome.DENY)))
    rendered = console.export_text()
    assert "deny" in rendered
    assert "read_file" in rendered


def test_render_decision_panel_renders_hint_as_json_not_python_repr() -> None:
    """``hint`` is a dict (e.g. ``{"glob": "/x/**"}``). Render it as JSON
    so the panel reads naturally and matches the wire format the platform
    stores. The pre-fix code used Python repr (single quotes) which made
    the panel look like Python debug output rather than diagnostic data."""
    decision = _decision(
        DecisionOutcome.DENY,
        reason="path outside allowed glob",
        hint={"glob": "/workspace/**"},
    )
    console = Console(record=True, width=100)
    console.print(_render_decision_panel(decision))
    rendered = console.export_text()

    # JSON shape — double quotes, no Python-dict syntax.
    assert '"glob": "/workspace/**"' in rendered
    assert "{'glob'" not in rendered


def test_drain_decisions_prints_only_deny_and_approval() -> None:
    """The deque drain helper consumes the whole queue but only prints
    panels for DENY / NEEDS_APPROVAL. ALLOWs are popped silently —
    leaving them in the deque across turns would mean the next turn
    suddenly sees old allows."""
    pending: deque[Decision] = deque(
        [
            _decision(DecisionOutcome.ALLOW, reason="silent"),
            _decision(DecisionOutcome.DENY, reason="visible deny"),
            _decision(DecisionOutcome.ALLOW, reason="silent again"),
            _decision(DecisionOutcome.NEEDS_APPROVAL, reason="visible approval"),
        ]
    )

    console = Console(record=True, width=100)
    _drain_decisions(console, pending)
    rendered = console.export_text()

    assert "visible deny" in rendered
    assert "visible approval" in rendered
    assert "silent" not in rendered
    # The deque must be empty after drain regardless of which entries
    # produced panels — otherwise the next turn would re-render them.
    assert len(pending) == 0


def test_drain_decisions_noop_on_empty_deque() -> None:
    """No decisions → no output. Empty turns (the agent answered without
    any tool call) must not print a stray panel separator."""
    pending: deque[Decision] = deque()
    console = Console(record=True, width=100)
    _drain_decisions(console, pending)
    assert console.export_text() == ""


# ---------------------------------------------------------------------------
# build_runtime — uvicorn-style module:attr spec
# ---------------------------------------------------------------------------


def _test_settings() -> Settings:
    """Minimal Settings instance for runtime tests."""
    return Settings(
        langfuse_public_key=None,
        langfuse_secret_key=None,
        langfuse_host="https://cloud.langfuse.com",
        model="openai:gpt-5.4",
        search_engine="linkup",
    )


def _write_fake_agent_module(tmp_path: Path, *, name: str) -> str:
    """Write a fake module exporting a minimal duck-typed agent, return its spec.

    The agent only needs ``.name``, ``.tools``, and ``.model`` for the
    AgentRuntime construction path (we don't actually invoke the
    runtime here)."""
    module_path = tmp_path / f"{name}.py"
    module_path.write_text(
        textwrap.dedent(
            f'''
            class _Agent:
                name = "{name}_inner"
                tools = []
                model = "openai:gpt-5.4"
            agent = _Agent()
            '''
        )
    )
    return f"{name}:agent"


def test_build_runtime_with_colon_routes_through_load_spec(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """An agent name containing ':' must hit the spec path and skip
    name-based resolution entirely — that's the whole point of the
    spec form (no YAML, no registry lookup)."""
    spec = _write_fake_agent_module(tmp_path, name="fake_spec_mod_a")
    monkeypatch.syspath_prepend(str(tmp_path))
    # Guard rail: load_agent must NOT fire on the spec path.
    monkeypatch.setattr(
        _common, "load_agent", lambda *a, **k: pytest.fail("load_agent was called")
    )
    monkeypatch.setattr(
        "hexgate.tracing.langfuse.get_langfuse_handler",
        lambda **kw: object(),
    )

    runtime = _common.build_runtime(
        _test_settings(),
        agent_name=spec,
        base_dir=tmp_path,
        model=None,
    )

    assert runtime.agent_source == "spec"
    # The runtime's agent_name comes from the loaded object's .name attr,
    # not the spec string — preserves whatever the user declared.
    assert runtime.agent_name == "fake_spec_mod_a_inner"


def test_build_runtime_without_colon_uses_name_resolver(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """No colon → existing name-resolution path. Mirror of the above
    so a future refactor can't accidentally swap the dispatch."""
    spec_loader_called = False

    def fail_load_spec(*_a, **_k):
        nonlocal spec_loader_called
        spec_loader_called = True
        raise AssertionError("load_spec was called on a plain id")

    monkeypatch.setattr(_common, "load_spec", fail_load_spec)
    monkeypatch.setattr(
        _common,
        "load_agent",
        lambda *a, **k: (object(), object()),
    )
    monkeypatch.setattr(_common, "resolve_agent_source", lambda *a, **k: "local")

    _common.build_runtime(
        _test_settings(),
        agent_name="just_a_name",
        base_dir=tmp_path,
        model=None,
    )
    assert spec_loader_called is False


def test_build_runtime_from_spec_attaches_decision_observer(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The spec path threads decision_observer through the same in-place
    injector C2 wired up for registered agents. Without this, chat with
    --agent module:attr would silently drop the observer and the REPL
    would render no decision panels."""
    spec = _write_fake_agent_module(tmp_path, name="fake_spec_mod_b")
    monkeypatch.syspath_prepend(str(tmp_path))
    monkeypatch.setattr(
        "hexgate.tracing.langfuse.get_langfuse_handler",
        lambda **kw: object(),
    )

    # Spy on the injector. Don't care about the return — we only want
    # to assert it was called with our observer.
    seen: dict = {}

    def spy_apply(agent, observer):
        seen["agent"] = agent
        seen["observer"] = observer

    # Patch on the loader module (where build_runtime_from_spec imports it).
    from hexgate.agents import loader as loader_mod

    monkeypatch.setattr(loader_mod, "_apply_decision_observer", spy_apply)

    sentinel = lambda _d: None  # noqa: E731

    _common.build_runtime(
        _test_settings(),
        agent_name=spec,
        base_dir=tmp_path,
        model=None,
        decision_observer=sentinel,
    )
    assert seen.get("observer") is sentinel
    assert getattr(seen.get("agent"), "name", None) == "fake_spec_mod_b_inner"


def test_build_runtime_from_spec_omits_observer_call_when_none(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Default ``decision_observer=None`` must NOT call the injector —
    otherwise the empty-injector path would log a 'no GuardedTool tools
    to attach to' warning on every spec-based chat startup."""
    spec = _write_fake_agent_module(tmp_path, name="fake_spec_mod_c")
    monkeypatch.syspath_prepend(str(tmp_path))
    monkeypatch.setattr(
        "hexgate.tracing.langfuse.get_langfuse_handler",
        lambda **kw: object(),
    )

    from hexgate.agents import loader as loader_mod

    monkeypatch.setattr(
        loader_mod,
        "_apply_decision_observer",
        lambda *_a, **_k: pytest.fail("_apply_decision_observer should not fire"),
    )

    _common.build_runtime(
        _test_settings(),
        agent_name=spec,
        base_dir=tmp_path,
        model=None,
    )


def test_build_runtime_from_spec_falls_back_to_settings_model(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """If the spec'd agent doesn't carry a ``.model`` attr, the runtime
    falls back to settings.model so the welcome banner has something
    sensible to print."""
    module_path = tmp_path / "fake_modelless.py"
    module_path.write_text(
        textwrap.dedent(
            """
            class _Agent:
                name = "modelless_inner"
                tools = []
            agent = _Agent()
            """
        )
    )
    monkeypatch.syspath_prepend(str(tmp_path))
    monkeypatch.setattr(
        "hexgate.tracing.langfuse.get_langfuse_handler",
        lambda **kw: object(),
    )

    runtime = _common.build_runtime(
        _test_settings(),
        agent_name="fake_modelless:agent",
        base_dir=tmp_path,
        model=None,
    )
    assert runtime.model == "openai:gpt-5.4"


# ---------------------------------------------------------------------------
# loader._apply_decision_observer — invariant & warning paths
# (private helper, exercised here because chat is its main consumer)
# ---------------------------------------------------------------------------


class _FakeEnforcer:
    """Stand-in for PolicyEnforcer — only needs ``_decision_observer``
    as a settable attribute, which is what the helper writes to."""

    def __init__(self) -> None:
        self._decision_observer = None


class _FakeGuardedTool:
    """Duck-typed GuardedTool. We monkeypatch the helper's GuardedTool
    isinstance check so this stands in for the real thing without us
    having to construct a real LangChain BaseTool."""

    def __init__(self, enforcer: _FakeEnforcer) -> None:
        self.enforcer = enforcer


class _FakeAgent:
    def __init__(self, tools: list[object], *, name: str = "fake") -> None:
        self.tools = tools
        self.name = name


def _stub_guarded_tool(monkeypatch: pytest.MonkeyPatch) -> None:
    """Replace the helper's GuardedTool import target with our fake
    so isinstance() lights up on our stand-in."""
    import hexgate.adapters.langchain.tools as tools_mod

    monkeypatch.setattr(tools_mod, "GuardedTool", _FakeGuardedTool)


def test_apply_decision_observer_patches_all_tools_sharing_one_enforcer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Today's invariant: every GuardedTool on an agent shares one
    enforcer. The patch must land on that shared instance — verified
    via id() identity, not just attribute equality."""
    _stub_guarded_tool(monkeypatch)
    shared = _FakeEnforcer()
    agent = _FakeAgent([_FakeGuardedTool(shared), _FakeGuardedTool(shared)])

    sentinel = lambda _d: None  # noqa: E731

    _apply_decision_observer(agent, sentinel)
    assert shared._decision_observer is sentinel
    # Both tools' enforcer attrs point at the same object — the assertion
    # above is the meaningful one; this just pins the invariant.
    assert agent.tools[0].enforcer is agent.tools[1].enforcer


def test_apply_decision_observer_warns_when_no_guarded_tools(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """If no tool on the agent is a GuardedTool (e.g. a non-LangChain
    registered factory), the helper warns rather than silently no-op'ing
    — otherwise the dev never finds out their observer never fires."""
    _stub_guarded_tool(monkeypatch)
    agent = _FakeAgent(tools=["just_a_string_not_a_tool"])

    with caplog.at_level(logging.WARNING, logger="hexgate.agents.loader"):
        _apply_decision_observer(agent, lambda _d: None)

    assert any("no GuardedTool tools" in r.message for r in caplog.records)


def test_apply_decision_observer_warns_when_multiple_distinct_enforcers(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Defensive: if a future refactor builds per-tool enforcers (instead
    of the current one-shared-enforcer-per-agent invariant), all are
    patched AND a warning surfaces the unusual shape. Without this, a
    silent regression would mean some tool calls bypass the observer."""
    _stub_guarded_tool(monkeypatch)
    enforcer_a = _FakeEnforcer()
    enforcer_b = _FakeEnforcer()
    agent = _FakeAgent([_FakeGuardedTool(enforcer_a), _FakeGuardedTool(enforcer_b)])

    sentinel = lambda _d: None  # noqa: E731

    with caplog.at_level(logging.WARNING, logger="hexgate.agents.loader"):
        _apply_decision_observer(agent, sentinel)

    # Both enforcers got the patch — that's the load-bearing assertion.
    assert enforcer_a._decision_observer is sentinel
    assert enforcer_b._decision_observer is sentinel
    # And the surprise was logged.
    assert any("distinct enforcer instances" in r.message for r in caplog.records)
