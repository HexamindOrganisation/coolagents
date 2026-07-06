"""Tests for custom agent tools."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from hexgate.agents.factory import create_agent, invoke_agent
from hexgate.runtime import (
    LocalWorkspace,
    ToolUseContext,
    reset_current_tool_use_context,
    set_current_tool_use_context,
)
from hexgate.tools import bash, edit_file, glob, grep, read_file, write_file
from hexgate.tools.decorators import format_tool_call_label
from hexgate.tools import agent_tool


def test_format_tool_call_label_defaults_to_tool_name() -> None:
    """Fall back to the tool name when no custom formatter is attached."""

    class PlainTool:
        """Provide a tiny stand-in tool with only a name."""

        name = "plain_tool"

    assert format_tool_call_label(PlainTool(), {"foo": "bar"}) == "plain_tool"


def test_agent_tool_hides_tool_use_context_from_schema() -> None:
    """Keep the runtime meta-argument out of the model-visible tool schema."""

    @agent_tool(name="read_from_workspace")
    async def read_from_workspace(
        path: str,
        tool_use_context: ToolUseContext,
    ) -> dict[str, str]:
        """Read a file from the current workspace."""
        assert tool_use_context.workspace is not None
        return {"content": tool_use_context.workspace.read_text(path)}

    assert "tool_use_context" not in read_from_workspace.args
    assert "path" in read_from_workspace.args


@pytest.mark.asyncio
async def test_agent_tool_injects_tool_use_context_during_agent_run(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Inject runtime workspace context into tools without exposing it to the model."""
    workspace = LocalWorkspace(tmp_path)
    workspace.write_text("notes.txt", "hello from workspace")
    captured: dict[str, Any] = {}

    @agent_tool(name="read_from_workspace")
    async def read_from_workspace(
        path: str,
        tool_use_context: ToolUseContext,
    ) -> dict[str, str]:
        """Read a file from the current workspace."""
        assert tool_use_context.workspace is not None
        captured["workspace_root"] = str(tool_use_context.workspace.root_dir)
        return {"content": tool_use_context.workspace.read_text(path)}

    class FakeGraph:
        async def ainvoke(
            self, payload: dict[str, Any], *, config: dict[str, Any]
        ) -> dict[str, Any]:
            _ = payload
            _ = config
            tool_result = await read_from_workspace.ainvoke({"path": "notes.txt"})
            return {"messages": [tool_result["content"]]}

    monkeypatch.setattr(
        "hexgate.agents.factory.create_langchain_agent",
        lambda **_kwargs: FakeGraph(),
    )
    monkeypatch.setattr(
        "hexgate.agents.factory.get_langfuse_handler",
        lambda **_kwargs: "handler",
    )
    monkeypatch.setattr(
        "hexgate.agents.factory.get_langfuse_runnable_config",
        lambda _handler: {"callbacks": ["handler"]},
    )

    agent, handler = create_agent(
        model="openai:gpt-5.4",
        tools=[read_from_workspace],
        system_prompt="You are a file assistant.",
        name="file-agent",
    )

    result = await invoke_agent(
        agent,
        handler,
        "read the file",
        tool_use_context=ToolUseContext(workspace=workspace),
    )

    assert result == {"messages": ["hello from workspace"]}
    assert captured["workspace_root"] == str(tmp_path.resolve())


@pytest.mark.asyncio
async def test_agent_tool_defaults_to_local_workspace_during_run(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Default each run to a LocalWorkspace rooted at the current directory."""
    captured: dict[str, Any] = {}

    @agent_tool(name="inspect_workspace")
    async def inspect_workspace(tool_use_context: ToolUseContext) -> dict[str, str]:
        """Return the active workspace root."""
        assert tool_use_context.workspace is not None
        captured["workspace_root"] = str(tool_use_context.workspace.root_dir)
        return {"workspace_root": str(tool_use_context.workspace.root_dir)}

    class FakeGraph:
        async def ainvoke(
            self, payload: dict[str, Any], *, config: dict[str, Any]
        ) -> dict[str, Any]:
            _ = payload
            _ = config
            tool_result = await inspect_workspace.ainvoke({})
            return {"messages": [tool_result["workspace_root"]]}

    monkeypatch.setattr(
        "hexgate.agents.factory.create_langchain_agent",
        lambda **_kwargs: FakeGraph(),
    )
    monkeypatch.setattr(
        "hexgate.agents.factory.get_langfuse_handler",
        lambda **_kwargs: "handler",
    )
    monkeypatch.setattr(
        "hexgate.agents.factory.get_langfuse_runnable_config",
        lambda _handler: {"callbacks": ["handler"]},
    )
    monkeypatch.chdir(tmp_path)

    agent, handler = create_agent(
        model="openai:gpt-5.4",
        tools=[inspect_workspace],
        system_prompt="You are a file assistant.",
    )

    result = await invoke_agent(agent, handler, "inspect the workspace")

    assert result == {"messages": [str(tmp_path.resolve())]}
    assert captured["workspace_root"] == str(tmp_path.resolve())


def test_local_workspace_blocks_parent_directory_escape(tmp_path: Path) -> None:
    """Keep local workspace access scoped to its root directory."""
    workspace = LocalWorkspace(tmp_path)

    with pytest.raises(ValueError):
        workspace.resolve_path("../outside.txt")


@pytest.mark.asyncio
async def test_read_file_reads_from_workspace(tmp_path: Path) -> None:
    """Read a text file through the built-in workspace-backed tool."""
    workspace = LocalWorkspace(tmp_path)
    workspace.write_text("notes.txt", "hello\nworld")
    token = set_current_tool_use_context(ToolUseContext(workspace=workspace))
    try:
        result = await read_file.ainvoke({"file_path": "notes.txt"})
    finally:
        reset_current_tool_use_context(token)

    assert result == {
        "ok": True,
        "file_path": "notes.txt",
        "content": "hello\nworld",
        "num_lines": 2,
    }


@pytest.mark.asyncio
async def test_write_file_creates_and_updates_files(tmp_path: Path) -> None:
    """Create a new file and then overwrite it through the built-in tool."""
    workspace = LocalWorkspace(tmp_path)
    token = set_current_tool_use_context(ToolUseContext(workspace=workspace))
    try:
        created = await write_file.ainvoke(
            {
                "file_path": "draft.txt",
                "content": "first version",
            }
        )
        updated = await write_file.ainvoke(
            {
                "file_path": "draft.txt",
                "content": "second version",
            }
        )
    finally:
        reset_current_tool_use_context(token)

    assert created["ok"] is True
    assert created["operation"] == "create"
    assert updated["ok"] is True
    assert updated["operation"] == "update"
    assert workspace.read_text("draft.txt") == "second version"


@pytest.mark.asyncio
async def test_edit_file_replaces_exact_string(tmp_path: Path) -> None:
    """Edit a file by exact string replacement."""
    workspace = LocalWorkspace(tmp_path)
    workspace.write_text("draft.txt", "const x = 1\n")
    token = set_current_tool_use_context(ToolUseContext(workspace=workspace))
    try:
        result = await edit_file.ainvoke(
            {
                "file_path": "draft.txt",
                "old_string": "const x = 1",
                "new_string": "const x = 2",
            }
        )
    finally:
        reset_current_tool_use_context(token)

    assert result["ok"] is True
    assert result["num_replacements"] == 1
    assert workspace.read_text("draft.txt") == "const x = 2\n"


@pytest.mark.asyncio
async def test_edit_file_rejects_ambiguous_replacement(tmp_path: Path) -> None:
    """Reject multiple matches unless replace_all is explicitly enabled."""
    workspace = LocalWorkspace(tmp_path)
    workspace.write_text("draft.txt", "hello\nhello\n")
    token = set_current_tool_use_context(ToolUseContext(workspace=workspace))
    try:
        with pytest.raises(ValueError, match="multiple locations"):
            await edit_file.ainvoke(
                {
                    "file_path": "draft.txt",
                    "old_string": "hello",
                    "new_string": "hi",
                }
            )
    finally:
        reset_current_tool_use_context(token)


@pytest.mark.asyncio
async def test_glob_returns_relative_matches(tmp_path: Path) -> None:
    """Find files by glob pattern and return workspace-relative paths."""
    workspace = LocalWorkspace(tmp_path)
    workspace.write_text("src/a.py", "print('a')")
    workspace.write_text("src/b.py", "print('b')")
    workspace.write_text("src/c.txt", "ignore")
    token = set_current_tool_use_context(ToolUseContext(workspace=workspace))
    try:
        result = await glob.ainvoke({"pattern": "**/*.py"})
    finally:
        reset_current_tool_use_context(token)

    assert result == {
        "ok": True,
        "pattern": "**/*.py",
        "filenames": ["src/a.py", "src/b.py"],
        "num_files": 2,
        "truncated": False,
        "search_root": ".",
    }


@pytest.mark.asyncio
async def test_grep_supports_files_and_content_modes(tmp_path: Path) -> None:
    """Search file contents within the workspace and return structured results."""
    workspace = LocalWorkspace(tmp_path)
    workspace.write_text("src/a.py", "def alpha():\n    pass\n")
    workspace.write_text("src/b.py", "def beta():\n    pass\n")
    workspace.write_text("notes.txt", "alpha appears here too\n")
    token = set_current_tool_use_context(ToolUseContext(workspace=workspace))
    try:
        files_result = await grep.ainvoke(
            {
                "pattern": "alpha",
                "glob": "*.py",
            }
        )
        content_result = await grep.ainvoke(
            {
                "pattern": "def",
                "glob": "*.py",
                "output_mode": "content",
            }
        )
    finally:
        reset_current_tool_use_context(token)

    assert files_result == {
        "ok": True,
        "pattern": "alpha",
        "mode": "files_with_matches",
        "num_files": 1,
        "num_matches": 1,
        "filenames": ["src/a.py"],
        "truncated": False,
    }
    assert content_result["ok"] is True
    assert content_result["mode"] == "content"
    assert content_result["num_files"] == 2
    assert content_result["num_matches"] == 2
    assert "src/a.py:1:def alpha():" in content_result["content"]
    assert "src/b.py:1:def beta():" in content_result["content"]


@pytest.mark.asyncio
async def test_local_workspace_run_command_uses_workspace_cwd(
    tmp_path: Path, srt_required: None
) -> None:
    """Execute shell commands relative to the workspace root."""
    workspace = LocalWorkspace(tmp_path)

    result = await workspace.run_command("pwd")

    assert result.exit_code == 0
    assert result.stdout.strip() == str(tmp_path.resolve())
    assert result.stderr == ""


@pytest.mark.asyncio
async def test_local_workspace_run_command_preserves_nonzero_exit_code(
    tmp_path: Path, srt_required: None
) -> None:
    """Return non-zero shell exits as normal command results."""
    workspace = LocalWorkspace(tmp_path)

    result = await workspace.run_command("printf 'nope' >&2; exit 7")

    assert result.exit_code == 7
    assert result.stdout == ""
    assert result.stderr == "nope"


@pytest.mark.asyncio
async def test_local_workspace_run_command_times_out(
    tmp_path: Path, srt_required: None
) -> None:
    """Raise a clear timeout error for long-running commands."""
    workspace = LocalWorkspace(tmp_path)

    with pytest.raises(TimeoutError, match="Command timed out"):
        await workspace.run_command("sleep 1", timeout_seconds=0)


def test_bash_call_formatter_is_human_friendly() -> None:
    """Render bash calls with a shortened command preview."""
    assert format_tool_call_label(bash, {"command": "ls -la"}) == "running ls -la"
    assert format_tool_call_label(
        bash,
        {
            "command": (
                "python -m pytest tests/test_tools.py::test_grep_supports_files_and_content_modes"
            )
        },
    ).startswith("running python -m pytest")


@pytest.mark.asyncio
async def test_bash_tool_returns_command_result_for_nonzero_exit_code(
    tmp_path: Path, srt_required: None
) -> None:
    """Treat shell exit failures as tool output instead of tool errors."""
    workspace = LocalWorkspace(tmp_path)
    token = set_current_tool_use_context(ToolUseContext(workspace=workspace))
    try:
        result = await bash.ainvoke(
            {
                "command": "printf 'boom' >&2; exit 3",
            }
        )
    finally:
        reset_current_tool_use_context(token)

    assert result == {
        "ok": True,
        "command": "printf 'boom' >&2; exit 3",
        "exit_code": 3,
        "stdout": "",
        "stderr": "boom",
        "stdout_truncated": False,
        "stderr_truncated": False,
        "policy_violation": False,
    }


@pytest.mark.asyncio
async def test_bash_tool_returns_structured_timeout_error(
    tmp_path: Path, srt_required: None
) -> None:
    """Surface command timeouts as tool failures."""
    workspace = LocalWorkspace(tmp_path)
    token = set_current_tool_use_context(ToolUseContext(workspace=workspace))
    try:
        result = await bash.ainvoke(
            {
                "command": "sleep 1",
                "timeout_seconds": 0,
            }
        )
    finally:
        reset_current_tool_use_context(token)

    assert result["ok"] is False
    assert result["error"]["type"] == "TimeoutError"
