"""Tests for :class:`MCPServerConfig` validation + qualified-name helper."""

from __future__ import annotations

import pytest

from hexgate.mcp import MCPServerConfig, MCPServerConfigError

# ---- name validation -------------------------------------------------------


@pytest.mark.parametrize(
    "bad_name",
    [
        "",  # empty
        "SLACK",  # uppercase
        "slack_server",  # underscore not allowed (kept separator unambiguous)
        "slack.server",  # dot
        "a" * 33,  # too long
        "🚀",  # non-ascii
        "slack/server",  # slash
    ],
)
def test_rejects_invalid_server_name(bad_name: str) -> None:
    with pytest.raises(MCPServerConfigError, match="must match"):
        MCPServerConfig(name=bad_name, transport="stdio", command="x")


@pytest.mark.parametrize(
    "good_name",
    [
        "slack",
        "github",
        "s",
        "a-b-c-1-2-3",
        "x" * 32,  # max length
    ],
)
def test_accepts_valid_server_name(good_name: str) -> None:
    # Must not raise.
    MCPServerConfig(name=good_name, transport="stdio", command="x")


# ---- transport validation --------------------------------------------------


def test_stdio_requires_command() -> None:
    with pytest.raises(MCPServerConfigError, match="requires `command`"):
        MCPServerConfig(name="slack", transport="stdio")


def test_stdio_rejects_url() -> None:
    with pytest.raises(MCPServerConfigError, match="takes `command`"):
        MCPServerConfig(name="slack", transport="stdio", command="x", url="y")


def test_http_requires_url() -> None:
    with pytest.raises(MCPServerConfigError, match="requires `url`"):
        MCPServerConfig(name="slack", transport="http")


def test_http_rejects_command() -> None:
    with pytest.raises(MCPServerConfigError, match="takes `url`"):
        MCPServerConfig(name="slack", transport="http", url="x", command="y")


def test_rejects_unknown_transport() -> None:
    with pytest.raises(MCPServerConfigError, match="unknown transport"):
        MCPServerConfig(name="slack", transport="smtp", command="x")  # type: ignore[arg-type]


# ---- qualified_tool_name ---------------------------------------------------


def test_qualified_tool_name_uses_hyphen_separator() -> None:
    """OpenAI Function Calling rejects ``:`` in tool names — hyphens are the
    safest separator that's valid across OpenAI + Anthropic schemas."""
    cfg = MCPServerConfig(name="slack", transport="stdio", command="x")
    assert cfg.qualified_tool_name("send_message") == "mcp-slack-send_message"


def test_qualified_tool_name_preserves_inner_underscores() -> None:
    """Snake-case is MCP's recommended tool-name convention; we don't rewrite it."""
    cfg = MCPServerConfig(name="gh", transport="stdio", command="x")
    assert (
        cfg.qualified_tool_name("create_pull_request") == "mcp-gh-create_pull_request"
    )


# ---- env semantics ---------------------------------------------------------


def test_env_defaults_to_none_meaning_inherit() -> None:
    """Default ``env=None`` means inherit the parent process env (the SDK
    default). ``env={}`` is the explicit sandbox-empty value — they MUST
    be distinguishable so a caller setting ``env={}`` for sandboxing
    doesn't silently get full parent-env inheritance (was finding #3)."""
    inherit = MCPServerConfig(name="x", transport="stdio", command="srv")
    empty = MCPServerConfig(name="x", transport="stdio", command="srv", env={})
    explicit = MCPServerConfig(
        name="x", transport="stdio", command="srv", env={"TOKEN": "abc"}
    )
    assert inherit.env is None
    assert empty.env == {}
    assert explicit.env == {"TOKEN": "abc"}


# ---- call_timeout_seconds --------------------------------------------------


def test_call_timeout_has_a_sensible_default() -> None:
    """A wedged MCP server must not stall the agent indefinitely (was
    finding #5). 30s is generous for network/disk tools and short enough
    for the agent loop to recover within one retry budget."""
    cfg = MCPServerConfig(name="x", transport="stdio", command="srv")
    assert cfg.call_timeout_seconds == 30.0


def test_call_timeout_can_be_disabled_explicitly() -> None:
    cfg = MCPServerConfig(
        name="x", transport="stdio", command="srv", call_timeout_seconds=None
    )
    assert cfg.call_timeout_seconds is None


def test_call_timeout_can_be_overridden() -> None:
    cfg = MCPServerConfig(
        name="x", transport="stdio", command="srv", call_timeout_seconds=5.0
    )
    assert cfg.call_timeout_seconds == 5.0
