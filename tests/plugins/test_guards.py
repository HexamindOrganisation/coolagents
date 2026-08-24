"""Behavior of the three official guards, both called directly and routed through
the shared runner (proving they drop into a real ``guards=`` pipeline)."""

from __future__ import annotations

import logging
from types import MappingProxyType

import pytest

from hexgate.guards import Halt, Proceed, ToolCall, ToolOutcome, build_pipeline
from hexgate.guards.runner import run_guarded_sync
from hexgate.plugins import secret_guard, secret_redactor, secret_watch
from tests.guards.helpers import FakeEnforcer, RecordingInvoke, langchain_error

_SECRET = "AKIAIOSFODNN7EXAMPLE"


def _call(**args) -> ToolCall:
    return ToolCall(tool_name="send", args=MappingProxyType(dict(args)))


# ---------------------------------------------------------------------------
# secret_guard — refuse
# ---------------------------------------------------------------------------


def test_secret_guard_passes_clean_args() -> None:
    assert secret_guard(_call(to="bob@example.com", body="hi")) is None


def test_secret_guard_halts_on_a_secret_without_leaking_it() -> None:
    result = secret_guard(_call(body=f"the key is {_SECRET}"))
    assert isinstance(result, Halt)
    assert "aws_access_key" in result.reason and "`body`" in result.reason
    assert _SECRET not in result.reason  # names the category, never the value


# ---------------------------------------------------------------------------
# secret_redactor — strip and proceed
# ---------------------------------------------------------------------------


def test_secret_redactor_passes_clean_args() -> None:
    assert secret_redactor(_call(body="nothing here")) is None


def test_secret_redactor_strips_the_secret_and_records_a_modification() -> None:
    result = secret_redactor(_call(auth={"token": _SECRET}, keep="me"))
    assert isinstance(result, Proceed)
    assert result.args == {"auth": {"token": "[REDACTED:aws_access_key]"}, "keep": "me"}
    assert result.modification is not None
    assert result.modification.plugin == "secret_redactor"
    assert "redacted 1" in result.modification.summary
    assert _SECRET not in result.modification.summary


# ---------------------------------------------------------------------------
# secret_watch — observe (log), never change the result
# ---------------------------------------------------------------------------


def test_secret_watch_is_observe_and_never_returns_an_action() -> None:
    assert secret_watch.observe is True
    out = ToolOutcome(ok=True, value={"leaked": _SECRET})
    assert secret_watch(_call(), out) is None


def test_secret_watch_logs_a_value_free_warning_on_a_leaked_result(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.WARNING, logger="hexgate.plugins.secrets"):
        secret_watch(_call(), ToolOutcome(ok=True, value={"leaked": _SECRET}))
    assert "secret_watch" in caplog.text and "aws_access_key" in caplog.text
    assert _SECRET not in caplog.text


def test_secret_watch_is_silent_on_clean_and_failed_results(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.WARNING, logger="hexgate.plugins.secrets"):
        secret_watch(_call(), ToolOutcome(ok=True, value={"ok": "clean"}))
        secret_watch(_call(), ToolOutcome(ok=False, error="boom"))
    assert caplog.text == ""


# ---------------------------------------------------------------------------
# End-to-end through the shared runner
# ---------------------------------------------------------------------------


def test_secret_guard_blocks_the_call_through_the_pipeline() -> None:
    enf, inv = FakeEnforcer(), RecordingInvoke("ran")
    pipe = build_pipeline([secret_guard])
    out = run_guarded_sync(
        "send",
        {"body": f"key {_SECRET}"},
        enforcer=enf,
        pipeline=pipe,
        approval_handler=None,
        invoke=inv.sync,
        render_error=langchain_error,
    )
    assert out["ok"] is False  # rendered as a blocked decision
    assert inv.calls == []  # the tool never ran
    assert _SECRET not in str(out)  # the value never reaches the model


def test_secret_redactor_hands_the_tool_cleaned_args_through_the_pipeline() -> None:
    enf, inv = FakeEnforcer(), RecordingInvoke("ran")
    pipe = build_pipeline([secret_redactor])
    run_guarded_sync(
        "send",
        {"auth": {"token": _SECRET}},
        enforcer=enf,
        pipeline=pipe,
        approval_handler=None,
        invoke=inv.sync,
        render_error=langchain_error,
    )
    assert inv.calls == [{"auth": {"token": "[REDACTED:aws_access_key]"}}]
    assert enf.seen_args == {"auth": {"token": "[REDACTED:aws_access_key]"}}
