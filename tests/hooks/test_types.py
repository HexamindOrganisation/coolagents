"""Tests for the guard decorators and the pipeline split."""

from __future__ import annotations

import pytest

from hexgate.hooks import after_tool, before_tool, build_pipeline
from hexgate.hooks.types import Hook, ToolPipeline


def _fn(call):  # noqa: ANN001, ANN202 - test stub
    return None


def _post(call, out):  # noqa: ANN001, ANN202 - test stub
    return None


def test_before_tool_bare_defaults() -> None:
    h = before_tool(_fn)
    assert isinstance(h, Hook)
    assert h.position == "pre"
    assert h.tool_names is None
    assert h.observe is False


def test_after_tool_bare_is_post() -> None:
    assert after_tool(_post).position == "post"


def test_called_form_scopes_and_flags() -> None:
    h = before_tool(tool_names=["a", "b"], observe=True)(_fn)
    assert h.position == "pre"
    assert h.tool_names == frozenset({"a", "b"})
    assert h.observe is True


def test_tool_names_accepts_a_bare_string() -> None:
    assert before_tool(tool_names="refund_order")(_fn).tool_names == frozenset(
        {"refund_order"}
    )


def test_applies_reflects_scope() -> None:
    scoped = before_tool(tool_names="x")(_fn)
    assert scoped.applies("x") is True
    assert scoped.applies("y") is False
    assert before_tool(_fn).applies("anything") is True


def test_decorated_guard_stays_callable() -> None:
    assert before_tool(lambda call: "ran")("call") == "ran"


def test_label() -> None:
    assert before_tool(_fn).label == "_fn"
    assert before_tool(lambda call: None).label == "<lambda>"


def test_build_pipeline_splits_and_preserves_order() -> None:
    p1, p2, q1 = before_tool(_fn), before_tool(_fn), after_tool(_post)
    pipe = build_pipeline([p1, q1, p2])
    assert isinstance(pipe, ToolPipeline)
    assert pipe.pre == (p1, p2)
    assert pipe.post == (q1,)


def test_build_pipeline_none_and_empty_are_none() -> None:
    assert build_pipeline(None) is None
    assert build_pipeline([]) is None


def test_build_pipeline_keeps_an_observer_even_when_empty() -> None:
    pipe = build_pipeline([], observer=lambda e: None)
    assert pipe is not None and pipe.is_empty


def test_build_pipeline_none_and_empty_behave_the_same_with_an_observer() -> None:
    """hooks=None must not silently drop an observer that hooks=[] would keep."""
    obs = lambda e: None  # noqa: E731
    assert build_pipeline(None, observer=obs) is not None
    assert build_pipeline([], observer=obs) is not None


def test_build_pipeline_rejects_an_undecorated_callable() -> None:
    with pytest.raises(TypeError, match="not a guard"):
        build_pipeline([lambda call: None])


def test_positional_string_raises_with_a_tool_names_hint() -> None:
    """A bare string positionally is a natural mistake; fail at decoration time."""
    with pytest.raises(TypeError, match="tool_names"):
        before_tool("refund_order")
    with pytest.raises(TypeError, match="tool_names"):
        after_tool("refund_order")


def test_non_callable_guard_raises() -> None:
    with pytest.raises(TypeError, match="callable"):
        before_tool(42)
