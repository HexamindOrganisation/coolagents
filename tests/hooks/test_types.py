"""Tests for the hook type layer: pipeline coercion, flags, labels."""

from __future__ import annotations

from hexgate.hooks.types import Hook, ToolPipeline, observe


def _hook_fn(call):  # noqa: ANN001, ANN202 - test stub
    return None


def test_bare_callable_is_coerced_to_a_default_hook() -> None:
    pipe = ToolPipeline(pre=[_hook_fn])
    assert isinstance(pipe.pre[0], Hook)
    assert pipe.pre[0].observe_only is False
    assert pipe.pre[0].matches is None


def test_existing_hook_passes_through_uncoerced() -> None:
    h = Hook(_hook_fn, observe_only=True)
    pipe = ToolPipeline(pre=[h])
    assert pipe.pre[0] is h


def test_observe_marks_a_hook_fail_open() -> None:
    h = observe(_hook_fn)
    assert h.observe_only is True
    assert h.fn is _hook_fn


def test_hook_label_uses_function_name() -> None:
    assert Hook(_hook_fn).label == "_hook_fn"
    assert Hook(lambda call: None).label == "<lambda>"


def test_is_empty_reflects_registered_hooks() -> None:
    assert ToolPipeline().is_empty is True
    assert ToolPipeline(pre=[_hook_fn]).is_empty is False
    assert ToolPipeline(post=[_hook_fn]).is_empty is False


def test_matches_predicate_is_carried() -> None:
    h = Hook(_hook_fn, matches=lambda name: name.startswith("x"))
    assert h.matches is not None
    assert h.matches("x_tool") is True
    assert h.matches("y_tool") is False
