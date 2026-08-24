"""Attribute-value coercion for decoded OTLP spans.

Generic plumbing shared by the per-scope builders in mapping.py: attempt
type conversion when a span attribute's proto type doesn't match what the
event field expects (string→int, JSON-string→list/dict, …), log every lossy
coercion, and reject — via :class:`SpanRejected` — only when coercion fails
or a required attribute is missing. Nothing here knows the event types;
that's mapping.py's job.
"""

from __future__ import annotations

import json
import logging
from typing import Any

_log = logging.getLogger(__name__)


class SpanRejected(Exception):
    """This span cannot become an event — permanently (DLQ, not retry)."""

    def __init__(self, error: str, *, error_class: str, scope: str) -> None:
        super().__init__(error)
        self.error = error
        self.error_class = error_class
        self.scope = scope


def required(attrs: dict[str, Any], key: str, *, scope: str) -> Any:
    value = attrs.get(key)
    if value is None:
        raise SpanRejected(
            f"missing required attribute {key}", error_class="validation", scope=scope
        )
    return value


def as_str(value: Any, default: str = "") -> str:
    if value is None:
        return default
    if isinstance(value, str):
        return value
    _log.warning("coerced non-string attribute %r to str", value)
    return str(value)


def as_int(value: Any, *, key: str, scope: str) -> int:
    if isinstance(value, bool):  # bool is an int subclass; never a count
        raise SpanRejected(
            f"{key} is a bool, expected int", error_class="validation", scope=scope
        )
    if isinstance(value, int):
        return value
    try:
        coerced = int(value)
    except (TypeError, ValueError):
        raise SpanRejected(
            f"{key}={value!r} is not coercible to int",
            error_class="validation",
            scope=scope,
        ) from None
    _log.warning("coerced %s=%r to int", key, value)
    return coerced


def as_str_list(value: Any, *, key: str, scope: str) -> list[str]:
    """Native string array preferred; a JSON-encoded array or a scalar string
    from a foreign emitter are accepted with a log line."""
    if value is None:
        return []
    if isinstance(value, list):
        return [as_str(v) for v in value]
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except ValueError:
            parsed = None
        if isinstance(parsed, list):
            _log.warning("coerced JSON-string %s to a list", key)
            return [as_str(v) for v in parsed]
        _log.warning("wrapped scalar %s=%r into a single-item list", key, value)
        return [value]
    raise SpanRejected(
        f"{key}={value!r} is not a string list", error_class="validation", scope=scope
    )


def as_json_dict(value: Any, *, key: str, scope: str) -> dict[str, Any] | None:
    """Dict payloads travel as JSON-string attributes (see semconv docstring);
    a kvlist already decoded to a dict is accepted with a log line."""
    if value is None:
        return None
    if isinstance(value, dict):
        _log.warning("accepted kvlist-shaped %s (expected a JSON string)", key)
        return value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except ValueError as exc:
            raise SpanRejected(
                f"{key} is not valid JSON: {exc}",
                error_class="validation",
                scope=scope,
            ) from None
        if not isinstance(parsed, dict):
            raise SpanRejected(
                f"{key} JSON is {type(parsed).__name__}, expected object",
                error_class="validation",
                scope=scope,
            )
        return parsed
    raise SpanRejected(
        f"{key}={value!r} is not a JSON-string dict",
        error_class="validation",
        scope=scope,
    )
