"""coerce.py — proto-typed attribute values → event field types."""

from __future__ import annotations

import pytest

from hexgate_api.jobs.enricher.coerce import (
    SpanRejected,
    as_int,
    as_json_dict,
    as_str,
    as_str_list,
    required,
)


def test_as_int_happy_path() -> None:
    assert as_int(42, key="k", scope="s") == 42


def test_when_int_arrives_as_string_then_coerced() -> None:
    assert as_int("42", key="k", scope="s") == 42


def test_when_int_is_not_coercible_then_span_rejected() -> None:
    with pytest.raises(SpanRejected) as exc:
        as_int("not-a-number", key="k", scope="s")
    assert exc.value.error_class == "validation"


def test_when_int_is_a_bool_then_span_rejected() -> None:
    with pytest.raises(SpanRejected):
        as_int(True, key="k", scope="s")


def test_as_str_list_happy_path() -> None:
    assert as_str_list(["a", "b"], key="k", scope="s") == ["a", "b"]


def test_when_list_arrives_as_json_string_then_coerced() -> None:
    assert as_str_list('["a", "b"]', key="k", scope="s") == ["a", "b"]


def test_when_list_arrives_as_scalar_then_wrapped() -> None:
    assert as_str_list("admin", key="k", scope="s") == ["admin"]


def test_when_list_is_missing_then_empty() -> None:
    assert as_str_list(None, key="k", scope="s") == []


def test_as_json_dict_happy_path() -> None:
    assert as_json_dict('{"a": 1}', key="k", scope="s") == {"a": 1}


def test_when_json_is_invalid_then_span_rejected() -> None:
    with pytest.raises(SpanRejected):
        as_json_dict("{not json", key="k", scope="s")


def test_when_json_is_not_an_object_then_span_rejected() -> None:
    with pytest.raises(SpanRejected):
        as_json_dict("[1, 2]", key="k", scope="s")


def test_when_dict_arrives_as_kvlist_then_accepted() -> None:
    assert as_json_dict({"a": 1}, key="k", scope="s") == {"a": 1}


def test_when_required_attribute_is_missing_then_span_rejected() -> None:
    with pytest.raises(SpanRejected) as exc:
        required({}, "sec_ai.event_id", scope="s")
    assert "sec_ai.event_id" in exc.value.error


def test_as_str_stringifies_with_default() -> None:
    assert as_str(None) == ""
    assert as_str(None, default="x") == "x"
    assert as_str(7) == "7"
