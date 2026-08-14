"""Tests for hexgate_api.query_scope — the shared window/scope helpers
reused by audit/service.py and llm_invocations/service.py."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from hexgate_api.query_scope import (
    CLOCK_SKEW_FUTURE,
    RETENTION_WINDOW,
    EventOutOfWindow,
    prepare_date_range,
    scope_filters,
    validate_event_window,
)

# ---------------------------------------------------------------------------
# validate_event_window()
# ---------------------------------------------------------------------------


def _now() -> datetime:
    return datetime.now(timezone.utc)


def test_validate_event_window_happy_path() -> None:
    validate_event_window(_now())  # no raise


def test_when_occurred_at_is_in_the_future_then_event_out_of_window_is_raised() -> None:
    with pytest.raises(EventOutOfWindow, match="future"):
        validate_event_window(_now() + CLOCK_SKEW_FUTURE + timedelta(minutes=1))


def test_when_occurred_at_is_older_than_retention_then_event_out_of_window_is_raised() -> (
    None
):
    with pytest.raises(EventOutOfWindow, match="retention"):
        validate_event_window(_now() - RETENTION_WINDOW - timedelta(days=1))


# ---------------------------------------------------------------------------
# scope_filters() — base project/window/agent WHERE builder
# ---------------------------------------------------------------------------

_BASE_WHERE = [
    "project_id = {pid:String}",
    "occurred_at >= {since:DateTime}",
]

_CUTOFF_TOLERANCE = timedelta(seconds=5)


def _assert_cutoff(params: dict, since_hours: int) -> None:
    """The cutoff sits ~``since_hours`` before now, stamped from the wall clock."""
    expected = _now() - timedelta(hours=since_hours)
    assert abs(params["since"] - expected) < _CUTOFF_TOLERANCE


def test_scope_filters_no_filters() -> None:
    where, params = scope_filters("p1", 24)
    assert where == _BASE_WHERE
    assert set(params) == {"pid", "since"}
    assert params["pid"] == "p1"
    _assert_cutoff(params, 24)


def test_scope_filters_agent_only() -> None:
    where, params = scope_filters("p1", 24, agent="example_agent")
    assert where == _BASE_WHERE + ["agent_name = {agent:String}"]
    assert set(params) == {"pid", "since", "agent"}
    assert params["agent"] == "example_agent"


def test_scope_filters_binds_the_window_instead_of_calling_now() -> None:
    """ClickHouse evaluates now() per query, so a scope reused for two queries
    would silently describe two different slices."""
    where, params = scope_filters("p1", 24)
    assert not any("now()" in clause for clause in where)
    assert isinstance(params["since"], datetime)
    assert params["since"].tzinfo is not None


_START = datetime(2025, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
_END = datetime(2025, 1, 7, 23, 59, 59, tzinfo=timezone.utc)


def test_scope_filters_appends_date_range_clause_when_both_dates_provided() -> None:
    where, params = scope_filters("p1", 24, start_date=_START, end_date=_END)
    assert where == [
        "project_id = {pid:String}",
        "occurred_at >= {start_date:DateTime} AND occurred_at <= {end_date:DateTime}",
    ]
    assert params == {"pid": "p1", "start_date": _START, "end_date": _END}


def test_scope_filters_falls_back_to_since_hours_when_one_date_missing() -> None:
    where, params = scope_filters("p1", 24, start_date=_START)
    assert where == _BASE_WHERE
    assert "start_date" not in params and "end_date" not in params


def test_scope_filters_falls_back_to_since_hours_when_start_date_is_after_end_date() -> (
    None
):
    where, params = scope_filters("p1", 24, start_date=_END, end_date=_START)
    assert where == _BASE_WHERE
    assert "start_date" not in params and "end_date" not in params


# ---------------------------------------------------------------------------
# prepare_date_range() — UTC normalization + 90-day retention clamping
# ---------------------------------------------------------------------------


def test_when_both_inputs_are_none_then_returns_none_none() -> None:
    assert prepare_date_range(None, None) == (None, None)


def test_when_naive_datetimes_provided_then_utc_is_attached() -> None:
    naive_start = datetime(2025, 1, 1)
    naive_end = datetime(2025, 1, 2)
    start, end = prepare_date_range(naive_start, naive_end)
    assert start.tzinfo is not None and end.tzinfo is not None


def test_when_window_exceeds_90d_then_start_date_is_clamped_to_end_minus_retention() -> (
    None
):
    far_start = _END - timedelta(days=200)
    start, _ = prepare_date_range(far_start, _END)
    assert start == _END - RETENTION_WINDOW


def test_when_end_date_is_in_the_future_then_end_date_is_clamped_to_now() -> None:
    future_end = _now() + timedelta(days=5)
    _, end = prepare_date_range(None, future_end)
    assert end <= _now() + CLOCK_SKEW_FUTURE
