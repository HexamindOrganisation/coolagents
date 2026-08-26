"""Unit tests for the shared batch-insert and schema-guard helpers in
core/clickhouse.py."""

from unittest.mock import MagicMock

import pytest

from hexgate_api.core.clickhouse import (
    BATCH_INSERT_SETTINGS,
    BatchItem,
    SchemaOutOfDate,
    insert_batch,
    verify_all,
)


def _row(event: dict, *, project_id: str, agent_version_id: str) -> list:
    return [event["id"], project_id, agent_version_id]


def test_insert_batch_builds_rows_and_pins_synchronous_insert() -> None:
    client = MagicMock()
    items = [
        BatchItem({"id": "e1"}, project_id="proj_a", agent_version_id="ver_1"),
        BatchItem({"id": "e2"}, project_id="proj_b", agent_version_id="ver_2"),
    ]

    insert_batch(client, "some_table", ["event_id", "project_id", "agent"], _row, items)

    client.insert.assert_called_once()
    args, kwargs = client.insert.call_args
    assert args[0] == "some_table"
    assert args[1] == [["e1", "proj_a", "ver_1"], ["e2", "proj_b", "ver_2"]]
    assert kwargs["column_names"] == ["event_id", "project_id", "agent"]
    # The one place the batch contract is pinned; every insert_*_batch inherits it.
    assert kwargs["settings"] == BATCH_INSERT_SETTINGS == {"async_insert": 0}


def test_insert_batch_with_no_items_never_touches_clickhouse() -> None:
    client = MagicMock()
    insert_batch(client, "some_table", ["event_id"], _row, [])
    client.insert.assert_not_called()


def test_batch_item_refuses_positional_ids() -> None:
    """The whole point of BatchItem over a bare tuple: two adjacent str ids
    can't be silently transposed, because they can't be passed positionally."""
    with pytest.raises(TypeError):
        BatchItem({"id": "e1"}, "proj_a", "ver_1")  # type: ignore[misc]


# ---------------------------------------------------------------------------
# verify_all() — one boot reports every feature's schema gaps
# ---------------------------------------------------------------------------


def _stale(missing: dict[str, list[str]]):
    def check(_client) -> None:
        raise SchemaOutOfDate(missing)

    return check


def test_verify_all_happy_path() -> None:
    first, second = MagicMock(), MagicMock()

    verify_all(MagicMock(), (first, second))  # no raise

    first.assert_called_once()
    second.assert_called_once()


def test_when_two_features_are_stale_then_every_gap_is_reported_at_once() -> None:
    """The reason this exists: sequential checks would stop at the audit
    gaps, and the llm gap would only surface on the boot after migrating."""
    with pytest.raises(SchemaOutOfDate) as exc:
        verify_all(
            MagicMock(),
            (
                _stale({"policy_decision": ["user_roles"]}),
                _stale({"llm_invocation": ["output_tokens"]}),
            ),
        )
    assert exc.value.missing == {
        "policy_decision": ["user_roles"],
        "llm_invocation": ["output_tokens"],
    }


def test_when_one_feature_is_stale_then_the_others_still_run() -> None:
    later = MagicMock()

    with pytest.raises(SchemaOutOfDate):
        verify_all(MagicMock(), (_stale({"policy_decision": ["user_roles"]}), later))

    later.assert_called_once()


def test_when_a_check_fails_for_another_reason_then_it_is_not_swallowed() -> None:
    """Unreachable/denied schemas are already downgraded to warnings inside
    the wrappers; anything else escaping is a bug, not a schema gap."""

    def broken(_client) -> None:
        raise RuntimeError("boom")

    with pytest.raises(RuntimeError):
        verify_all(MagicMock(), (broken,))
