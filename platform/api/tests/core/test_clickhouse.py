"""Unit tests for the shared batch-insert helper in core/clickhouse.py."""

from unittest.mock import MagicMock

from hexgate_api.core.clickhouse import BATCH_INSERT_SETTINGS, insert_batch


def _row(event: dict, *, project_id: str, agent_version_id: str) -> list:
    return [event["id"], project_id, agent_version_id]


def test_insert_batch_builds_rows_and_pins_synchronous_insert() -> None:
    client = MagicMock()
    items = [({"id": "e1"}, "proj_a", "ver_1"), ({"id": "e2"}, "proj_b", "ver_2")]

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
