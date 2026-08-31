"""__main__.py — exit codes a supervisor can act on."""

from __future__ import annotations

import pytest

from hexgate_api.core.clickhouse import SchemaOutOfDate
from hexgate_api.jobs.enricher import __main__ as entry
from hexgate_api.jobs.enricher.consumer import TopicsMissing


@pytest.mark.parametrize(
    "failure",
    [SchemaOutOfDate({"policy_decision": ["x"]}), TopicsMissing(["t"])],
)
def test_when_a_startup_check_fails_then_exit_code_is_1(monkeypatch, failure) -> None:
    async def _run(self):
        raise failure

    monkeypatch.setattr(entry.EnricherJob, "run", _run)
    assert entry.main() == 1


def test_main_happy_path_exits_0(monkeypatch) -> None:
    async def _run(self):
        return None

    monkeypatch.setattr(entry.EnricherJob, "run", _run)
    assert entry.main() == 0
