"""Tests for canonical agent-name derivation (``security/naming.py``)."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from hexgate.security.naming import (
    DEFAULT_AGENT_NAME,
    canonical_agent_name,
    canonical_name,
)


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("billing-bot", "billing-bot"),
        ("  billing-bot  ", "billing-bot"),  # trimmed
        ("", DEFAULT_AGENT_NAME),  # blank → default
        ("   ", DEFAULT_AGENT_NAME),  # whitespace-only → default
        (None, DEFAULT_AGENT_NAME),  # missing → default
        (123, DEFAULT_AGENT_NAME),  # non-str → default
    ],
)
def test_canonical_name(raw: object, expected: str) -> None:
    assert canonical_name(raw) == expected  # type: ignore[arg-type]


def test_canonical_agent_name_reads_name_attr() -> None:
    assert (
        canonical_agent_name(SimpleNamespace(name="  refund-agent ")) == "refund-agent"
    )


def test_canonical_agent_name_defaults_when_unnamed() -> None:
    assert canonical_agent_name(SimpleNamespace()) == DEFAULT_AGENT_NAME
    assert canonical_agent_name(SimpleNamespace(name=None)) == DEFAULT_AGENT_NAME
    assert canonical_agent_name(SimpleNamespace(name="")) == DEFAULT_AGENT_NAME


def test_own_and_target_derivation_agree() -> None:
    # The whole point: an agent's own-name and its name as a reach target derive
    # identically, so a target authored under the name it registers with matches.
    agent = SimpleNamespace(name="Support Bot")
    assert canonical_agent_name(agent) == canonical_name(agent.name)
