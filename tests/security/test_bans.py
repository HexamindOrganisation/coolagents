"""Tests for the kill-switch ban primitive (SDK side) — ``hexgate.security.bans``.

Covers the BanSet snapshot + indexing, the ETag-cached PlatformBanSource and
its shared-per-key registry, the fail-soft BanGate (agent/user/precedence/
no-op/fail-soft), resolve_ban_gate's local-mode/no-key gates, and the
ban-enforcement emitter (event payload + configure_ban_sink wiring). No real
network calls — the HexgateClient is always mocked.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import pytest

from hexgate.runtime import User
from hexgate.security.bans import (
    EMPTY_BAN_SET,
    BanEnforcementEvent,
    BanGate,
    BanSet,
    PlatformBanSource,
    ban_set_from_payload,
    configure_ban_sink,
    get_ban_source,
    resolve_ban_gate,
)
from hexgate.security.bans import _ban_sources as _BAN_SOURCES
from hexgate.security.errors import AgentBannedError
from hexgate.tracing import _senders


@pytest.fixture(autouse=True)
def _isolate_ban_state(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Reset the shared ban-source + sender registries and HEXGATE_* env."""
    _BAN_SOURCES.clear()
    _senders._senders.clear()
    _senders._logged_local_mode_suppressed.clear()
    monkeypatch.delenv("HEXGATE_API_KEY", raising=False)
    monkeypatch.delenv("HEXGATE_API_URL", raising=False)
    monkeypatch.delenv(_senders._LOCAL_MODE_ENV, raising=False)
    yield
    _BAN_SOURCES.clear()
    _senders._senders.clear()
    _senders._logged_local_mode_suppressed.clear()


def _user(user_id: str = "u-1") -> User:
    return User(user_id=user_id, session_id="s-1", role="developer")


def _agent_entry(agent_name: str = "bot", ban_id: str = "b-agent") -> dict[str, Any]:
    return {
        "ban_id": ban_id,
        "ban_type": "agent",
        "target_agent_name": agent_name,
        "target_user_id": None,
        "reason": "agent disabled",
    }


def _user_entry(user_id: str = "u-1", ban_id: str = "b-user") -> dict[str, Any]:
    return {
        "ban_id": ban_id,
        "ban_type": "user",
        "target_agent_name": None,
        "target_user_id": user_id,
        "reason": "user suspended",
    }


class _FakeBanClient:
    """Stand-in for HexgateClient.get_bans — scripts (payload, etag) returns
    and records the If-None-Match sent on each call."""

    def __init__(self, responses: list[tuple[list[dict] | None, str | None]]) -> None:
        self._responses = responses
        self.if_none_match_seen: list[str | None] = []
        self.calls = 0

    def get_bans(
        self, *, if_none_match: str | None = None
    ) -> tuple[list[dict] | None, str | None]:
        self.if_none_match_seen.append(if_none_match)
        resp = self._responses[min(self.calls, len(self._responses) - 1)]
        self.calls += 1
        return resp


# ---------------------------------------------------------------------------
# BanSet + ban_set_from_payload
# ---------------------------------------------------------------------------


def test_ban_set_lookups_hit_and_miss() -> None:
    bans = ban_set_from_payload([_agent_entry("bot"), _user_entry("u-9")])
    assert bans.agent_ban("bot").ban_id == "b-agent"
    assert bans.user_ban("u-9").ban_id == "b-user"
    assert bans.agent_ban("other") is None
    assert bans.user_ban("nobody") is None


def test_ban_set_from_payload_indexes_by_type() -> None:
    bans = ban_set_from_payload([_agent_entry("bot")])
    # An agent ban is not reachable via the user index and vice versa.
    assert bans.agent_ban("bot") is not None
    assert bans.user_ban("bot") is None


def test_ban_set_from_payload_skips_blank_target() -> None:
    """A malformed entry with no target for its type is dropped, not indexed
    under an empty key (which would over-match every agent/user)."""
    bans = ban_set_from_payload(
        [
            {
                "ban_id": "bad",
                "ban_type": "agent",
                "target_agent_name": None,
                "target_user_id": None,
                "reason": None,
            }
        ]
    )
    assert bans.agent_ban("") is None
    assert bans == EMPTY_BAN_SET  # nothing indexed at all


def test_empty_ban_set_never_matches() -> None:
    assert EMPTY_BAN_SET.agent_ban("bot") is None
    assert EMPTY_BAN_SET.user_ban("u-1") is None


# ---------------------------------------------------------------------------
# PlatformBanSource — ETag / 304 cache
# ---------------------------------------------------------------------------


def test_source_200_populates_cache_and_etag() -> None:
    client = _FakeBanClient([([_agent_entry("bot")], '"etag-1"')])
    src = PlatformBanSource(client)  # type: ignore[arg-type]

    bans = src.fetch()

    assert bans.agent_ban("bot") is not None
    assert src._etag == '"etag-1"'
    assert client.if_none_match_seen == [None]  # first call sends no etag


def test_source_304_returns_cached_identity() -> None:
    client = _FakeBanClient([([_agent_entry("bot")], '"etag-1"'), (None, '"etag-1"')])
    src = PlatformBanSource(client)  # type: ignore[arg-type]

    first = src.fetch()
    second = src.fetch()

    assert second is first  # 304 → same object by identity
    # The second call echoes the cached etag as If-None-Match.
    assert client.if_none_match_seen == [None, '"etag-1"']


def test_source_200_then_200_rebuilds() -> None:
    client = _FakeBanClient(
        [([_agent_entry("bot")], '"etag-1"'), ([_user_entry("u-9")], '"etag-2"')]
    )
    src = PlatformBanSource(client)  # type: ignore[arg-type]

    src.fetch()
    updated = src.fetch()

    assert updated.agent_ban("bot") is None
    assert updated.user_ban("u-9") is not None
    assert src._etag == '"etag-2"'


# ---------------------------------------------------------------------------
# get_ban_source registry — shared per api-key
# ---------------------------------------------------------------------------


def test_get_ban_source_shared_per_key() -> None:
    client = _FakeBanClient([(None, None)])
    a = get_ban_source("key-1", client)  # type: ignore[arg-type]
    b = get_ban_source("key-1", client)  # type: ignore[arg-type]
    c = get_ban_source("key-2", client)  # type: ignore[arg-type]
    assert a is b  # same key → one shared source
    assert c is not a  # distinct key → distinct source


# ---------------------------------------------------------------------------
# BanGate.check — the enforcement decision
# ---------------------------------------------------------------------------


class _StaticSource:
    def __init__(self, bans: BanSet) -> None:
        self._bans = bans

    def fetch(self) -> BanSet:
        return self._bans


class _BoomSource:
    def fetch(self) -> BanSet:
        raise RuntimeError("platform down")


def test_check_agent_ban_raises_enriched_error() -> None:
    bans = ban_set_from_payload([_agent_entry("bot", ban_id="b1")])
    gate = BanGate("bot", _StaticSource(bans))

    with pytest.raises(AgentBannedError) as exc:
        gate.check(_user())

    err = exc.value
    assert err.ban_type == "agent"
    assert err.target == "bot"
    assert err.code == "agent_banned"
    assert err.reason == "agent disabled"
    assert "administrator" in err.user_message


def test_check_user_ban_raises() -> None:
    bans = ban_set_from_payload([_user_entry("u-1", ban_id="b2")])
    gate = BanGate("safe-agent", _StaticSource(bans))

    with pytest.raises(AgentBannedError) as exc:
        gate.check(_user("u-1"))

    assert exc.value.code == "user_banned"
    assert exc.value.target == "u-1"


def test_check_no_ban_returns_none() -> None:
    gate = BanGate("safe-agent", _StaticSource(EMPTY_BAN_SET))
    assert gate.check(_user()) is None


def test_check_agent_ban_wins_over_user_ban() -> None:
    """Both banned → agent ban is chosen (checked first) for deterministic
    emitted ban_type/ban_id."""
    bans = ban_set_from_payload(
        [_agent_entry("bot", ban_id="AGENT"), _user_entry("u-1", ban_id="USER")]
    )
    gate = BanGate("bot", _StaticSource(bans))

    with pytest.raises(AgentBannedError) as exc:
        gate.check(_user("u-1"))

    assert exc.value.code == "agent_banned"


def test_check_none_source_is_noop() -> None:
    """Local mode / no key → source None → gate never raises."""
    assert BanGate("bot", None).check(_user()) is None


def test_check_none_user_only_checks_agent() -> None:
    bans = ban_set_from_payload([_user_entry("u-1")])
    gate = BanGate("bot", _StaticSource(bans))
    # No user in scope → user bans can't apply; agent isn't banned → passes.
    assert gate.check(None) is None


def test_check_fail_soft_uses_last_good() -> None:
    """A fetch failure logs and reuses last-good; it never raises on its own."""
    gate = BanGate("bot", _BoomSource())
    # last-good is empty → no ban → no raise despite the fetch blowing up.
    assert gate.check(_user()) is None


def test_check_fail_soft_keeps_previous_ban(caplog: pytest.LogCaptureFixture) -> None:
    """If the last-good set banned the agent, a later fetch failure still
    refuses (fail-soft never under-blocks)."""

    class _FlakySource:
        def __init__(self) -> None:
            self.calls = 0

        def fetch(self) -> BanSet:
            self.calls += 1
            if self.calls == 1:
                return ban_set_from_payload([_agent_entry("bot")])
            raise RuntimeError("down")

    gate = BanGate("bot", _FlakySource())
    with pytest.raises(AgentBannedError):
        gate.check(_user())  # first fetch bans
    with pytest.raises(AgentBannedError):
        gate.check(_user())  # second fetch fails → last-good still bans


async def test_check_async_raises_through_to_thread() -> None:
    bans = ban_set_from_payload([_agent_entry("bot")])
    gate = BanGate("bot", _StaticSource(bans))
    with pytest.raises(AgentBannedError):
        await gate.check_async(_user())


# ---------------------------------------------------------------------------
# BanGate._emit — fire-and-forget telemetry on a hit
# ---------------------------------------------------------------------------


class _RecordingSink:
    def __init__(self) -> None:
        self.events: list[BanEnforcementEvent] = []

    def emit(self, event: BanEnforcementEvent) -> None:
        self.events.append(event)


def test_emit_fires_on_hit_with_full_context() -> None:
    bans = ban_set_from_payload([_agent_entry("bot", ban_id="b1")])
    sink = _RecordingSink()
    gate = BanGate("bot", _StaticSource(bans), sink)  # type: ignore[arg-type]

    with pytest.raises(AgentBannedError):
        gate.check(_user("u-1"))

    [ev] = sink.events
    assert ev.ban_id == "b1"
    assert ev.ban_type == "agent"
    assert ev.agent_name == "bot"
    assert ev.user_id == "u-1"
    assert ev.session_id == "s-1"


def test_no_emit_when_no_ban() -> None:
    sink = _RecordingSink()
    gate = BanGate("bot", _StaticSource(EMPTY_BAN_SET), sink)  # type: ignore[arg-type]
    gate.check(_user())
    assert sink.events == []


def test_none_sink_is_noop_but_still_raises() -> None:
    bans = ban_set_from_payload([_agent_entry("bot")])
    gate = BanGate("bot", _StaticSource(bans), None)
    with pytest.raises(AgentBannedError):
        gate.check(_user())


# ---------------------------------------------------------------------------
# resolve_ban_gate — local mode / no key gates
# ---------------------------------------------------------------------------


def test_resolve_ban_gate_none_without_key() -> None:
    assert resolve_ban_gate("bot") is None


def test_resolve_ban_gate_none_in_local_mode(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HEXGATE_API_KEY", "fty_live_proj_secret")
    monkeypatch.setenv(_senders._LOCAL_MODE_ENV, "1")
    assert resolve_ban_gate("bot") is None


def test_resolve_ban_gate_builds_gate_with_shared_source() -> None:
    client = _FakeBanClient([(None, None)])
    g1 = resolve_ban_gate("bot", api_key="fty_live_proj_a", client=client)  # type: ignore[arg-type]
    g2 = resolve_ban_gate("other", api_key="fty_live_proj_a", client=client)  # type: ignore[arg-type]
    assert g1 is not None and g2 is not None
    # Same api-key → the two per-agent gates share one ban source.
    assert g1._source is g2._source


# ---------------------------------------------------------------------------
# BanEnforcementEvent.as_payload — wire mapping
# ---------------------------------------------------------------------------


def test_event_payload_field_mapping() -> None:
    ev = BanEnforcementEvent(
        ban_type="user",
        ban_id="b1",
        agent_name="bot",
        reason="abuse",
        user_id="u-1",
        session_id="s-1",
    )
    wire = ev.as_payload()
    assert wire["event_id"] == str(ev.event_id)
    assert wire["occurred_at"] == ev.occurred_at.isoformat()
    assert wire["agent_name"] == "bot"
    assert wire["user_id"] == "u-1"
    assert wire["session_id"] == "s-1"
    assert wire["ban_type"] == "user"
    assert wire["ban_id"] == "b1"
    assert wire["reason"] == "abuse"


def test_event_payload_reason_none_normalizes_to_empty() -> None:
    wire = BanEnforcementEvent(
        ban_type="agent", ban_id="b1", agent_name="bot"
    ).as_payload()
    assert wire["reason"] == ""
    assert wire["user_id"] == ""
    assert wire["session_id"] == ""


def test_event_payload_omits_server_resolved_fields() -> None:
    wire = BanEnforcementEvent(
        ban_type="agent", ban_id="b1", agent_name="bot"
    ).as_payload()
    assert "project_id" not in wire
    assert "agent_version_id" not in wire
    assert "received_at" not in wire


def test_event_id_unique_per_event() -> None:
    w1 = BanEnforcementEvent(ban_type="agent", ban_id="b", agent_name="a").as_payload()
    w2 = BanEnforcementEvent(ban_type="agent", ban_id="b", agent_name="a").as_payload()
    assert w1["event_id"] != w2["event_id"]
    assert "+00:00" in w1["occurred_at"]


# ---------------------------------------------------------------------------
# configure_ban_sink — thin wiring onto the shared sender registry
# ---------------------------------------------------------------------------


def test_configure_ban_sink_none_without_key() -> None:
    assert configure_ban_sink() is None


def test_configure_ban_sink_wires_to_ban_enforcements_endpoint() -> None:
    sender = configure_ban_sink("k")
    assert sender is not None
    assert sender._endpoint == "https://app.hexgate.ai/v1/audit/ban-enforcements"


def test_configure_ban_sink_memoized_per_key() -> None:
    a = configure_ban_sink("k1")
    assert configure_ban_sink("k1") is a
    assert configure_ban_sink("k2") is not a


def test_configure_ban_sink_suppressed_in_local_mode(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(_senders._LOCAL_MODE_ENV, "1")
    assert configure_ban_sink("real_key") is None


def test_configure_ban_sink_distinct_from_other_event_types() -> None:
    """The ban sink shares the registry but is keyed by its own path, so it
    never collides with the decisions/usage senders for the same key."""
    import hexgate.audit as audit_mod

    decisions = audit_mod.configure("k1")
    ban = configure_ban_sink("k1")
    assert decisions is not ban
    assert decisions._endpoint.endswith("/v1/audit/decisions")
    assert ban._endpoint.endswith("/v1/audit/ban-enforcements")
