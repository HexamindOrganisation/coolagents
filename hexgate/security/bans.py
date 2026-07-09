"""Kill-switch bans (SDK side) — refuse a banned agent or user before the LLM
runs, at an invoke-time gate independent of ``PolicyEnforcer.decide()``.

The ban feed is project-scoped, so its source and sink are shared per api-key
(module registries), unlike the per-agent policy source. See
``plans/kill-switch-phase2.md``.
"""

from __future__ import annotations

import asyncio
import logging
import threading
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Protocol
from uuid import UUID, uuid4

from hexgate.config.env import resolve_api_key
from hexgate.security.errors import AgentBannedError
from hexgate.tracing._senders import (
    AuditSender,
    _local_mode_active,
    get_or_create_sender,
)

if TYPE_CHECKING:
    from hexgate.cloud.client import HexgateClient
    from hexgate.runtime.context import User

logger = logging.getLogger("hexgate.security.bans")


class BanContentError(RuntimeError):
    """The ``/v1/bans`` body was a 200 but malformed — contract drift, not a
    transient error (mirrors :class:`~hexgate.security.source.PolicyContentError`)."""


# ---------------------------------------------------------------------------
# BanSet — immutable snapshot with the two lookups the gate needs
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class BanEntry:
    """One active ban, mirroring the platform ``BanFeedEntry`` wire shape."""

    ban_id: str
    ban_type: str  # "agent" | "user"
    target_agent_name: str | None
    target_user_id: str | None
    reason: str | None


@dataclass(frozen=True, slots=True)
class BanSet:
    """Immutable snapshot of active bans, indexed by target for O(1) lookup."""

    _by_agent: Mapping[str, BanEntry]
    _by_user: Mapping[str, BanEntry]

    def agent_ban(self, agent_name: str) -> BanEntry | None:
        return self._by_agent.get(agent_name)

    def user_ban(self, user_id: str) -> BanEntry | None:
        return self._by_user.get(user_id)


EMPTY_BAN_SET = BanSet({}, {})


def ban_set_from_payload(entries: list[dict[str, Any]]) -> BanSet:
    """Index a ``GET /v1/bans`` body into a :class:`BanSet`.

    Entries with an unknown ban_type or blank target are dropped and logged
    (an empty key would over-match). A non-array/non-object body raises
    :class:`BanContentError` rather than silently yielding no bans.
    """
    if not isinstance(entries, list):
        raise BanContentError(f"expected a JSON array, got {type(entries).__name__}")
    by_agent: dict[str, BanEntry] = {}
    by_user: dict[str, BanEntry] = {}
    for raw in entries:
        if not isinstance(raw, dict):
            raise BanContentError(f"expected ban objects, got {type(raw).__name__}")
        entry = BanEntry(
            ban_id=raw.get("ban_id", ""),
            ban_type=raw.get("ban_type", ""),
            target_agent_name=raw.get("target_agent_name"),
            target_user_id=raw.get("target_user_id"),
            reason=raw.get("reason"),
        )
        if entry.ban_type == "agent" and entry.target_agent_name:
            by_agent[entry.target_agent_name] = entry
        elif entry.ban_type == "user" and entry.target_user_id:
            by_user[entry.target_user_id] = entry
        else:
            # Unknown ban_type or blank target — can't index, so drop it, but
            # loudly: this is a ban the operator created that we won't enforce.
            logger.warning(
                "dropping unenforceable ban %s (ban_type=%r, blank/unknown target)",
                entry.ban_id,
                entry.ban_type,
            )
    return BanSet(by_agent, by_user)


# ---------------------------------------------------------------------------
# BanSource — ETag-cached fetch, shared per api-key (feed is project-scoped)
# ---------------------------------------------------------------------------


class BanSource(Protocol):
    """Produces the current :class:`BanSet`; raises on error (the gate makes
    the refresh fail-soft)."""

    def fetch(self) -> BanSet: ...


class PlatformBanSource:
    """Fetch ``GET /v1/bans`` with ETag/304, cached under a lock.

    Mirrors :class:`~hexgate.security.source.PlatformPolicySource` but keyed to
    the project (from the bearer), not an agent.
    """

    def __init__(self, client: HexgateClient) -> None:
        self._client = client
        # Serialize read-etag → HTTP → write-cache: the source is shared across
        # agents and refreshed off a to_thread worker, so concurrent fetches
        # could otherwise pair a body with the wrong etag.
        self._lock = threading.Lock()
        self._cached = EMPTY_BAN_SET
        self._etag: str | None = None

    def fetch(self) -> BanSet:
        with self._lock:
            payload, etag = self._client.get_bans(if_none_match=self._etag)
            if payload is None:  # 304 — unchanged since last fetch
                return self._cached
            self._cached = ban_set_from_payload(payload)
            self._etag = etag
            return self._cached


# One source per api-key — the feed is project-wide, so agents share a cache.
_ban_sources: dict[str, PlatformBanSource] = {}


def get_ban_source(api_key: str, client: HexgateClient) -> PlatformBanSource:
    """Get-or-create the shared :class:`PlatformBanSource` for ``api_key``."""
    src = _ban_sources.get(api_key)
    if src is None:
        src = _ban_sources[api_key] = PlatformBanSource(client)
    return src


# ---------------------------------------------------------------------------
# Ban-enforcement emitter — thin wrapper over the shared sender registry
# ---------------------------------------------------------------------------

_BAN_ENFORCEMENT_PATH = "/v1/audit/ban-enforcements"


@dataclass(frozen=True, slots=True)
class BanEnforcementEvent:
    """One refusal, ready to POST. Matches the platform
    ``BanEnforcementEvent(AuditEnvelope)``; the server resolves project_id /
    agent_version_id / received_at."""

    ban_type: str
    ban_id: str
    agent_name: str = ""
    reason: str | None = None
    user_id: str = ""
    session_id: str = ""
    event_id: UUID = field(default_factory=uuid4)
    occurred_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def as_payload(self) -> dict[str, Any]:
        return {
            "event_id": str(self.event_id),
            "occurred_at": self.occurred_at.isoformat(),
            "agent_name": self.agent_name,
            "user_id": self.user_id,
            "session_id": self.session_id,
            "ban_type": self.ban_type,
            "ban_id": self.ban_id,
            "reason": self.reason or "",
        }


def configure_ban_sink(
    api_key: str | None = None,
    base_url: str | None = None,
) -> AuditSender | None:
    """Get-or-create the ban-enforcement sender (shared registry; ``None`` in
    local mode / no key). Drained by the existing ``audit.shutdown``."""
    return get_or_create_sender(_BAN_ENFORCEMENT_PATH, api_key, base_url)


# ---------------------------------------------------------------------------
# BanGate — per-agent invoke-time gate: refresh (fail-soft) → check → refuse
# ---------------------------------------------------------------------------


class BanGate:
    """Refuses a banned agent or user before the LLM runs.

    Per-agent but points at the shared project-scoped source. Fail-soft with
    last-good, like :meth:`PolicyBinding.refresh`; a ``None`` source (local
    mode / no key) is a permanent no-op. On generator/stream entrypoints the
    refusal surfaces when iteration begins (before the first chunk), not at
    call time.
    """

    def __init__(
        self,
        agent_name: str,
        source: BanSource | None,
        sink: AuditSender | None = None,
    ) -> None:
        self._agent_name = agent_name
        self._source = source
        self._sink = sink
        self._last_good = EMPTY_BAN_SET

    def _current(self) -> BanSet:
        # Fail-soft is deliberate for v1 (fail-closed is a Phase 4 opt-in):
        # a control-plane blip must never crash a run. Note the sharper
        # trade-off vs. policy — a ban never successfully fetched degrades to
        # EMPTY, not to a prior restrictive state.
        if self._source is None:
            return EMPTY_BAN_SET
        try:
            self._last_good = self._source.fetch()
        except BanContentError as exc:
            # Contract drift, not a blip — log loudly, like PolicyContentError.
            logger.error("ban feed rejected; using last-good: %s", exc)
        except Exception as exc:  # noqa: BLE001 — transient; keep last-good
            logger.warning("ban refresh failed; using last-good: %s", exc)
        return self._last_good

    def _decide(self, bans: BanSet, user: User | None) -> None:
        # Agent ban checked first so a coincident agent+user ban emits a
        # deterministic ban_type/ban_id.
        hit = bans.agent_ban(self._agent_name)
        if hit is None and user is not None:
            hit = bans.user_ban(user.user_id)
        if hit is None:
            return
        self._emit(hit, user)
        target = (
            hit.target_agent_name if hit.ban_type == "agent" else hit.target_user_id
        )
        raise AgentBannedError(
            ban_type=hit.ban_type,
            target=target or "",
            code=f"{hit.ban_type}_banned",
            reason=hit.reason,
        )

    def check(self, user: User | None) -> None:
        """Raise :class:`AgentBannedError` if this agent or user is banned."""
        self._decide(self._current(), user)

    async def check_async(self, user: User | None) -> None:
        """Async check: fetch off-loop, decide + emit + raise on the loop.

        The emit must stay on the loop — the fire-and-forget ``AuditSender``
        only adopts a running loop on its on-loop path, so emitting from the
        ``to_thread`` worker would drop the event.
        """
        bans = await asyncio.to_thread(self._current)
        self._decide(bans, user)

    def _emit(self, hit: BanEntry, user: User | None) -> None:
        # Best-effort: on sync entrypoints with no running loop, a sink built
        # off-loop drops the event (shared AuditSender limitation, not
        # ban-specific). The refusal itself is unaffected.
        if self._sink is None:
            return
        self._sink.emit(
            BanEnforcementEvent(
                ban_type=hit.ban_type,
                ban_id=hit.ban_id,
                reason=hit.reason,
                agent_name=self._agent_name,
                user_id=user.user_id if user else "",
                session_id=(user.session_id or "") if user else "",
            )
        )


def resolve_ban_gate(
    agent_name: str,
    *,
    api_key: str | None = None,
    client: HexgateClient | None = None,
) -> BanGate | None:
    """Build the gate for ``agent_name``, or ``None`` in local mode / no key
    (the caller skips the check). Points at the shared per-key source + sink."""
    if _local_mode_active():
        return None
    key = resolve_api_key(api_key)
    if not key:
        return None
    if client is None:
        from hexgate.cloud.client import HexgateClient, HexgateConfig

        client = HexgateClient(HexgateConfig.from_env(api_key=key))
    return BanGate(agent_name, get_ban_source(key, client), configure_ban_sink(key))
