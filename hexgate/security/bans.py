"""Kill-switch bans — the SDK side of the ``Ban`` primitive.

Bans are an operator-controlled, override-everything denylist evaluated
*around* the policy engine, at a new invoke-time gate that refuses **before
the LLM runs** (see ``plans/kill-switch.md`` §4.3/§4.12 and
``plans/kill-switch-phase2.md``). Two ban types, both meaning "don't run at
all": an ``agent`` ban (one agent can't execute anything) and a ``user`` ban
(one ``user_id`` can't execute anything, across every agent in the project).

This module owns four things, none of which touch ``PolicyEnforcer.decide()``
or the per-tool-call hot path:

  * :class:`BanEntry` / :class:`BanSet` — an immutable snapshot of the active
    bans with the two O(1) lookups the gate needs.
  * :class:`PlatformBanSource` + :func:`get_ban_source` — an ETag-cached fetch
    of ``GET /v1/bans``. The feed is **project-scoped** (project resolved from
    the bearer token), so one source is **shared per api-key** across every
    agent in the process — one cache, one ETag, one poll cadence. This mirrors
    the shared ``hexgate.tracing._senders`` registry, not the per-agent
    :class:`~hexgate.security.source.PlatformPolicySource`.
  * :class:`BanGate` + :func:`resolve_ban_gate` — a per-agent gate (it carries
    ``agent_name``) that refreshes fail-soft, checks, and on a hit emits a
    telemetry event then raises :class:`AgentBannedError`.
  * :class:`BanEnforcementEvent` + :func:`configure_ban_sink` — a fire-and-forget
    ``POST /v1/audit/ban-enforcements`` emitter, a thin wrapper over the shared
    ``(api_key, path)`` sender registry (mirrors ``hexgate.tracing.usage``).
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


# ---------------------------------------------------------------------------
# BanSet — immutable snapshot with the two lookups the gate needs
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class BanEntry:
    """One active ban, mirroring the platform ``BanFeedEntry`` wire shape.

    Exactly one of ``target_agent_name`` / ``target_user_id`` is set,
    matching ``ban_type`` (the platform enforces this at create time).
    """

    ban_id: str
    ban_type: str  # "agent" | "user"
    target_agent_name: str | None
    target_user_id: str | None
    reason: str | None


@dataclass(frozen=True, slots=True)
class BanSet:
    """Immutable snapshot of the project's active bans, indexed for lookup.

    Built by :func:`ban_set_from_payload` from a ``GET /v1/bans`` body.
    Agent bans are keyed by ``target_agent_name``, user bans by
    ``target_user_id`` — so the gate's two checks are plain dict gets.
    """

    _by_agent: Mapping[str, BanEntry]
    _by_user: Mapping[str, BanEntry]

    def agent_ban(self, agent_name: str) -> BanEntry | None:
        """Return the active ban for ``agent_name``, or ``None``."""
        return self._by_agent.get(agent_name)

    def user_ban(self, user_id: str) -> BanEntry | None:
        """Return the active ban for ``user_id``, or ``None``."""
        return self._by_user.get(user_id)


EMPTY_BAN_SET = BanSet({}, {})


def ban_set_from_payload(entries: list[dict[str, Any]]) -> BanSet:
    """Build a :class:`BanSet` from the ``GET /v1/bans`` body.

    The body is a list of ``BanFeedEntry`` dicts (``ban_id``, ``ban_type``,
    ``target_agent_name``, ``target_user_id``, ``reason``). Agent bans are
    indexed by ``target_agent_name`` and user bans by ``target_user_id``;
    entries with a missing/blank target for their type are skipped rather
    than indexed under an empty key (defensive — the platform never emits
    those, but an empty-key entry would silently over-match).
    """
    by_agent: dict[str, BanEntry] = {}
    by_user: dict[str, BanEntry] = {}
    for raw in entries:
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
    return BanSet(by_agent, by_user)


# ---------------------------------------------------------------------------
# BanSource — ETag-cached fetch, shared per api-key (feed is project-scoped)
# ---------------------------------------------------------------------------


class BanSource(Protocol):
    """Produces the current :class:`BanSet` on demand.

    Expected to be **cheap when nothing has changed** (ETag/304), so the gate
    can call :meth:`fetch` at the top of every run. Raises on transport/HTTP
    error — the :class:`BanGate` is what makes the refresh fail-soft.
    """

    def fetch(self) -> BanSet: ...


class PlatformBanSource:
    """Pull the project's active bans from ``GET /v1/bans``, with ETag/304.

    Mirrors :class:`~hexgate.security.source.PlatformPolicySource` (lock + ETag
    cache) but is keyed to the project, not an agent — the feed derives the
    project from the bearer token, so there's no ``agent_name`` here. A 304
    returns the cached :class:`BanSet` by identity; a 200 rebuilds and caches.
    """

    def __init__(self, client: HexgateClient) -> None:
        self._client = client
        # Serialize the (read etag → HTTP → write cache) cycle: the gate's
        # refresh runs on a to_thread worker, and one source is shared across
        # every agent, so concurrent runs could otherwise interleave a write
        # to _cached with another's read of _etag and pair a body with the
        # wrong etag. Same guard PlatformPolicySource uses.
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


# One source per api-key — the feed is project-wide, so every agent wrapped
# for a given key shares one cache/ETag/poll. Mirrors the shared sender
# registry in hexgate.tracing._senders (not the per-agent policy source).
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
    """One kill-switch refusal, ready to POST. Satisfies ``_PayloadEvent``.

    Matches the platform ``BanEnforcementEvent(AuditEnvelope)``: ``agent_name``
    is always the invoked agent (non-empty even for user bans), ``ban_type``
    is ``agent``/``user``, ``ban_id`` is non-empty; the server resolves
    ``project_id`` / ``agent_version_id`` / ``received_at``.
    """

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
    """Get-or-create the ban-enforcement sender for ``api_key``.

    Thin wrapper over the shared ``(api_key, path)`` registry — mirrors
    :func:`hexgate.audit.configure` / :func:`hexgate.tracing.usage.configure_usage_sender`.
    Returns ``None`` in local mode or when no key is resolvable, and the
    existing ``hexgate.audit.shutdown`` / ``hexgate.tracing.usage.shutdown``
    drain it along with every other sender — no new lifecycle code.
    """
    return get_or_create_sender(_BAN_ENFORCEMENT_PATH, api_key, base_url)


# ---------------------------------------------------------------------------
# BanGate — per-agent invoke-time gate: refresh (fail-soft) → check → refuse
# ---------------------------------------------------------------------------


class BanGate:
    """Refuses a banned agent or user before the LLM runs.

    Per-agent (it carries ``agent_name``) but points at the shared, project-
    scoped :class:`BanSource`. The refresh is **fail-soft with last-good**,
    exactly like :meth:`PolicyBinding.refresh` — a control-plane blip must
    never crash a run. A ``None`` source (local mode / no key) makes the gate
    a permanent no-op.
    """

    def __init__(
        self,
        agent_name: str,
        source: BanSource | None,
        sink: AuditSender | None = None,
    ) -> None:
        self._agent_name = agent_name
        self._source = source
        self._sink = sink  # ban-enforcement emitter (fire-and-forget)
        self._last_good = EMPTY_BAN_SET

    def _current(self) -> BanSet:
        if self._source is None:  # local mode / no api-key → no bans
            return EMPTY_BAN_SET
        try:
            self._last_good = self._source.fetch()
        except Exception as exc:  # noqa: BLE001 — fail-soft like binding.refresh
            logger.warning("ban refresh failed; using last-good: %s", exc)
        return self._last_good

    def check(self, user: User | None) -> None:
        """Raise :class:`AgentBannedError` if this agent or user is banned.

        Agent ban wins over user ban (checked first) — both refuse anyway,
        but this makes the emitted ``ban_type`` / ``ban_id`` deterministic.
        """
        bans = self._current()
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

    async def check_async(self, user: User | None) -> None:
        """Async wrapper — the fetch is sync urllib, like ``refresh_async``."""
        await asyncio.to_thread(self.check, user)

    def _emit(self, hit: BanEntry, user: User | None) -> None:
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
    """Build the gate for ``agent_name``, or ``None`` when there's no platform.

    Returns ``None`` in local mode or when no api-key is resolvable — the
    caller treats a ``None`` gate as a no-op (skip the check). Otherwise the
    gate points at the shared per-key ban source and ban sink.
    """
    if _local_mode_active():
        return None
    key = resolve_api_key(api_key)
    if not key:
        return None
    if client is None:
        from hexgate.cloud.client import HexgateClient, HexgateConfig

        client = HexgateClient(HexgateConfig.from_env(api_key=key))
    return BanGate(agent_name, get_ban_source(key, client), configure_ban_sink(key))
