"""In-memory WebSocket relay for serve-mode agent sessions.

The backend bridges two peer roles per project:

- **serve** (the developer's `hexgate serve` process) — one per project.
  New connections replace any existing one; the old socket is closed.
- **chat** (dashboard Playground tabs) — many per project. All chat sockets
  receive the same events from the serve peer.

Messages are opaque JSON blobs relayed unchanged. Synthetic events are
injected by the relay itself: `{"type": "agent_online", "online": bool}`
so the dashboard can render a live/offline indicator without polling.
"""

from __future__ import annotations

import asyncio
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from fastapi import WebSocket


@dataclass
class ProjectRelay:
    serve: WebSocket | None = None
    agent_name: str | None = None
    chats: set[WebSocket] = field(default_factory=set)


def _status_payload(online: bool, agent: str | None) -> dict[str, Any]:
    payload: dict[str, Any] = {"type": "agent_online", "online": online}
    if agent:
        payload["agent"] = agent
    return payload


class ConnectionRegistry:
    """Track serve/chat WebSockets per project and broker messages."""

    def __init__(self) -> None:
        self._projects: dict[str, ProjectRelay] = defaultdict(ProjectRelay)
        self._lock = asyncio.Lock()

    async def attach_serve(self, project_id: str, ws: WebSocket) -> WebSocket | None:
        """Register a serve socket, evicting any previous one."""
        async with self._lock:
            entry = self._projects[project_id]
            previous = entry.serve
            entry.serve = ws
            # New serve session — reset agent metadata until its hello lands.
            entry.agent_name = None
        if previous is not None and previous is not ws:
            try:
                await previous.close(
                    code=1000, reason="replaced by new serve connection"
                )
            except Exception:
                pass
        await self._broadcast_chat(project_id, _status_payload(True, None))
        return previous

    async def set_agent_name(self, project_id: str, agent_name: str | None) -> None:
        async with self._lock:
            entry = self._projects[project_id]
            entry.agent_name = agent_name
            online = entry.serve is not None
        await self._broadcast_chat(project_id, _status_payload(online, agent_name))

    async def detach_serve(self, project_id: str, ws: WebSocket) -> None:
        async with self._lock:
            entry = self._projects.get(project_id)
            if entry is None or entry.serve is not ws:
                return
            entry.serve = None
            entry.agent_name = None
        await self._broadcast_chat(project_id, _status_payload(False, None))

    async def attach_chat(self, project_id: str, ws: WebSocket) -> None:
        async with self._lock:
            self._projects[project_id].chats.add(ws)
            entry = self._projects[project_id]
            online = entry.serve is not None
            agent = entry.agent_name
        await _safe_send(ws, _status_payload(online, agent))

    async def detach_chat(self, project_id: str, ws: WebSocket) -> None:
        async with self._lock:
            entry = self._projects.get(project_id)
            if entry is not None:
                entry.chats.discard(ws)

    async def relay_to_serve(self, project_id: str, payload: dict[str, Any]) -> None:
        async with self._lock:
            serve = self._projects.get(project_id, ProjectRelay()).serve
        if serve is None:
            return
        await _safe_send(serve, payload)

    async def relay_to_chat(self, project_id: str, payload: dict[str, Any]) -> None:
        await self._broadcast_chat(project_id, payload)

    async def _broadcast_chat(self, project_id: str, payload: dict[str, Any]) -> None:
        async with self._lock:
            chats = list(self._projects.get(project_id, ProjectRelay()).chats)
        for ws in chats:
            await _safe_send(ws, payload)


async def _safe_send(ws: WebSocket, payload: dict[str, Any]) -> bool:
    """Send JSON, swallow socket errors, return success."""
    try:
        await ws.send_json(payload)
        return True
    except Exception:
        return False


registry = ConnectionRegistry()
