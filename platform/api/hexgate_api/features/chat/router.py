"""WebSocket relay: ``hexgate serve`` producer (bearer) + dashboard chat (cookie)."""

from fastapi import APIRouter, Depends, WebSocket, WebSocketDisconnect
from sqlmodel.ext.asyncio.session import AsyncSession

from hexgate_api.core.db import get_session
from hexgate_api.core.relay import registry
from hexgate_api.deps.ws import ws_require_org_member, ws_require_project

router = APIRouter()


@router.websocket("/serve")
async def ws_serve(
    websocket: WebSocket,
    session: AsyncSession = Depends(get_session),
) -> None:
    """Producer socket for ``hexgate serve`` — project derived from token.

    The CLI connects with two subprotocols offered: ``bearer.<key>`` and
    ``hexgate.v1``. ``ws_require_project`` validates the bearer and
    resolves it to the token's project (no project_id in the URL — the
    biscuit *is* the project context). On a successful handshake the
    server echoes ``hexgate.v1`` back; the bearer subprotocol is
    consumed and never mirrored.
    """
    project_id = await ws_require_project(websocket, session)
    if project_id is None:
        return  # handshake already closed with 4401
    await registry.attach_serve(project_id, websocket)
    try:
        while True:
            payload = await websocket.receive_json()
            if isinstance(payload, dict) and payload.get("type") == "hello":
                agent_name = payload.get("agent")
                await registry.set_agent_name(
                    project_id, agent_name if isinstance(agent_name, str) else None
                )
                continue
            await registry.relay_to_chat(project_id, payload)
    except WebSocketDisconnect:
        pass
    finally:
        await registry.detach_serve(project_id, websocket)


@router.websocket("/projects/{project_id}/chat")
async def ws_chat(
    websocket: WebSocket,
    project_id: str,
    session: AsyncSession = Depends(get_session),
) -> None:
    """Consumer socket for dashboard Playground sessions.

    Cookie-authed: the dashboard's JS WebSocket reaches for the
    ``hexgate_session`` cookie automatically. ``ws_require_org_member``
    verifies it + checks the caller is a member of the project's org
    before ``accept()`` runs. Anonymous / cross-org connects close
    with 4401 before the handshake completes.
    """
    user = await ws_require_org_member(websocket, project_id, session)
    if user is None:
        return  # close already sent
    await registry.attach_chat(project_id, websocket)
    try:
        while True:
            payload = await websocket.receive_json()
            await registry.relay_to_serve(project_id, payload)
    except WebSocketDisconnect:
        pass
    finally:
        await registry.detach_chat(project_id, websocket)
