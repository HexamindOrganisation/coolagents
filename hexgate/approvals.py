"""Framework-agnostic approval-handler type alias.

Extracted from :mod:`hexgate.agents.factory` so adapter code paths
(``hexgate.adapters.openai``, ``hexgate.adapters.pydantic_ai``,
``hexgate.adapters.google``) can reference the type without transitively
loading LangChain and LangGraph via ``factory.py``'s module-top imports.

The alias itself has no framework dependencies — it composes a plain
``bool`` shortcut with a ``Callable`` over :class:`Decision`, both
stdlib. Everything an adapter needs to talk about approvals lives here;
:mod:`hexgate.agents.approvals` (the ``resolve_approval_*`` helpers)
imports from this module so it stays framework-agnostic too.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import TypeAlias

from hexgate.security.decision import Decision

ApprovalHandler: TypeAlias = bool | Callable[[Decision], bool | Awaitable[bool]]

__all__ = ["ApprovalHandler"]
