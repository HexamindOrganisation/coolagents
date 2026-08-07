"""The enforcement seam between the proxy transport and the policy engine.

:class:`Gate` is the one place egress talks to
:class:`~hexgate.security.enforcer.PolicyEnforcer`. A transport hands it the
enforcer args for a request; it resolves the caller's :class:`HexgateContext`, asks the
enforcer for a :class:`~hexgate.security.decision.Decision` (which emits the
audit event and fires the decision observer as a side effect), and reduces it
to an allow/deny result — awaiting the approval handler on ``NEEDS_APPROVAL``.

Keeping every policy interaction behind this one method is what lets a future
MITM transport reuse the whole enforcement path unchanged: the tunnel
transport calls :meth:`check` once (host-level); a MITM transport would call
it a second time with the decrypted request's full URL. Neither knows or
cares which engine ran.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from inspect import isawaitable
from typing import Any

from hexgate.approvals import ApprovalHandler
from hexgate.egress.model import NET_TOOL
from hexgate.runtime.context import HexgateContext
from hexgate.security.decision import Decision, DecisionOutcome
from hexgate.security.enforcer import PolicyEnforcer

_log = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class GateResult:
    """The effective verdict for one egress request.

    ``allowed`` folds approval resolution in: an ``approval_required`` decision
    whose handler approved reports ``allowed=True`` while ``decision`` still
    carries the original ``NEEDS_APPROVAL`` outcome and reason (useful for
    logging what was approved).
    """

    allowed: bool
    decision: Decision


class Gate:
    """Reduce an egress request to a :class:`GateResult` via the enforcer."""

    def __init__(
        self,
        enforcer: PolicyEnforcer,
        user: HexgateContext,
        *,
        tool: str = NET_TOOL,
        approval_handler: ApprovalHandler | None = None,
    ) -> None:
        self._enforcer = enforcer
        self._user = user
        self._tool = tool
        self._approval_handler = approval_handler

    async def check(self, args: dict[str, Any]) -> GateResult:
        """Decide one egress request, resolving approval when required.

        The caller identity lives in a contextvar the enforcer reads on
        ``decide()``. Connection handlers run in their own asyncio task, which
        does not inherit the agent's ``async with HexgateContext(...)`` scope, so we
        re-bind the run's user in *this* task via ``sync_scope()`` for the
        duration of the synchronous decide call.

        No ``ToolUseContext`` is installed here, so *trusted* ``ctx.*`` attrs
        are unavailable and fail closed — egress supports advisory ``ctx.*``
        only until attenuation is wired into this path.
        """
        with self._user.sync_scope():
            decision = self._enforcer.decide(self._tool, args)

        if decision.allowed:
            return GateResult(True, decision)
        if (
            decision.outcome is DecisionOutcome.NEEDS_APPROVAL
            and self._approval_handler is not None
        ):
            return GateResult(await self._resolve_approval(decision), decision)
        return GateResult(False, decision)

    async def _resolve_approval(self, decision: Decision) -> bool:
        """Normalize the approval handler (bool / sync / async) to a bool.

        Fails closed: a handler that raises denies the request rather than
        letting the exception escape into the connection handler.
        """
        handler = self._approval_handler
        if isinstance(handler, bool):
            return handler
        try:
            result: Any = handler(decision)  # type: ignore[misc]
            if isawaitable(result):
                result = await result
            return bool(result)
        except Exception:
            _log.exception("egress approval_handler raised; denying (fail-closed)")
            return False
