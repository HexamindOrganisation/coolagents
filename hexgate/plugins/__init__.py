"""Official guards, ready to drop into ``guards=[...]``.

Three plugins built on one shared secret detector (:mod:`hexgate.plugins.secrets`),
covering the two outbound cases and the inbound one:

- :data:`secret_guard` — before-guard that **refuses** a call whose arguments
  carry a credential, with an actionable, value-free reason.
- :data:`secret_redactor` — before-guard that **strips** the credential from the
  arguments and lets the cleaned call run.
- :data:`secret_watch` — after-guard (observe) that **flags** a credential that
  leaked into a tool's result. It never changes the result in v1; it is the exact
  code that becomes a scrubber once result rewrite lands.

``secret_guard`` and ``secret_redactor`` are the two halves of the outbound case;
pick per tool by whether a secret's presence means the call is wrong (guard) or
merely incidental and safe to strip (redactor). Do not register both on the same
tool — the redactor would clean the args before the guard ever sees them.

::

    from hexgate import create_agent
    from hexgate.plugins import secret_guard, secret_watch

    agent, _ = create_agent(model=..., tools=[...], guards=[secret_guard, secret_watch])

The detector primitives are exported too, for building a custom guard (scoped with
``@before_tool(tool_names=[...])``, or with your own reason).
"""

from __future__ import annotations

import logging

from hexgate.guards import (
    Halt,
    Modification,
    Proceed,
    ToolCall,
    ToolOutcome,
    after_tool,
    before_tool,
)
from hexgate.plugins.secrets import (
    SecretHit,
    redact_secrets,
    safe_detail,
    safe_reason,
    scan_secrets,
)

_log = logging.getLogger("hexgate.plugins.secrets")


@before_tool
def secret_guard(call: ToolCall) -> Halt | None:
    """Refuse a tool call whose arguments carry a credential.

    Fail-closed (a raise denies the call). The model sees only the category and
    field, never the value, so the refusal cannot leak and does not hand the
    model a substring to obfuscate and resend.
    """
    hits = scan_secrets(call.args)
    if not hits:
        return None
    return Halt(reason=safe_reason(hits), detail=safe_detail(hits))


@before_tool
def secret_redactor(call: ToolCall) -> Proceed | None:
    """Strip every credential from the arguments and let the cleaned call run.

    Args are JSON, so the strip is a clean recursive walk; the secret leaf becomes
    a ``[REDACTED:<category>]`` marker. Records a :class:`Modification` naming the
    count and categories (never the value) so the rewrite is visible to the trail.
    """
    cleaned, hits = redact_secrets(call.args)
    if not hits:
        return None
    cats = ", ".join(sorted({h.category for h in hits}))
    return Proceed(
        args=cleaned,
        modification=Modification(
            plugin="secret_redactor",
            target="args",
            summary=f"redacted {len(hits)} secret(s): {cats}",
        ),
    )


@after_tool(observe=True)
def secret_watch(call: ToolCall, outcome: ToolOutcome) -> None:
    """Flag a credential that leaked into a tool's result.

    Observe-only (fail-open, cannot halt or rewrite): it logs a value-free warning
    on the operator channel and leaves the result untouched. Scans JSON-ish results
    only; an opaque return object is skipped. It becomes a scrubber once result
    rewrite lands (a later phase).

    It walks the full result on every call, so for a high-throughput tool that
    returns large payloads, register a scoped variant rather than this global one::

        after_tool(tool_names=["search"], observe=True)(secret_watch.fn)
    """
    if not outcome.ok:
        return None
    hits = scan_secrets(outcome.value)
    if hits:
        _log.warning(
            "secret_watch: %d probable secret(s) in %r result [%s]",
            len(hits),
            call.tool_name,
            safe_detail(hits),
        )
    return None


__all__ = [
    "SecretHit",
    "redact_secrets",
    "safe_detail",
    "safe_reason",
    "scan_secrets",
    "secret_guard",
    "secret_redactor",
    "secret_watch",
]
