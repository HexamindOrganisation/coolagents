"""Shared execution bookkeeping for the framework version-compat probes.

Each framework's probe defines the same two tools; their bodies call
:func:`record_execution`. Tier 1 asserts the *denied* tool never ran — if
an adapter silently fails to attach its enforcer to a given framework
version, the tool executes and this flag catches the bypass (the failure
mode that a "did the run complete" assertion would miss).
"""

from __future__ import annotations

# Tool names the probe policy allows / denies. Kept here so every probe and
# the policy YAML agree on one spelling.
ALLOWED_TOOL = "get_weather"
DENIED_TOOL = "delete_user"

# Substring present in every adapter's deny rendering — `error_type` for a
# DENY outcome (see hexgate.security.decision). Adapters surface it as a
# string ([policy_denied] ...) or inside the structured-error dict.
DENY_MARKER = "policy_denied"

_executed: set[str] = set()


def record_execution(name: str) -> None:
    """Mark ``name`` as having run — called from each probe tool body."""
    _executed.add(name)


def was_executed(name: str) -> bool:
    """Whether ``name``'s tool body ran since the last reset."""
    return name in _executed


def reset_executions() -> None:
    """Clear the execution record (per-test, via an autouse fixture)."""
    _executed.clear()
