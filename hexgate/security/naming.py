"""Canonical agent-name derivation, shared by every adapter and the reach gate.

An agent's name is the identity a policy references two ways: its *own* name selects
its policy, and a *reach* key (``agent.handoff:<name>`` / ``agent.tool:<name>``)
names a *target* agent. Both the own-name lookup and the target-name match must
derive the name the same way, or a target authored under the name it registers with
would silently fail to match at the handoff seam. Before this module the derivation
was duplicated across adapters in two subtly different spellings
(``getattr(agent, "name", "default")`` vs ``... or "default"``); this is now the
one place it lives.

Matching is exact on the trimmed name (no case folding): a policy target name must
equal the name its agent registers with. Case-insensitive matching would have to be
applied to both the policy key (at lowering) and the runtime name to stay in parity,
so it is deliberately left as a possible follow-up rather than a silent half-fix.
"""

from __future__ import annotations

from typing import Any

# The identity a null/blank-named agent collapses to, so it never reaches a policy
# lookup, a cache key, or a reach match as ``None``/``""``.
DEFAULT_AGENT_NAME = "default"


def canonical_name(name: str | None) -> str:
    """Normalize an agent name string: trim whitespace, blank/None → ``"default"``."""
    if not isinstance(name, str):
        return DEFAULT_AGENT_NAME
    return name.strip() or DEFAULT_AGENT_NAME


def canonical_agent_name(agent: Any) -> str:
    """The name a framework ``Agent`` object is known by for policy.

    Reads the framework-agnostic ``name`` attribute (every supported SDK agent has
    one) through :func:`canonical_name`. Used for both an agent's own-name lookup
    and, at the handoff/delegation seam, for the target agent's reach match, so the
    two can never drift."""
    return canonical_name(getattr(agent, "name", None))
