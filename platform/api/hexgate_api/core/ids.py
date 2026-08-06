"""Prefixed row-id generation for SQLModel tables (e.g. ``agt_a1b2c3…``)."""

import secrets

from hexgate_api.models import Agent, AgentVersion, ApiKey, Ban, Tool

# Class-keyed so a typo is a NameError at import, not a runtime bug. Centralized
# so entropy / format changes happen in one place.
_ID_PREFIXES: dict[type, str] = {
    Agent: "agt",
    AgentVersion: "agv",
    Tool: "tol",
    ApiKey: "tok",
    Ban: "ban",
}


def new_id(kind: type) -> str:
    """Generate a prefixed row id for a SQLModel class, e.g. ``agt_a1b2…``."""
    return f"{_ID_PREFIXES[kind]}_{secrets.token_hex(6)}"
