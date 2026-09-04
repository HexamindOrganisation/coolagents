"""Tests for hexgate.adapters._common's shared Langfuse propagation helper."""

from __future__ import annotations

from hexgate.adapters._common import _MAX_METADATA_CHARS, langfuse_propagate_kwargs
from hexgate.runtime import HexgateContext


def test_propagate_kwargs_joins_roles_as_string() -> None:
    """Multiple roles stamp as a comma-joined string (Langfuse drops non-str)."""
    ctx = HexgateContext(user_id="u", session_id="s", user_roles=["billing", "admin"])
    kwargs = langfuse_propagate_kwargs(ctx, "tag")
    assert kwargs["metadata"] == {"user_roles": "billing, admin"}
    assert kwargs["user_id"] == "u"
    assert kwargs["tags"] == ["tag"]


def test_propagate_kwargs_truncates_over_the_langfuse_cap() -> None:
    """A large role list is truncated to <=200 chars so Langfuse doesn't drop it."""
    ctx = HexgateContext(user_id="u", user_roles=[f"role_{i:03d}" for i in range(100)])
    roles = langfuse_propagate_kwargs(ctx, "tag")["metadata"]["user_roles"]
    assert len(roles) <= _MAX_METADATA_CHARS
    assert roles.endswith("...")
