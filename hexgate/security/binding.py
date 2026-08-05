"""Policy binding — hold an enforcer, keep it current from a source.

Tools close over the enforcer, so :meth:`PolicyBinding.refresh` (called
at every run boundary) hot-swaps ``enforcer.policy`` for all of them.
Resolve is fail-loud, refresh is fail-soft (stale, never unverified).
A platform 404 propagates; callers register and resolve again. No
implicit allow-all — static engines go through the plain constructor.
"""

from __future__ import annotations

import asyncio
import logging
import os
from dataclasses import dataclass
from typing import TYPE_CHECKING

import yaml

from hexgate.config.env import resolve_api_key
from hexgate.security.policy_set import load_policy_set_from_dict
from hexgate.security.source import (
    _LOCAL_POLICY_ENV_VAR,
    _REQUIRE_SIGNATURE_ENV_VAR,
    PlatformPolicySource,
    PolicyContentError,
    PolicySource,
    _local_policy_override,
    _truthy,
    decode_and_verify_platform_bundle,
)

if TYPE_CHECKING:
    from hexgate.cloud.client import HexgateClient
    from hexgate.security.decision import PolicyEngine

    # Annotation-only — PolicyEnforcer is only named in a type hint here, never
    # constructed. Keeping it out of the runtime import graph is also what
    # breaks the import cycle that would otherwise form:
    #   audit → security/__init__ → binding → enforcer → audit
    # (enforcer.py imports audit at module load). Don't promote this to a
    # top-level import.
    from hexgate.security.enforcer import PolicyEnforcer

logger = logging.getLogger("hexgate.security.binding")


class PolicyBindingError(RuntimeError):
    """A policy binding could not be resolved (construction only)."""


@dataclass(frozen=True)
class ResolvedPolicy:
    """A resolved policy engine plus the source that refreshes it.

    What resolution produces — no enforcer. Each surface builds its own
    enforcer (with its own audit sender) from ``engine``.
    """

    engine: PolicyEngine
    source: PolicySource | None


def resolve_policy(
    agent_name: str,
    *,
    api_key: str | None = None,
    client: HexgateClient | None = None,
) -> ResolvedPolicy:
    """Resolve the current policy for ``agent_name``.

    Precedence: ``HEXGATE_LOCAL_POLICY`` override → platform (``client``
    or ``api_key``/``HEXGATE_API_KEY``) → raise. Eager and fail-loud; a
    platform 404 propagates as ``HexgateError``.
    """
    if not agent_name:
        raise PolicyBindingError(
            "resolve_policy() requires a non-empty agent name — "
            "it is the platform lookup key."
        )

    override = _local_policy_override()
    if override is not None:
        bundle, source = override
        return ResolvedPolicy(bundle, source)

    if client is None and resolve_api_key(api_key):
        from hexgate.cloud.client import HexgateClient, HexgateConfig

        client = HexgateClient(HexgateConfig.from_env(api_key=api_key))
    if client is not None:
        payload, etag = client.get_agent(agent_name)
        if payload is None:
            # Invariant: no If-None-Match was sent, so a 304 is impossible.
            # Raise so `python -O` can't strip the check.
            raise PolicyBindingError(
                f"HexgateClient.get_agent({agent_name!r}) returned no payload "
                "on initial fetch (no If-None-Match was sent)"
            )
        engine, source = platform_policy_from_payload(client, agent_name, payload, etag)
        return ResolvedPolicy(engine, source)

    raise PolicyBindingError(
        f"no policy available for agent {agent_name!r}: HEXGATE_API_KEY is "
        f"not set and {_LOCAL_POLICY_ENV_VAR} is not set. Set a "
        "credential, point the override at a policy, or construct "
        "PolicyBinding(PolicyEnforcer(engine)) explicitly."
    )


class PolicyBinding:
    """An enforcer plus the optional source that keeps it current.

    Role still resolves per tool call from the :class:`~hexgate.runtime.HexgateContext`
    contextvar, so one binding serves many concurrent users.
    """

    def __init__(
        self, enforcer: PolicyEnforcer, source: PolicySource | None = None
    ) -> None:
        self.enforcer = enforcer
        self.source = source

    def refresh(self) -> None:
        """Pull the current policy and swap it in; no-op without a source.

        Fail-soft: fetch/verification failures log a warning and keep
        the previous verified policy.
        """
        if self.source is None:
            return
        try:
            new_policy = self.source.fetch()
        except PolicyContentError as exc:
            # Dashboard-saved edit the runtime rejects → ERROR so the
            # UI/runtime drift is grep-able. Still fail-soft.
            logger.error(
                "policy refresh for agent %r rejected platform content: %s",
                getattr(self.enforcer, "agent_name", "?"),
                exc,
            )
            return
        except Exception as exc:  # noqa: BLE001 — refresh must not crash a run
            # Transient (network, 5xx, strict-mode signature refusal) — WARN.
            logger.warning(
                "policy refresh for agent %r failed: %s — keeping "
                "previously loaded policy",
                getattr(self.enforcer, "agent_name", "?"),
                exc,
            )
            return
        if new_policy is None or new_policy is self.enforcer.policy:
            return  # nothing served, or same cached object (304)
        self.enforcer.policy = new_policy

    async def refresh_async(self) -> None:
        """Async entry point — runs :meth:`refresh` off the event loop."""
        await asyncio.to_thread(self.refresh)


def platform_policy_from_payload(
    client: HexgateClient,
    agent_name: str,
    payload: dict,
    etag: str | None,
) -> tuple[PolicyEngine, PolicySource]:
    """Decode + verify a ``get_agent`` payload into ``(engine, seeded source)``.

    Signed bundle → WASM engine; bundle-less → pydantic engine on
    ``policy_yaml`` (forbidden under ``HEXGATE_BUNDLE_REQUIRE_SIGNATURE``).
    Shared by :func:`resolve_policy` and ``load_hexgate_agent``.
    """
    bundle = decode_and_verify_platform_bundle(payload, client.public_key_bytes())
    policy: PolicyEngine
    if bundle is not None:
        policy = bundle
    elif _truthy(os.environ.get(_REQUIRE_SIGNATURE_ENV_VAR)):
        raise PolicyBindingError(
            f"{_REQUIRE_SIGNATURE_ENV_VAR} is set but the platform served "
            f"no signed bundle for agent {agent_name!r} — the policy may "
            "not have compiled (is opa available on the control plane?). "
            "Refusing to fall back to the pydantic engine."
        )
    else:
        # Loud one-shot signal (fires at load time, not per turn) so an
        # operator running `hexgate serve` doesn't silently get the
        # pydantic engine when they expected the production-shaped
        # WASM path. Common cause: `opa` not installed on the platform
        # host — see compile_bundle() in platform/api/services.py, which
        # logs "opa not on PATH" on the server side too.
        logger.warning(
            "policy for %r served without a WASM bundle — falling back to "
            "the pydantic engine. Decisions are equivalent (parity-tested), "
            "but signature verification and signed-artifact distribution "
            "are off. Install `opa` on the platform host and re-save the "
            "policy to get the WASM path; set %s=true to refuse the "
            "fallback entirely.",
            agent_name,
            _REQUIRE_SIGNATURE_ENV_VAR,
        )
        policy = load_policy_set_from_dict(
            yaml.safe_load(payload.get("policy_yaml") or "") or {}
        )

    # Pre-seeded so the next refresh is a 304 (bundle path) or a cache
    # hit (pydantic-fallback path) unless the policy actually changed.
    # The yaml hash is only relevant on the pydantic-fallback path —
    # compute it from the same `policy_yaml` we just parsed above so the
    # source's first refresh comparison matches load-time exactly.
    import hashlib

    yaml_hash: str | None = None
    # (#3) Mirror fetch()'s guard: don't seed an ETag on the no-bundle
    # path or the first refresh could 304 and swallow an edit.
    seed_etag: str | None = etag
    if bundle is None:
        yaml_text = payload.get("policy_yaml") or ""
        yaml_hash = hashlib.sha256(yaml_text.encode("utf-8")).hexdigest()
        seed_etag = None
    source = PlatformPolicySource(
        client,
        agent_name,
        initial_engine=policy,
        initial_etag=seed_etag,
        initial_yaml_hash=yaml_hash,
    )
    return policy, source
