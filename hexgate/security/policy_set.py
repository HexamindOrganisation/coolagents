"""Role-aware policy bundles — load, resolve inheritance, pick by role.

A single ``policy.yaml`` is the legacy shape (one policy applies to every
caller). A ``policies/`` directory is the new shape:

    agent/
    ├── agent.yaml
    ├── system.md
    └── policies/
        ├── default.yaml      # fallback when the caller's roles are unknown
        ├── read_only.yaml    # mixin — is_mixin: true
        ├── support.yaml      # inherits: [read_only]
        └── billing.yaml      # inherits: [read_only, support]

A :class:`PolicySet` holds the resolved (post-inheritance) policy per role
name, plus the ``default`` fallback. The enforcer calls ``policy_for(role)``
once per role the caller carries; this module stays single-role.

``default`` is a *fallback*, not a *floor*: a caller whose role is defined never
inherits it. For a baseline shared by every role, use a mixin and ``inherits``.

Inheritance semantics: left-to-right merge — ``inherits: [A, B]`` resolves
to ``merge(A, merge(B, self))``, where ``merge`` deep-merges the ``tools``
maps (child entries override parent entries by tool name) and replaces
scalar fields (``default_policy``) with the child's value when set.

Mixin policies (``is_mixin: true``) can only be referenced via ``inherits``
— they're never picked as the effective policy for any context scope.
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

import yaml

from hexgate.security.constraints import iter_const_refs, parse_constraint
from hexgate.security.decision import Verdict
from hexgate.security.models import (
    AGENT_RUN_TOOL,
    AgentPolicy,
    AgentTargetPolicy,
    BaseToolPolicy,
    ToolPolicy,
    is_agent_reach_key,
    is_agent_via_key,
)

DEFAULT_ROLE_NAME = "default"


class PolicySetError(ValueError):
    """Raised when a role's policies/ directory is malformed."""


class PolicySet:
    """Resolved role-to-policy map for one agent.

    ``policies`` keys are role names; values are fully-resolved
    :class:`AgentPolicy` instances (inheritance flattened, mixins inlined).
    The ``default`` key is always present — it's what a lookup falls back to
    when a role is ``None`` or doesn't match any defined role.

    ``aliased_default`` names the role a loader *picked* as that fallback when
    the document declared none, so the analyzer can tell an authored ``default``
    from an inferred one. Injected rather than derived: only the loader knows
    which key it aliased, and by the time the map reaches here the alias is
    indistinguishable from a deliberate one.
    """

    def __init__(
        self,
        policies: dict[str, AgentPolicy],
        *,
        aliased_default: str | None = None,
    ) -> None:
        if DEFAULT_ROLE_NAME not in policies:
            raise PolicySetError(
                f"PolicySet missing required '{DEFAULT_ROLE_NAME}' role"
            )
        _validate_const_refs(policies)
        self._policies = policies
        self._aliased_default = aliased_default

    @property
    def aliased_default(self) -> str | None:
        """The named role ``default`` silently falls back to, if any.

        ``None`` when the document declared its own ``default`` (or is a legacy
        flat file, which *is* the default role). Otherwise every role name the
        policy doesn't define resolves to this role's grants.
        """
        return self._aliased_default

    def policy_for(self, role: str | None) -> AgentPolicy:
        """Return the effective policy for ``role`` (or the default fallback)."""
        if role is None:
            return self._policies[DEFAULT_ROLE_NAME]
        return self._policies.get(role, self._policies[DEFAULT_ROLE_NAME])

    def evaluate(
        self,
        *,
        role: str | None,
        tool: str,
        args: Mapping[str, Any],
        attributes: Mapping[str, Any] | None = None,
    ) -> Verdict:
        """:class:`~hexgate.security.decision.PolicyEngine` entry point.

        Resolves the role's policy and runs the pydantic engine. ``attributes``
        feed the ``ctx.*`` constraint namespace; the role still selects the
        policy bucket (``policy_for``) on its own."""
        from hexgate.security.policy import evaluate_tool_call

        return evaluate_tool_call(
            self.policy_for(role), tool, dict(args), role=role, attributes=attributes
        )

    @property
    def roles(self) -> list[str]:
        """List of role names, including ``default``, excluding mixins."""
        return sorted(self._policies)

    def declares_admission(self) -> bool:
        """True if any resolved role carries the ``agent.run`` key.

        Derived from ``effective_tools`` rather than a source field so it holds
        after inheritance and module folding, where the ``admission`` block has
        become an ``agent.run`` key (R-AGENT-002)."""
        return any(
            AGENT_RUN_TOOL in policy.effective_tools
            for policy in self._policies.values()
        )

    def declares_reach(self) -> bool:
        """True if any resolved role carries an ``agent.tool:`` / ``agent.handoff:`` key."""
        return any(
            any(is_agent_reach_key(key) for key in policy.effective_tools)
            for policy in self._policies.values()
        )

    def declares_tool_reach(self) -> bool:
        """True if any resolved role carries an ``agent.tool:`` (agent-as-tool) key."""
        return any(
            any(is_agent_via_key(key, "tool") for key in policy.effective_tools)
            for policy in self._policies.values()
        )

    def __contains__(self, role: str) -> bool:
        return role in self._policies

    def __repr__(self) -> str:
        return f"PolicySet(roles={self.roles!r})"


def _validate_const_refs(policies: Mapping[str, AgentPolicy]) -> None:
    """Reject a ``consts.<name>`` reference to a constant not defined for its role.

    Runs at :class:`PolicySet` construction so the pydantic engine and the Rego
    compiler agree on whether a policy is valid — otherwise an undefined const
    loads cleanly and denies at runtime on pydantic, but fails the WASM build.
    Constraints are already grammar-validated at model load; this is the
    cross-reference check that needs the role's resolved ``consts``.
    """
    for role, policy in policies.items():
        available = set(policy.consts)
        for tool_policy in (*policy.effective_tools.values(), policy.default_policy):
            for raw in tool_policy.constraints:
                for name in iter_const_refs(parse_constraint(raw)):
                    if name not in available:
                        raise PolicySetError(
                            f"role {role!r}: constraint {raw!r} references "
                            f"undefined constant consts.{name}"
                        )


def load_policy_set(source: str | Path | AgentPolicy | None) -> PolicySet:
    """Load a :class:`PolicySet` from disk, a single policy file, or an in-memory model.

    Three input shapes accepted:

    * ``Path`` pointing at a directory ending in ``policies`` — every
      ``*.yaml`` file inside is loaded as a role; the file stem is the role
      name. Inheritance is resolved and mixins are inlined.
    * ``Path`` pointing at a single YAML file (legacy ``policy.yaml``) —
      treated as the single ``default`` role; inheritance fields ignored.
    * An already-validated :class:`AgentPolicy` model — used as the
      ``default`` role; useful in tests.

    A ``PolicySet`` always carries a ``default`` role. If the directory
    doesn't ship a ``default.yaml``, the most-permissive non-mixin role
    becomes the fallback — operators should ship an explicit
    ``default.yaml`` to avoid this guesswork.
    """
    if source is None:
        return PolicySet({DEFAULT_ROLE_NAME: AgentPolicy()})
    if isinstance(source, AgentPolicy):
        return PolicySet({DEFAULT_ROLE_NAME: source})

    path = Path(source)
    if path.is_dir():
        return _load_from_directory(path)
    return _load_legacy_file(path)


def load_policy_map(
    policy_map: dict[str, AgentPolicy], default: str | None = None
) -> PolicySet:
    """Build a :class:`PolicySet` from a plain ``{role: AgentPolicy}`` dict.

    Used by the cloud loader and by inline-roles ``policy.yaml`` files. Each
    role's ``inherits`` field is resolved against the rest of the map before
    mixin filtering — mirrors the ``_load_from_directory`` path so both
    storage shapes produce the same effective policies.

    ``default`` names the role to use as the fallback. Defaults to
    ``"default"`` if the dict contains it, otherwise the alphabetically first
    concrete role — matching what a ``policies/`` directory infers.
    """
    if not policy_map:
        raise PolicySetError("policy_map must contain at least one role")
    # Resolve inheritance against the full map (including mixins, which can
    # only be referenced via ``inherits``).
    fully_resolved: dict[str, AgentPolicy] = {}
    for role_name in policy_map:
        fully_resolved[role_name] = _resolve_inheritance(
            role_name, policy_map, chain=[]
        )
    resolved = {name: pol for name, pol in fully_resolved.items() if not pol.is_mixin}
    if not resolved:
        raise PolicySetError("policy_map contains only mixins; need a concrete role")
    # An explicit ``default=`` is the caller's deliberate choice; only the
    # fallback we *infer* here is worth warning about downstream.
    inferred = default is None and DEFAULT_ROLE_NAME not in resolved
    # ``sorted()``, not insertion order: ``_load_from_directory`` infers its
    # fallback alphabetically, and the same role set must resolve undefined role
    # names to the same policy however the document was loaded.
    default_name = default or (
        DEFAULT_ROLE_NAME if DEFAULT_ROLE_NAME in resolved else sorted(resolved)[0]
    )
    if default_name not in resolved:
        raise PolicySetError(
            f"requested default role {default_name!r} not in {sorted(resolved)!r}"
        )
    if default_name != DEFAULT_ROLE_NAME:
        resolved[DEFAULT_ROLE_NAME] = resolved[default_name]
    return PolicySet(resolved, aliased_default=default_name if inferred else None)


def _load_legacy_file(path: Path) -> PolicySet:
    """Load a single ``policy.yaml`` — flat or inline-roles shape."""
    payload = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return load_policy_set_from_dict(payload)


def load_policy_set_from_dict(payload: dict[str, Any]) -> PolicySet:
    """Build a :class:`PolicySet` from an already-parsed YAML document.

    Detects which shape the document carries and dispatches accordingly:

    * **Inline roles shape** — has a top-level ``roles:`` key whose value is
      a mapping of ``{role_name: agent_policy_spec}``. Each value is validated
      as an :class:`AgentPolicy`; the resulting map is wrapped via
      :func:`load_policy_map` so inheritance and mixin filtering apply.

    * **Flat single-policy shape** (legacy) — anything else is treated as a
      single :class:`AgentPolicy` and wrapped as the ``default`` role.

    Used by the cloud loader (the platform returns one ``policy_yaml`` string
    per agent, with roles potentially inline) and by ``_load_legacy_file``
    for SDK-local agents.
    """
    if isinstance(payload.get("roles"), dict):
        role_policies = {
            role_name: AgentPolicy.model_validate(spec or {})
            for role_name, spec in payload["roles"].items()
        }
        return load_policy_map(role_policies)
    return PolicySet({DEFAULT_ROLE_NAME: AgentPolicy.model_validate(payload)})


def _load_from_directory(root: Path) -> PolicySet:
    """Walk ``root/*.yaml``, parse each as an :class:`AgentPolicy`, resolve inheritance."""
    raw: dict[str, AgentPolicy] = {}
    for file in sorted(root.glob("*.yaml")):
        name = file.stem
        payload = yaml.safe_load(file.read_text(encoding="utf-8")) or {}
        try:
            raw[name] = AgentPolicy.model_validate(payload)
        except Exception as exc:
            raise PolicySetError(f"policy {file.name!r} is invalid: {exc}") from exc
    if not raw:
        raise PolicySetError(f"no policy files found in {root}")

    resolved: dict[str, AgentPolicy] = {}
    for name in raw:
        resolved[name] = _resolve_inheritance(name, raw, chain=[])

    concrete = {name: pol for name, pol in resolved.items() if not pol.is_mixin}
    if not concrete:
        raise PolicySetError(
            f"every policy in {root} is a mixin; need at least one concrete role"
        )

    aliased: str | None = None
    if DEFAULT_ROLE_NAME not in concrete:
        # No explicit default — pick the first concrete role alphabetically and
        # alias it as the fallback. Loud but not fatal; operators should drop
        # in an explicit default.yaml, which the ``implicit-default`` lint says.
        aliased = sorted(concrete)[0]
        concrete[DEFAULT_ROLE_NAME] = concrete[aliased]
    return PolicySet(concrete, aliased_default=aliased)


def _resolve_inheritance(
    name: str, raw: dict[str, AgentPolicy], chain: list[str]
) -> AgentPolicy:
    """Recursively flatten ``inherits`` for one role.

    ``inherits: [A, B]`` means the parents are merged in declaration order,
    then this role's own fields overlay last. Equivalent to Python's MRO
    with explicit precedence: ``self`` wins, then later parents, then
    earlier parents.
    """
    if name in chain:
        raise PolicySetError(f"cyclic inheritance: {' -> '.join(chain + [name])}")
    if name not in raw:
        raise PolicySetError(
            f"role {name!r} not found (inherited from {chain[-1] if chain else '<root>'})"
        )
    own = raw[name]
    if not own.inherits:
        return own
    merged_tools: dict[str, ToolPolicy] = {}
    merged_agents: dict[str, AgentTargetPolicy] = {}
    merged_consts: dict[str, object] = {}
    merged_default: BaseToolPolicy = own.default_policy
    merged_admission: BaseToolPolicy | None = own.admission

    # Merge parents left-to-right (later parents override earlier). ``agents``
    # merges by target name like ``tools`` does. ``admission`` only overwrites when
    # a parent actually sets one, so a later mixin that omits it can't null out an
    # earlier parent's rule — dropping an agent gate silently would be fail-open.
    for parent_name in own.inherits:
        parent = _resolve_inheritance(parent_name, raw, chain + [name])
        merged_tools.update(parent.tools)
        merged_agents.update(parent.agents)
        merged_consts.update(parent.consts)
        merged_default = parent.default_policy
        if parent.admission is not None:
            merged_admission = parent.admission

    # Self overrides everything from parents. Check ``model_fields_set`` rather
    # than comparing against ``BaseToolPolicy()``: a child that explicitly says
    # ``default_policy: { mode: deny }`` is value-equal to the default but the
    # user's intent is to override, and silently inheriting an ``allow`` from a
    # parent would be fail-open.
    merged_tools.update(own.tools)
    merged_agents.update(own.agents)
    merged_consts.update(own.consts)
    if "default_policy" in own.model_fields_set:
        merged_default = own.default_policy
    if "admission" in own.model_fields_set:
        merged_admission = own.admission

    return AgentPolicy(
        version=own.version,
        inherits=own.inherits,
        is_mixin=own.is_mixin,
        default_policy=merged_default,
        tools=merged_tools,
        consts=merged_consts,
        admission=merged_admission,
        agents=merged_agents,
    )
