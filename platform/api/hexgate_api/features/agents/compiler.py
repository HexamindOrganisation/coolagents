"""Policy → signed-WASM-bundle compilation + starter-policy generation.

Split out of the agents service so the DB/registration logic there stays free
of the SDK/opa shell-out and the tool-name heuristics used to seed a
brand-new agent's ``policy_yaml``.
"""

import logging
from typing import Callable

from hexgate_api.schemas import AgentManifest

logger = logging.getLogger("hexgate.platform.agents.compiler")

# Fail-closed starter policy for a brand-new agent in a MODULAR project. The
# agent's real enforcement is the shared modular bundle; policy_yaml is only the
# SDK's pydantic fallback if that bundle can't be built or served (e.g. opa
# down). A modular agent must fall back to deny-all, not to a permissive
# tool-derived starter — otherwise a transient compile failure fails open.
DENY_ALL_POLICY_YAML = "version: 1\ndefault_policy:\n  mode: deny\n"


def compile_bundle(
    policy_yaml: str, sign: Callable[[bytes], bytes]
) -> tuple[bytes, str, bytes] | None:
    """Compile ``policy_yaml`` to a signed WASM bundle.

    Runs the SDK's YAML → Rego → WASM compiler, builds a manifest with the
    content hashes, and signs the manifest's exact bytes with ``sign`` (the
    platform's root key). Returns ``(wasm_bytes, manifest_text, signature)``,
    or ``None`` when compilation can't happen — ``opa`` not installed, or the
    policy is malformed. A ``None`` return is not an error: the caller stores
    no bundle and the SDK falls back to the pydantic engine.

    Stays sync because it doesn't touch the DB — only shells out to ``opa``
    via the SDK. Callers run it inside an async handler via the default
    threadpool (``asyncio.to_thread``) if they need to keep the event loop
    responsive during a long compile; for our tiny policies a direct call
    is fine.
    """
    # Imported lazily so the platform still boots if the SDK / opa aren't
    # present — only save-time compilation needs them. build_signed_bundle
    # is the SAME helper `hexgate policy build` uses, so the manifest format
    # and its byte-exact serialization can't drift between the two.
    from hexgate.security import build_signed_bundle
    from hexgate.security.rego_wasm import OpaNotFoundError

    try:
        bundle = build_signed_bundle(policy_yaml, sign=sign)
    except OpaNotFoundError:
        logger.warning(
            "compile_bundle: opa not on PATH — storing no bundle "
            "(SDK will fall back to pydantic). Install opa to ship signed bundles."
        )
        return None
    except Exception as exc:
        # Any other compile failure (bad constraint, schema error, opa build
        # error) degrades gracefully — the save still succeeds without a bundle.
        logger.warning("compile_bundle: policy did not compile: %s", exc)
        return None

    return bundle.wasm_bytes, bundle.manifest_bytes.decode("utf-8"), bundle.signature


# Tool-name heuristics used by ``_classify_tool`` to bucket a tool into one of
# four categories. Matched against the LOWERCASED tool name with a substring
# search — so ``Read_File`` and ``read_file`` both land in "read". The
# patterns are deliberately broad: misclassification on a brand-new agent is
# a one-time editing chore, while missing a write-shape tool would silently
# hand a freshly-registered agent more power than the operator intended.
_SHELL_PATTERNS = (
    "bash",
    "shell",
    "exec",
    "run_command",
    "subprocess",
    "spawn",
)
_WRITE_PATTERNS = (
    "write_",
    "_write",
    "edit_",
    "create_",
    "update_",
    "delete_",
    "remove_",
    "patch_",
    "post_",
    "put_",
)
_READ_PATTERNS = (
    "read_",
    "_read",
    "search",
    "fetch",
    "list_",
    "get_",
    "find_",
    "grep",
    "glob",
    "view_",
    "describe_",
    "inspect_",
)


def _classify_tool(name: str) -> str:
    """Return one of ``"read" | "write" | "shell" | "unknown"`` for a tool name.

    Order matters: shell wins over write (a tool literally named
    ``run_command`` matches both ``run_command`` and ``_command``), and read
    is checked last so write-prefix takes precedence over a misleading
    ``read_`` substring elsewhere in the name.

    ``"unknown"`` is the fail-closed bucket — callers should treat it as
    write-shape so a brand-new agent doesn't silently inherit power the
    operator didn't authorize.
    """
    lower = name.lower()
    if any(p in lower for p in _SHELL_PATTERNS):
        return "shell"
    if any(p in lower for p in _WRITE_PATTERNS):
        return "write"
    if any(p in lower for p in _READ_PATTERNS):
        return "read"
    return "unknown"


def _emit_tool_lines(names: list[str], mode: str, indent: int = 6) -> str:
    """Render ``{name: { mode: ... }}`` lines for a YAML policy block.

    Returns an empty string when ``names`` is empty — the caller can drop
    the surrounding ``tools:`` key entirely if all its buckets are empty,
    keeping the generated YAML clean (no dangling ``tools:`` with no
    children, which the AgentPolicy validator rejects).
    """
    pad = " " * indent
    return "".join(f"{pad}{n}: {{ mode: {mode} }}\n" for n in names)


def _default_policy_for_manifest(manifest: AgentManifest) -> str:
    """Build a starter role-aware ``policy_yaml`` from a manifest's tools.

    Modeled on the ``support_bot`` seed at :mod:`hexgate_api.features.agents.seed_data`:

      - ``read_only`` (mixin) — every read-shape tool from the manifest.
      - ``default`` — inherits ``read_only``, used when no User scope is set.
      - ``member`` — inherits ``read_only``; writes + shells + unknowns
        require approval.
      - ``admin`` — inherits ``read_only``; writes pass through, shells
        still require approval.

    Unknown tools (those that didn't match any heuristic) land in the
    write bucket — fail-closed, surfaced to the operator via a comment so
    they can reclassify in the dashboard editor.

    Only called for brand-new agents (first POST /v1/agents for a given
    name); re-registers of an existing agent leave the operator's edited
    policy alone.
    """
    reads: list[str] = []
    writes: list[str] = []
    shells: list[str] = []
    unknowns: list[str] = []
    for tool in manifest.tools:
        bucket = _classify_tool(tool.name)
        if bucket == "read":
            reads.append(tool.name)
        elif bucket == "shell":
            shells.append(tool.name)
        elif bucket == "write":
            writes.append(tool.name)
        else:
            unknowns.append(tool.name)

    # Heads-up comment for unknown-bucket tools — the operator sees them
    # in the dashboard editor and can move them to a more appropriate
    # bucket. Empty when every tool classified cleanly.
    unknown_note = (
        "# Heuristic could not classify these tools — treating as writes\n"
        "# (fail-closed). Move them to read_only or shells as appropriate:\n"
        + "".join(f"#   - {n}\n" for n in unknowns)
        + "\n"
        if unknowns
        else ""
    )

    # ``read_only`` body — drop the ``tools:`` key when the manifest has
    # zero read-shape tools to avoid emitting ``tools:`` with no children
    # (rejected by the policy parser).
    read_only_tools = f"    tools:\n{_emit_tool_lines(reads, 'allow')}" if reads else ""

    # member + admin override blocks. ``writes + unknowns`` always get the
    # role-appropriate mode; shells are pinned to approval_required across
    # both roles because shells are the highest-blast-radius primitive
    # and shouldn't differ between operator personas.
    member_overrides = writes + unknowns + shells
    member_tools = (
        f"    tools:\n"
        f"{_emit_tool_lines(writes + unknowns, 'approval_required')}"
        f"{_emit_tool_lines(shells, 'approval_required')}"
        if member_overrides
        else ""
    )
    admin_overrides = writes + unknowns + shells
    admin_tools = (
        f"    tools:\n"
        f"{_emit_tool_lines(writes + unknowns, 'allow')}"
        f"{_emit_tool_lines(shells, 'approval_required')}"
        if admin_overrides
        else ""
    )

    return f"""version: 1
# Generated by `hexgate register`. Edit freely — re-running register
# never overwrites this; it only updates the manifest snapshot.
#
# Four entries:
#   read_only  (mixin)  factored-out 'safe to read' allowlist
#   default             fallback when no User scope is set
#   member              typical user; writes + shells require approval
#   admin               power user; writes allow, shells still gate
#
# Note: 'admin' here is an AGENT policy role (used by the SDK at request
# time via User(role="admin")), distinct from the ORG admin role on
# /orgs/:id/members.

{unknown_note}roles:
  read_only:
    is_mixin: true
    default_policy:
      mode: deny
{read_only_tools}
  default:
    inherits: [read_only]

  member:
    inherits: [read_only]
{member_tools}
  admin:
    inherits: [read_only]
{admin_tools}"""
