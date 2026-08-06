"""`hexgate policy` subcommand — author + inspect + dry-run policy documents.

Wraps the compiler library and both enforcement engines in a five-verb
CLI: ``build``, ``validate``, ``show-rego``, ``test``, ``keygen``. Every
verb is a thin wrapper — the heavy lifting lives in
:mod:`hexgate.security`. That symmetry lets the platform's save flow use
the same code without duplication.

``build`` compiles the policy to a signed WASM bundle (yaml + rego +
wasm + manifest, ``--sign-key`` to sign); ``test`` evaluates a decision
through either engine (``--engine pydantic`` by default, ``--engine
wasm`` to run the compiled module).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError
from yaml.error import MarkedYAMLError

from hexgate.security import (
    AgentPolicy,
    DecisionOutcome,
    DEFAULT_ROLE_NAME,
    OpaNotFoundError,
    PolicySetError,
    SignatureError,
    Verdict,
    WasmCompileError,
    WasmEvalError,
    WasmPolicy,
    build_signed_bundle,
    compile_to_rego,
    compile_to_wasm,
    decode_key,
    encode_key,
    evaluate_tool_call,
    generate_keypair,
    load_policy_set_from_dict,
    sign_bytes,
    verdict_from_rego,
)
from hexgate.security.constraints import ConstraintParseError, parse_constraint


# ---------------------------------------------------------------------------
# Argparse wiring
# ---------------------------------------------------------------------------


def add_parser(subparsers: argparse._SubParsersAction) -> None:
    """Register the ``policy`` subcommand on the top-level hexgate CLI."""
    parser = subparsers.add_parser(
        "policy",
        help="Author, inspect, and dry-run agent policy documents.",
        description="Author, inspect, and dry-run agent policy documents.",
    )
    sub = parser.add_subparsers(dest="policy_cmd", required=True, metavar="subcommand")

    # ---- build ----
    p_build = sub.add_parser(
        "build",
        help="Compile a policy.yaml to a bundle (yaml + rego + wasm).",
        description=(
            "Compile a policy.yaml to a bundle directory. Produces the "
            "original yaml, the compiled rego, the wasm module, and a "
            "bundle.json manifest with content hashes. Skip the wasm step "
            "with --no-wasm when opa is not available."
        ),
    )
    p_build.add_argument("source", help="Path to the source policy.yaml file.")
    p_build.add_argument(
        "--out",
        default=None,
        help="Output directory (defaults to the source file's directory).",
    )
    p_build.add_argument(
        "--no-wasm",
        action="store_true",
        help="Skip the opa build -t wasm step (useful when opa is unavailable).",
    )
    p_build.add_argument(
        "--sign-key",
        default=None,
        metavar="PATH",
        help=(
            "Path to an Ed25519 private key (base64url, from `hexgate policy "
            "keygen`). When set, signs the bundle manifest and writes a "
            "detached {stem}.bundle.json.sig. Production bundles come signed "
            "by the platform; this flag is for local/CI signing."
        ),
    )
    p_build.set_defaults(func=_main_build)

    # ---- keygen ----
    p_keygen = sub.add_parser(
        "keygen",
        help="Generate an Ed25519 keypair for signing bundles locally.",
        description=(
            "Write a fresh Ed25519 keypair (raw keys, base64url-encoded) to "
            "disk: <out>.private for signing (`build --sign-key`) and "
            "<out>.public for verifying (HEXGATE_BUNDLE_PUBKEY_PATH). For "
            "local/CI use — production signing keys live in the platform "
            "keystore."
        ),
    )
    p_keygen.add_argument(
        "--out",
        required=True,
        metavar="PREFIX",
        help="Output path prefix; writes PREFIX.private + PREFIX.public.",
    )
    p_keygen.add_argument(
        "--force",
        action="store_true",
        help="Overwrite existing key files at the prefix.",
    )
    p_keygen.set_defaults(func=_main_keygen)

    # ---- validate ----
    p_val = sub.add_parser(
        "validate",
        help="Parse the YAML and check every constraint against the grammar.",
        description=(
            "Runs the same checks the platform's /validate endpoint does, "
            "but locally — no network needed. Exits 0 on success, 1 on any "
            "error (with all errors printed)."
        ),
    )
    p_val.add_argument("source", help="Path to the policy.yaml file.")
    p_val.set_defaults(func=_main_validate)

    # ---- show-rego ----
    p_show = sub.add_parser(
        "show-rego",
        help="Compile the policy and print the resulting Rego to stdout.",
        description=(
            "Useful for spotting what Rego rules your YAML produces, before "
            "you trust them in production. Output goes to stdout so you can "
            "pipe it to a file or opa eval."
        ),
    )
    p_show.add_argument("source", help="Path to the policy.yaml file.")
    p_show.set_defaults(func=_main_show_rego)

    # ---- test ----
    p_test = sub.add_parser(
        "test",
        help="Dry-run a tool-call decision against the policy.",
        description=(
            "Evaluates the policy against the given role/tool/args without "
            "spinning up the agent. Prints ALLOW / DENY / APPROVAL_REQUIRED "
            "with the offending constraint when relevant. Designed for "
            "CI policy-test suites."
        ),
    )
    p_test.add_argument("source", help="Path to the policy.yaml file.")
    p_test.add_argument(
        "--role",
        required=True,
        help='Role to evaluate as, e.g. "billing".',
    )
    p_test.add_argument(
        "--tool",
        required=True,
        help='Tool the agent is calling, e.g. "refund_order".',
    )
    p_test.add_argument(
        "--args",
        default="{}",
        help='Tool arguments as a JSON object (e.g. \'{"amount": 30, "currency": "USD"}\'). Defaults to {}.',
    )
    p_test.add_argument(
        "--attributes",
        default="{}",
        help=(
            "Caller ABAC attributes as a JSON object, exposed to ctx.* "
            'constraints (e.g. \'{"department": "finance", "clearance_level": 3}\'). '
            "JSON (not key=value) so numbers/bools keep their type and match "
            "production. Defaults to {}."
        ),
    )
    p_test.add_argument(
        "--engine",
        choices=("pydantic", "wasm"),
        default="pydantic",
        help=(
            "Decision engine: pydantic (default — fast, no opa needed) or "
            "wasm (compiles the policy via opa and evaluates in wasmtime; "
            "matches what production will run)."
        ),
    )
    p_test.set_defaults(func=_main_test)

    # ---- resolve ----
    p_resolve = sub.add_parser(
        "resolve",
        help="Link a bundle of policy modules into one effective policy.",
        description=(
            "Loads boundary + capability modules from <dir>/policies/, composes "
            "them (fences intersect, grants union, denies win) into a single "
            "effective policy, and prints it. The intermediate artifact between "
            "many module files and the signed WASM bundle — inspect it to see "
            "exactly what the engines will enforce."
        ),
    )
    p_resolve.add_argument(
        "--dir",
        default=".",
        help="Repo root containing a policies/ tree (default: current dir).",
    )
    p_resolve.add_argument(
        "-o",
        "--output",
        help="Write the effective policy YAML here (default: stdout).",
    )
    p_resolve.set_defaults(func=_main_resolve)


def main(args: argparse.Namespace) -> int:
    """Entry point used by the top-level dispatcher in hexgate/cli/__init__.py."""
    return args.func(args)


# ---------------------------------------------------------------------------
# Subcommand handlers
# ---------------------------------------------------------------------------


def _main_keygen(args: argparse.Namespace) -> int:
    """Generate an Ed25519 keypair and write it base64url-encoded to disk."""
    prefix = Path(args.out)
    private_out = prefix.with_name(prefix.name + ".private")
    public_out = prefix.with_name(prefix.name + ".public")

    if not args.force:
        for existing in (private_out, public_out):
            if existing.exists():
                print(
                    f"{existing} already exists — pass --force to overwrite.",
                    file=sys.stderr,
                )
                return 1

    parent = prefix.parent
    if str(parent):
        parent.mkdir(parents=True, exist_ok=True)

    private_raw, public_raw = generate_keypair()
    # 0600 the private key — it's a signing secret.
    private_out.write_text(encode_key(private_raw) + "\n", encoding="utf-8")
    private_out.chmod(0o600)
    public_out.write_text(encode_key(public_raw) + "\n", encoding="utf-8")

    print(f"✓ Wrote {private_out} (private signing key — keep secret, .gitignore it)")
    print(f"✓ Wrote {public_out} (public verify key)")
    print(
        "\nSign a bundle:   hexgate policy build <policy.yaml> "
        f"--sign-key {private_out}"
    )
    print(f"Verify at runtime:  export HEXGATE_BUNDLE_PUBKEY_PATH={public_out}")
    return 0


def _main_build(args: argparse.Namespace) -> int:
    """Compile + write the bundle artifacts (yaml + rego + wasm [+ signature])."""
    source_path = Path(args.source)
    source_text, payload, err = _read_and_parse(source_path)
    if err is not None:
        print(err, file=sys.stderr)
        return 1

    # Load the signing key early so a bad key fails before we write anything.
    sign_key: bytes | None = None
    if getattr(args, "sign_key", None):
        sign_key, err = _read_signing_key(Path(args.sign_key))
        if err is not None:
            print(err, file=sys.stderr)
            return 1

    # One source of truth for compile + manifest + sign — shared with the
    # platform's save-time pipeline (see build_signed_bundle). We only
    # translate its exceptions into the CLI's print + exit-code UX here.
    sign_cb = (
        (lambda data: sign_bytes(data, sign_key)) if sign_key is not None else None
    )
    try:
        bundle = build_signed_bundle(
            source_text,
            source_name=source_path.name,
            sign=sign_cb,
            compile_wasm=not args.no_wasm,
        )
    except (PolicySetError, ConstraintParseError, ValidationError) as exc:
        print(f"compile error: {exc}", file=sys.stderr)
        return 1
    except OpaNotFoundError as exc:
        print(
            f"wasm compile skipped — {exc}\n"
            "Pass --no-wasm to suppress this and emit yaml+rego only.",
            file=sys.stderr,
        )
        return 1
    except WasmCompileError as exc:
        print(f"wasm compile error: {exc}", file=sys.stderr)
        return 1

    # Resolve to an absolute path up front so all derived paths are
    # unambiguous — a relative --out otherwise breaks the relative_to()
    # display math below.
    out_dir = (Path(args.out) if args.out else source_path.parent).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    stem = source_path.stem  # "billing.yaml" → "billing"
    yaml_out = out_dir / f"{stem}.yaml"
    rego_out = out_dir / f"{stem}.rego"
    wasm_out = out_dir / f"{stem}.wasm"
    bundle_out = out_dir / f"{stem}.bundle.json"

    # Always rewrite the trio so the bundle stays consistent — if the dev
    # is reusing the source dir as the output dir, the YAML write is a
    # no-op (same bytes).
    yaml_out.write_text(source_text, encoding="utf-8")
    rego_out.write_text(bundle.rego_text, encoding="utf-8")
    wasm_bytes = bundle.wasm_bytes
    if wasm_bytes is not None:
        wasm_out.write_bytes(wasm_bytes)
    bundle_out.write_bytes(bundle.manifest_bytes)

    sig_out = out_dir / f"{stem}.bundle.json.sig"
    if bundle.signature is not None:
        sig_out.write_bytes(bundle.signature)

    print(f"✓ Wrote {_display_path(yaml_out)}")
    print(f"✓ Wrote {_display_path(rego_out)}")
    if wasm_bytes is not None:
        print(f"✓ Wrote {_display_path(wasm_out)}")
    else:
        print("ⓘ wasm step skipped (--no-wasm)", file=sys.stderr)
    print(f"✓ Wrote {_display_path(bundle_out)}")
    if sign_key is not None:
        print(f"✓ Wrote {_display_path(sig_out)} (signed)")
    return 0


def _main_validate(args: argparse.Namespace) -> int:
    """Mirror the platform's /validate endpoint, locally."""
    source_path = Path(args.source)
    source_text, payload, err = _read_and_parse(source_path)
    if err is not None:
        print(err, file=sys.stderr)
        return 1

    errors: list[str] = []

    # Constraint grammar check on the raw payload FIRST, so a bad expression
    # reports as "role → tool: <error>" — friendlier than the raw pydantic
    # ValidationError the model-level grammar validator would raise at load.
    for role, tool_name, raw in _iter_raw_constraints(payload):
        try:
            parse_constraint(raw)
        except ConstraintParseError as exc:
            errors.append(f"{role} → {tool_name}: {exc}")

    if errors:
        print(f"{len(errors)} constraint error(s):", file=sys.stderr)
        for e in errors:
            print(f"  • {e}", file=sys.stderr)
        return 1

    # Schema + inheritance + mixin validation (constraints already clean above).
    try:
        load_policy_set_from_dict(payload)
    except (PolicySetError, ValidationError) as exc:
        print(f"policy schema: {exc}", file=sys.stderr)
        return 1

    # Run the full Rego compile (minus the opa/wasm step) so validate is a
    # strict subset of build — catches const conflicts, file_scope-in-wasm, and
    # any other build-time rejection. Otherwise validate could pass a policy
    # the platform build then refuses, giving false confidence in CI.
    try:
        compile_to_rego(payload)
    except (PolicySetError, ConstraintParseError, ValidationError) as exc:
        print(f"policy build: {exc}", file=sys.stderr)
        return 1

    print("✓ Policy parses cleanly.")
    return 0


def _iter_raw_constraints(payload: dict) -> "list[tuple[str, str, str]]":
    """Yield ``(role, tool, raw_constraint)`` over an unvalidated policy payload.

    Handles both document shapes: inline-roles (``payload["roles"]``) and the
    flat single-policy form (tools at the top level → the ``default`` role).
    Defensive against partially-malformed payloads — non-dict tools/specs are
    skipped so the schema validator downstream reports them.
    """
    roles = payload.get("roles")
    specs = (
        list(roles.items())
        if isinstance(roles, dict)
        else [(DEFAULT_ROLE_NAME, payload)]
    )

    def _emit(role: str, tool_name: str, tool_policy: object) -> None:
        raws = tool_policy.get("constraints") if isinstance(tool_policy, dict) else None
        for raw in raws or []:
            if isinstance(raw, str):
                out.append((role, tool_name, raw))

    out: list[tuple[str, str, str]] = []
    for role, spec in specs:
        if not isinstance(spec, dict):
            continue
        # The role's catch-all policy also carries constraints — report a bad
        # expression there under "<default>" instead of letting the schema
        # load raise a raw, unlocalized ValidationError.
        _emit(role, "<default>", spec.get("default_policy"))
        tools = spec.get("tools")
        if isinstance(tools, dict):
            for tool_name, tool_policy in tools.items():
                _emit(role, tool_name, tool_policy)
    return out


def _main_show_rego(args: argparse.Namespace) -> int:
    """Compile + print to stdout. No file writes."""
    source_path = Path(args.source)
    source_text, payload, err = _read_and_parse(source_path)
    if err is not None:
        print(err, file=sys.stderr)
        return 1
    try:
        rego = compile_to_rego(
            payload,
            source_hash=hashlib.sha256(source_text.encode("utf-8")).hexdigest(),
        )
    except (PolicySetError, ConstraintParseError, ValidationError) as exc:
        print(f"compile error: {exc}", file=sys.stderr)
        return 1
    sys.stdout.write(rego)
    return 0


def _main_resolve(args: argparse.Namespace) -> int:
    """Link the local module bundle into one effective policy and print it."""
    from hexgate.security import (
        LinkError,
        link_policy_set,
        load_local_modules,
    )

    try:
        boundaries, capabilities = load_local_modules(args.dir)
    except (ValueError, OSError) as exc:
        print(f"load error: {exc}", file=sys.stderr)
        return 1
    if not boundaries and not capabilities:
        print(
            f"no modules found under {args.dir}/policies/"
            " (expected policies/boundaries/ and/or policies/capabilities/)",
            file=sys.stderr,
        )
        return 1

    try:
        result = link_policy_set(boundaries, capabilities)
    except (LinkError, PolicySetError, ConstraintParseError, ValidationError) as exc:
        print(f"link error: {exc}", file=sys.stderr)
        return 1

    effective = result.effective[DEFAULT_ROLE_NAME]
    # Full dump (not exclude_defaults): a tool set to the default `deny` mode
    # would otherwise render as `{}`, hiding the outcome in an inspection view.
    text = yaml.safe_dump(effective.model_dump(mode="json"), sort_keys=False)
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
        print(f"✓ wrote effective policy to {args.output}")
    else:
        sys.stdout.write(text)

    # Provenance to stderr so stdout stays a clean policy document.
    print("\nlayers (resolution order):", file=sys.stderr)
    for prov in result.layers:
        print(f"  [{prov.kind:10}] {prov.module}  ({prov.source})", file=sys.stderr)
    if result.trace.shadowed:
        print("shadowed (ineligible under a ceiling):", file=sys.stderr)
        for tool, by in sorted(result.trace.shadowed.items()):
            print(f"  {tool}  ← {by.module} ({by.source})", file=sys.stderr)
    return 0


def _main_test(args: argparse.Namespace) -> int:
    """Dry-run a single (role, tool, args) decision through the chosen engine."""
    source_path = Path(args.source)
    source_text, payload, err = _read_and_parse(source_path)
    if err is not None:
        print(err, file=sys.stderr)
        return 1

    try:
        tool_args: dict[str, Any] = json.loads(args.args)
    except json.JSONDecodeError as exc:
        print(f"--args is not valid JSON: {exc}", file=sys.stderr)
        return 1
    if not isinstance(tool_args, dict):
        print("--args must be a JSON object (dict).", file=sys.stderr)
        return 1

    try:
        attributes: dict[str, Any] = json.loads(getattr(args, "attributes", "{}"))
    except json.JSONDecodeError as exc:
        print(f"--attributes is not valid JSON: {exc}", file=sys.stderr)
        return 1
    if not isinstance(attributes, dict):
        print("--attributes must be a JSON object (dict).", file=sys.stderr)
        return 1

    try:
        policy_set = load_policy_set_from_dict(payload)
    except (PolicySetError, ValidationError) as exc:
        print(f"policy schema: {exc}", file=sys.stderr)
        return 1

    if args.role not in policy_set:
        print(
            f'role "{args.role}" not in policy (known roles: {policy_set.roles!r})',
            file=sys.stderr,
        )
        return 1

    label = f"{args.role} → {args.tool}({json.dumps(tool_args, sort_keys=True)})"
    engine = getattr(args, "engine", "pydantic")

    if engine == "wasm":
        return _test_via_wasm(
            payload, args.role, args.tool, tool_args, attributes, label
        )
    return _test_via_pydantic(
        policy_set, args.role, args.tool, tool_args, attributes, label
    )


def _render_verdict(verdict: Verdict, label: str) -> int:
    """Print a verdict uniformly and return the process exit code.

    Shared by both engines so pydantic and wasm decisions render the same
    — including the structured ``violations`` / ``hint`` detail when the
    engine produced it.
    """
    if verdict.outcome is DecisionOutcome.ALLOW:
        print(f"✓ ALLOW · {label}")
        return 0
    if verdict.outcome is DecisionOutcome.NEEDS_APPROVAL:
        print(f"⚠ APPROVAL_REQUIRED · {label}\n  reason: {verdict.reason}")
        return 0
    print(f"✗ DENY · {label}\n  reason: {verdict.reason}")
    if verdict.violations:
        print("  violations:")
        for v in verdict.violations:
            print(f"    • {v}")
    if verdict.hint is not None:
        print(f"  hint: {verdict.hint}")
    return 1


def _test_via_pydantic(
    policy_set: Any,
    role: str,
    tool: str,
    tool_args: dict,
    attributes: dict,
    label: str,
) -> int:
    """Run the decision through the in-process constraint evaluator."""
    policy: AgentPolicy = policy_set.policy_for(role)
    # Forward role AND attributes so role-scoped (role == "admin") and ctx.*
    # constraints decide the same as the wasm path and production — omitting
    # either here made `policy test` fail closed on rules production allows.
    return _render_verdict(
        evaluate_tool_call(policy, tool, tool_args, role=role, attributes=attributes),
        label,
    )


def _test_via_wasm(
    payload: dict,
    role: str,
    tool: str,
    tool_args: dict,
    attributes: dict,
    label: str,
) -> int:
    """Compile to wasm on the fly + evaluate — matches production semantics."""
    try:
        rego = compile_to_rego(payload)
    except (PolicySetError, ConstraintParseError, ValidationError) as exc:
        print(f"compile error: {exc}", file=sys.stderr)
        return 1
    try:
        artifact = compile_to_wasm(rego)
    except (OpaNotFoundError, WasmCompileError) as exc:
        print(f"wasm compile error: {exc}", file=sys.stderr)
        return 1
    try:
        wasm_policy = WasmPolicy.from_bytes(artifact.wasm)
        decision = wasm_policy.decide(
            role=role, tool=tool, args=tool_args, ctx=attributes
        )
    except WasmEvalError as exc:
        print(f"wasm eval error: {exc}", file=sys.stderr)
        return 1

    return _render_verdict(
        verdict_from_rego(decision, tool_name=tool, role=role), label
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _read_and_parse(
    source_path: Path,
) -> tuple[str, dict[str, Any], str | None]:
    """Load + parse a policy.yaml. Returns (text, parsed, error_message?)."""
    if not source_path.is_file():
        return "", {}, f"no such file: {source_path}"
    try:
        text = source_path.read_text(encoding="utf-8")
    except OSError as exc:
        return "", {}, f"cannot read {source_path}: {exc}"
    try:
        parsed = yaml.safe_load(text) or {}
    except MarkedYAMLError as exc:
        line = exc.problem_mark.line + 1 if exc.problem_mark else None
        loc = f" (line {line})" if line is not None else ""
        return text, {}, f"YAML parse error{loc}: {exc.problem or exc}"
    if not isinstance(parsed, dict):
        return text, {}, f"{source_path} must contain a YAML mapping at top level"
    return text, parsed, None


def _read_signing_key(key_path: Path) -> tuple[bytes | None, str | None]:
    """Read + decode a base64url Ed25519 private key. Returns (key, error?)."""
    if not key_path.is_file():
        return None, f"--sign-key: no such file: {key_path}"
    try:
        encoded = key_path.read_text(encoding="utf-8").strip()
    except OSError as exc:
        return None, f"--sign-key: cannot read {key_path}: {exc}"
    try:
        raw = decode_key(encoded)
    except SignatureError as exc:
        return None, f"--sign-key: {key_path} is not a valid base64url key: {exc}"
    if len(raw) != 32:
        return None, (
            f"--sign-key: {key_path} decodes to {len(raw)} bytes, expected 32 "
            "(raw Ed25519 private key from `hexgate policy keygen`)."
        )
    return raw, None


def _display_path(path: Path) -> str:
    """Render a path relative to cwd when it's underneath, else absolute.

    Resolves both sides so the comparison and the rendered string stay
    consistent — a relative ``--out`` would otherwise pass an "under cwd"
    check but blow up on ``relative_to`` against an absolute cwd.
    """
    resolved = path.resolve()
    try:
        return str(resolved.relative_to(Path.cwd().resolve()))
    except ValueError:
        return str(resolved)
