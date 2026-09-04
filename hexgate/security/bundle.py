"""``PolicyBundle`` — a loadable, integrity-checked policy artifact.

A bundle is what ``hexgate policy build`` emits: a directory containing
the source ``policy.yaml``, the compiled ``policy.rego``, the
``policy.wasm`` blob, and a ``policy.bundle.json`` manifest holding the
content hashes. This class wraps the on-disk layout so the runtime can
load + verify + evaluate in one motion.

Today the bundle is content-addressed by sha256 (hashes in the manifest
match sha256 of the on-disk artifacts). M2 phase 6 layers an Ed25519
signature on top: the platform signs the manifest, the runtime checks
the signature before trusting the hashes. Until then, integrity is a
local check — useful for "bundle wasn't corrupted in transit" but not
a defense against malicious authors.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from hexgate.security.decision import Verdict
from hexgate.security.signing import SignatureError, verify_bytes
from hexgate.security.wasm_engine import WasmPolicy


class BundleIntegrityError(RuntimeError):
    """A bundle's on-disk content does not match the hashes in its manifest.

    Examples: someone hand-edited ``policy.rego`` after the build, the
    wasm file was truncated in transit, or the manifest was swapped with
    one from a different build.
    """


class BundleLoadError(RuntimeError):
    """A bundle directory is missing required files or is malformed."""


class BundleSignatureError(RuntimeError):
    """A bundle's signature is missing, malformed, or fails verification.

    Distinct from :class:`BundleIntegrityError`: integrity is the local
    hash chain (files match the manifest); signature is *authenticity*
    (the manifest was signed by a key the runtime trusts). A bundle can
    have valid integrity but a bad/absent signature.
    """


@dataclass
class PolicyBundle:
    """A loaded policy bundle, ready to evaluate via WASM.

    The dataclass holds the raw bytes / text; the ``WasmPolicy`` instance
    is created lazily on first ``policy()`` call so callers that only want
    metadata (e.g. the dashboard's bundle inspector) don't pay the
    wasmtime setup cost.

    Two construction paths:

      * :meth:`from_disk` — a `hexgate policy build` directory (yaml + rego
        + wasm + manifest [+ sig]). All artifacts present.
      * :meth:`from_parts` — a bundle pulled from the platform over HTTP:
        wasm + manifest + signature only, no source/rego files. ``source_path``
        is ``None`` and ``rego_text`` is empty for these; integrity then
        rests on the wasm-hash check + the signature.
    """

    # None for platform-served (from_parts) bundles — no source file locally.
    source_path: Path | None
    rego_text: str
    wasm_bytes: bytes
    manifest: dict
    # Exact on-disk manifest bytes — what the signature is computed over.
    # We keep the raw bytes (not a re-serialization of `manifest`) so
    # signature verification never depends on JSON canonicalization.
    manifest_bytes: bytes = b""
    # Detached signature over `manifest_bytes` (raw 64-byte Ed25519), or
    # None for unsigned bundles (dev / HEXGATE_LOCAL_POLICY path).
    signature: bytes | None = None
    _wasm_policy: WasmPolicy | None = field(default=None, repr=False, compare=False)

    # ---- Construction --------------------------------------------------

    @classmethod
    def from_disk(cls, path: Path | str) -> "PolicyBundle":
        """Load a bundle from a directory.

        Expects ``<dir>/{stem}.yaml``, ``{stem}.rego``, ``{stem}.wasm``,
        and ``{stem}.bundle.json`` for some shared ``{stem}`` (the
        source basename — e.g. "policy" for the platform's default
        export). When multiple stems are present in one directory we
        refuse rather than guess — pass an explicit file instead.
        """
        directory = Path(path)
        if not directory.is_dir():
            raise BundleLoadError(f"not a directory: {directory}")

        manifests = sorted(directory.glob("*.bundle.json"))
        if not manifests:
            raise BundleLoadError(
                f"no *.bundle.json found in {directory}; "
                "build with `hexgate policy build` first."
            )
        if len(manifests) > 1:
            raise BundleLoadError(
                f"multiple bundle manifests in {directory}: "
                f"{[m.name for m in manifests]} — pass an explicit path."
            )
        manifest_path = manifests[0]
        # `foo.bundle.json` → stem = `foo`
        stem = manifest_path.name[: -len(".bundle.json")]

        try:
            manifest_bytes = manifest_path.read_bytes()
            manifest = json.loads(manifest_bytes.decode("utf-8"))
        except (OSError, json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise BundleLoadError(f"cannot read {manifest_path}: {exc}") from exc

        source_path = directory / f"{stem}.yaml"
        rego_path = directory / f"{stem}.rego"
        wasm_path = directory / f"{stem}.wasm"

        for required in (source_path, rego_path, wasm_path):
            if not required.is_file():
                raise BundleLoadError(
                    f"bundle at {directory} is missing {required.name}"
                )

        # Detached signature is optional — present only for platform-signed
        # (or `--sign-key`-built) bundles. Unsigned bundles load fine; the
        # caller decides whether to require a signature.
        sig_path = directory / f"{stem}.bundle.json.sig"
        signature = sig_path.read_bytes() if sig_path.is_file() else None

        return cls(
            source_path=source_path,
            rego_text=rego_path.read_text(encoding="utf-8"),
            wasm_bytes=wasm_path.read_bytes(),
            manifest=manifest,
            manifest_bytes=manifest_bytes,
            signature=signature,
        )

    @classmethod
    def from_parts(
        cls,
        *,
        wasm_bytes: bytes,
        manifest_bytes: bytes,
        signature: bytes | None = None,
    ) -> "PolicyBundle":
        """Build an in-memory bundle from the parts the platform serves.

        No source yaml or rego files come over the wire — only the wasm,
        the exact manifest bytes (what the signature covers), and the
        detached signature. ``manifest_bytes`` is parsed for metadata but
        kept verbatim for :meth:`verify_signature`.

        Trust for these bundles rests on two checks the caller should run:
        :meth:`verify_signature` (the manifest is genuinely the platform's)
        and :meth:`verify_integrity` (the wasm matches the manifest's
        ``wasm_hash``). source/rego hashes are informational — there are no
        local files to check them against.
        """
        try:
            manifest = json.loads(manifest_bytes.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise BundleLoadError(f"bundle manifest is not valid JSON: {exc}") from exc
        if not isinstance(manifest, dict):
            raise BundleLoadError("bundle manifest is not a JSON object")
        return cls(
            source_path=None,
            rego_text="",
            wasm_bytes=wasm_bytes,
            manifest=manifest,
            manifest_bytes=manifest_bytes,
            signature=signature,
        )

    # ---- Integrity -----------------------------------------------------

    def verify_integrity(self) -> None:
        """Confirm the on-hand artifacts match the hashes in the manifest.

        This is the *integrity* check (artifacts match the manifest). For
        *authenticity* (the manifest was signed by a trusted key), see
        :meth:`verify_signature`. Run both for full assurance.

        For ``from_disk`` bundles all three artifacts are present and all
        three hashes are checked. For ``from_parts`` (platform-served)
        bundles there's no local source yaml or rego file, so those checks
        are skipped — only the wasm-hash check applies. The wasm check is
        the load-bearing one: it ties the actual module to the
        signature-authenticated manifest.
        """
        # source.yaml — only checkable when we hold the file (from_disk).
        expected_source_hash = self.manifest.get("source_hash")
        if expected_source_hash and self.source_path is not None:
            actual = hashlib.sha256(self.source_path.read_bytes()).hexdigest()
            if actual != expected_source_hash:
                raise BundleIntegrityError(
                    f"source.yaml hash mismatch: manifest says "
                    f"{expected_source_hash}, got {actual}"
                )

        # rego — only checkable when we hold the text (from_disk).
        expected_rego_hash = self.manifest.get("rego_hash")
        if expected_rego_hash and self.rego_text:
            actual = hashlib.sha256(self.rego_text.encode("utf-8")).hexdigest()
            if actual != expected_rego_hash:
                raise BundleIntegrityError(
                    f"rego hash mismatch: manifest says "
                    f"{expected_rego_hash}, got {actual}"
                )

        expected_wasm_hash = self.manifest.get("wasm_hash")
        if expected_wasm_hash is None:
            # Bundles built with `--no-wasm` carry None here — they can't
            # be used for enforcement.
            raise BundleIntegrityError(
                "manifest has no wasm_hash — this bundle was built without "
                "the WASM step (--no-wasm); rebuild with opa available."
            )
        actual = hashlib.sha256(self.wasm_bytes).hexdigest()
        if actual != expected_wasm_hash:
            raise BundleIntegrityError(
                f"wasm hash mismatch: manifest says {expected_wasm_hash}, got {actual}"
            )

    # ---- Authenticity --------------------------------------------------

    @property
    def is_signed(self) -> bool:
        """Whether a detached signature was loaded alongside this bundle."""
        return self.signature is not None

    def verify_signature(self, public_key_raw: bytes) -> None:
        """Verify the detached signature over the manifest bytes.

        ``public_key_raw`` is the raw 32-byte Ed25519 public key — the
        same key the SDK trusts for biscuit verification (the platform
        signs both with one root). Raises :class:`BundleSignatureError`
        if there's no signature, or if it doesn't verify.

        Signature authenticates the manifest; the manifest's hashes
        authenticate the files. So a valid signature + a passing
        :meth:`verify_integrity` together prove the whole bundle came
        from the trusted signer untampered. Callers should run both.
        """
        if self.signature is None:
            raise BundleSignatureError(
                "bundle has no signature (no *.bundle.json.sig alongside the "
                "manifest); cannot verify authenticity."
            )
        try:
            verify_bytes(self.manifest_bytes, self.signature, public_key_raw)
        except SignatureError as exc:
            raise BundleSignatureError(
                f"bundle signature verification failed: {exc}"
            ) from exc

    # ---- Evaluation ----------------------------------------------------

    def policy(self) -> WasmPolicy:
        """Return the cached WasmPolicy (instantiated on first call).

        Routes through :meth:`WasmPolicy.from_bytes_cached` so the
        content-addressed cache actually fires in production. The hot
        path the cache was designed for — ``refresh_policy()`` swaps
        in a new bundle instance whose ``wasm_hash`` matches the
        previous one (whitespace-only YAML edit, bundle-dir touch,
        platform 304 fallthrough) — now reuses the existing wasmtime
        store instead of paying ~50–100ms re-instantiation each turn.
        """
        if self._wasm_policy is None:
            self._wasm_policy = WasmPolicy.from_bytes_cached(
                self.wasm_bytes, self.wasm_hash
            )
        return self._wasm_policy

    def evaluate(
        self,
        *,
        role: str | None,
        tool: str,
        args: Mapping[str, Any],
        attributes: Mapping[str, Any] | None = None,
    ) -> Verdict:
        """:class:`~hexgate.security.decision.PolicyEngine` entry point.

        Runs the compiled WASM module; ``None`` role falls back to the
        ``default`` role, matching the pydantic engine. ``attributes`` become
        the ``input.ctx`` document the compiled ``ctx.*`` conditions read."""
        from hexgate.security.policy import evaluate_tool_call_wasm
        from hexgate.security.policy_set import DEFAULT_ROLE_NAME

        return evaluate_tool_call_wasm(
            self, role or DEFAULT_ROLE_NAME, tool, dict(args), attributes=attributes
        )

    def declares_admission(self) -> bool:
        """Read the admission-configured flag from the signed manifest.

        The compiled WASM is opaque, so the derived signal is recorded at build
        time (:func:`build_signed_bundle`) under ``agent_gating``. Absent (an older
        bundle) reads False — safe, those predate agent-level policy (R-AGENT-002)."""
        return bool(self.manifest.get("agent_gating", {}).get("admission", False))

    def declares_reach(self) -> bool:
        """Read the reach-configured flag from the signed manifest (reach counterpart)."""
        return bool(self.manifest.get("agent_gating", {}).get("reach", False))

    def declares_tool_reach(self) -> bool:
        """Read the agent-as-tool reach flag from the signed manifest. Absent (an
        older bundle) reads False, so no spurious warning fires."""
        return bool(self.manifest.get("agent_gating", {}).get("reach_tool", False))

    # ---- Metadata ------------------------------------------------------

    @property
    def source_hash(self) -> str | None:
        return self.manifest.get("source_hash")

    @property
    def wasm_hash(self) -> str | None:
        return self.manifest.get("wasm_hash")


# ---------------------------------------------------------------------------
# Producer side — compile (+ optionally sign) a bundle from policy YAML
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SignedBundle:
    """The artifacts ``hexgate policy build`` and the platform both emit.

    ``manifest_bytes`` are the *exact* bytes the signature covers — callers
    must persist/transmit these verbatim, never a re-serialization of
    ``manifest`` (that's the canonicalization-free invariant
    :meth:`PolicyBundle.verify_signature` relies on).
    """

    rego_text: str
    wasm_bytes: bytes | None  # None when compile_wasm=False (--no-wasm)
    manifest: dict
    manifest_bytes: bytes
    signature: bytes | None  # None when no `sign` callback was given

    @property
    def source_hash(self) -> str | None:
        return self.manifest.get("source_hash")

    @property
    def wasm_hash(self) -> str | None:
        return self.manifest.get("wasm_hash")


def build_signed_bundle(
    policy_yaml: str,
    *,
    source_name: str = "policy.yaml",
    sign: Callable[[bytes], bytes] | None = None,
    compile_wasm: bool = True,
    opa_bin: str | None = None,
) -> SignedBundle:
    """Compile policy YAML to a (optionally signed) bundle — one source of truth.

    Both ``hexgate policy build`` (the CLI) and the platform's save-time
    pipeline call this, so the manifest schema + its byte-exact
    serialization live in exactly one place. Two divergent copies would
    silently break signature verification across the SDK↔platform seam,
    since the signature is computed over those exact bytes.

    Raises on failure — ``PolicySetError`` / ``ConstraintParseError`` /
    ``ValidationError`` from the Rego compile, ``OpaNotFoundError`` /
    ``WasmCompileError`` from the WASM compile. Callers translate to their
    own UX (the CLI prints + exits; the platform logs + degrades to a
    bundle-less save).
    """
    # Lazy import keeps bundle.py importable (and the platform booting) even
    # when the opa-backed compiler isn't needed — only producers hit this.
    from hexgate.security.policy_set import load_policy_set_from_dict
    from hexgate.security.rego import compile_to_rego
    from hexgate.security.rego_wasm import compile_to_wasm

    payload = yaml.safe_load(policy_yaml) or {}
    source_hash = hashlib.sha256(policy_yaml.encode("utf-8")).hexdigest()
    rego_text = compile_to_rego(payload, source_hash=source_hash)

    # Record the agent-gate engagement flags derived from the resolved policy: the
    # compiled WASM is opaque, so the bundle-backed gate reads these from the
    # (signed) manifest to decide whether to fire (R-AGENT-002).
    resolved = load_policy_set_from_dict(payload)
    agent_gating = {
        "admission": resolved.declares_admission(),
        "reach": resolved.declares_reach(),
        "reach_tool": resolved.declares_tool_reach(),
    }

    wasm_bytes: bytes | None = None
    wasm_hash: str | None = None
    if compile_wasm:
        wasm_bytes = compile_to_wasm(rego_text, opa_bin=opa_bin).wasm
        wasm_hash = hashlib.sha256(wasm_bytes).hexdigest()

    manifest = {
        "version": 1,
        "source": source_name,
        "source_hash": source_hash,
        "rego_hash": hashlib.sha256(rego_text.encode("utf-8")).hexdigest(),
        "wasm_hash": wasm_hash,
        "agent_gating": agent_gating,
    }
    # The one canonical serialization. Sign these exact bytes.
    manifest_bytes = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode(
        "utf-8"
    )
    signature = sign(manifest_bytes) if sign is not None else None

    return SignedBundle(
        rego_text=rego_text,
        wasm_bytes=wasm_bytes,
        manifest=manifest,
        manifest_bytes=manifest_bytes,
        signature=signature,
    )
