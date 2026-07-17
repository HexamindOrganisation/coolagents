#!/usr/bin/env python3
"""Framework version-compatibility matrix driver.

Runs the opt-in probe suite (``tests/version_compat/``, marker
``version_compat``) against a grid of framework versions, each installed
into an isolated ``uv`` venv, and emits a compatibility table.

For each ``(framework, version)`` cell it:
  1. installs ``<dist>==<version>`` into that framework's reused venv
     (hexgate + dev extras installed once);
  2. runs the framework's probe module, capturing per-test outcomes via
     JUnit XML;
  3. classifies the result by tier — Tier 0 (contract), Tier 1 (the
     deterministic deny-path / allow-decision seam checks), Tier 2 (LLM
     e2e, only when a provider key is in the environment).

A Tier 1 failure is the critical signal: the wrap stopped attaching for
that version. A Tier 1 pass with a Tier 2 failure is *investigate*
(possibly model flakiness), not an automatic hard fail.

Everything lands under ``build/version-matrix/`` (gitignored). Policy is
local + offline (the probe conftest sets ``HEXGATE_LOCAL_POLICY`` /
``HEXGATE_LOCAL_MODE``); ``opa`` must be on ``PATH``.

Examples::

    # Default grid (floor + samples + latest) for every framework:
    python scripts/version_matrix.py

    # Just pydantic_ai, explicit versions:
    python scripts/version_matrix.py --versions pydantic=1.88.0,1.89.1,2.12.0

    # Preview the plan without installing anything:
    python scripts/version_matrix.py --dry-run
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import urllib.request
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as installed_dist_version
from pathlib import Path

from packaging.version import InvalidVersion, Version

REPO_ROOT = Path(__file__).resolve().parent.parent
PROBE_DIR = REPO_ROOT / "tests" / "version_compat"
WORK_DIR = REPO_ROOT / "build" / "version-matrix"
VENVS_DIR = WORK_DIR / "venvs"
JUNIT_DIR = WORK_DIR / "junit"
DEFAULT_OUT = WORK_DIR / "results.md"

PYPI_JSON = "https://pypi.org/pypi/{dist}/json"
PYPI_TIMEOUT_SECONDS = 30
PYTHON_VERSION = "3.13"
DEFAULT_LIMIT = 6

# Test-node name fragment -> tier. See tests/version_compat/README.md.
_TIER_BY_FRAGMENT = {
    "contract": 0,
    "deny_path": 1,
    "allow_decision": 1,
    "e2e": 2,
}


@dataclass(frozen=True)
class Framework:
    """One matrix row: a distribution and its probe module."""

    key: str
    dist: str
    test_file: str
    # Lowest version worth testing (usually the pyproject floor). ``None``
    # means "no floor" (deepagents isn't a hexgate dependency) — sample the
    # latest releases instead.
    floor: str | None
    # Extra pins to force alongside the primary dist, when a version is only
    # coherent with specific companions. Empty means "let uv resolve".
    pin_extra: tuple[str, ...] = ()


FRAMEWORKS: dict[str, Framework] = {
    "pydantic": Framework(
        "pydantic", "pydantic-ai-slim", "test_pydantic_ai.py", "1.88.0"
    ),
    "openai": Framework("openai", "openai-agents", "test_openai.py", "0.0.10"),
    "google": Framework("google", "google-adk", "test_google.py", "1.14.0"),
    "langchain": Framework("langchain", "langchain", "test_langchain.py", "1.0.0"),
    "deepagents": Framework("deepagents", "deepagents", "test_deepagents.py", None),
}

# Per-tier outcome, and the overall cell verdict.
TIER_PASS, TIER_FAIL, TIER_SKIP, TIER_NA = "pass", "fail", "skip", "n/a"


@dataclass
class CellResult:
    framework: str
    version: str
    tiers: dict[int, str] = field(default_factory=dict)
    status: str = ""
    detail: str = ""


# ---------------------------------------------------------------------------
# Version discovery + selection
# ---------------------------------------------------------------------------


def discover_versions(dist: str) -> list[Version]:
    """Return sorted stable versions of ``dist`` from PyPI (prereleases dropped)."""
    url = PYPI_JSON.format(dist=dist)
    try:
        with urllib.request.urlopen(url, timeout=PYPI_TIMEOUT_SECONDS) as resp:
            data = json.load(resp)
    except (OSError, json.JSONDecodeError) as exc:
        # OSError covers URLError/HTTPError/socket timeouts; raise a domain
        # error so one unreachable dist is reported, not a run-aborting crash.
        raise RuntimeError(f"PyPI lookup failed for {dist!r}: {exc}") from exc
    versions: list[Version] = []
    for raw in data.get("releases", {}):
        try:
            parsed = Version(raw)
        except InvalidVersion:
            continue
        if not parsed.is_prerelease:
            versions.append(parsed)
    versions.sort()
    return versions


def _installed_version(dist: str) -> Version | None:
    try:
        return Version(installed_dist_version(dist))
    except (PackageNotFoundError, InvalidVersion):
        return None


def select_versions(
    framework: Framework,
    *,
    limit: int,
    explicit: list[str] | None,
    include_installed: bool,
    latest_only: bool,
) -> list[str]:
    """Choose the versions to test for ``framework``.

    Explicit versions win. Otherwise take the floor, the latest, and an
    evenly-spaced sample in between up to ``limit`` — the installed version
    folded in when asked.
    """
    if explicit:
        return [str(v) for v in sorted({Version(v) for v in explicit})]

    available = discover_versions(framework.dist)
    if framework.floor is not None:
        floor = Version(framework.floor)
        available = [v for v in available if v >= floor]
    if not available:
        return []
    if latest_only:
        return [str(available[-1])]

    picks: set[Version] = {available[0], available[-1]}
    if limit > 2 and len(available) > 2:
        step = (len(available) - 1) / (limit - 1)
        for i in range(limit):
            picks.add(available[round(i * step)])
    if include_installed:
        inst = _installed_version(framework.dist)
        if inst is not None:
            picks.add(inst)
    return [str(v) for v in sorted(picks)]


# ---------------------------------------------------------------------------
# venv lifecycle + cell execution
# ---------------------------------------------------------------------------


def _run(cmd: list[str], **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, cwd=REPO_ROOT, text=True, capture_output=True, **kwargs)


class VenvManager:
    """One reused venv per framework; every cell re-resolves the full graph.

    Each cell installs ``-e .[dev]`` together with ``<dist>==<version>`` so uv
    re-resolves *coupled* transitive deps (langgraph for langchain, the openai
    base lib for openai-agents, …) to a set consistent with the pinned version.
    Pinning only the primary dist and reusing whatever was already installed
    silently leaves stale companions — which manifests as spurious Tier 2
    failures / import errors, not a real wrap break.
    """

    def __init__(self, uv: str) -> None:
        self._uv = uv
        self._created: set[str] = set()

    def python_for(self, framework: Framework) -> Path:
        return VENVS_DIR / framework.key / "bin" / "python"

    def ensure(self, framework: Framework) -> Path:
        """Create the (empty) venv once per framework."""
        python = self.python_for(framework)
        if framework.key in self._created:
            return python
        venv_dir = VENVS_DIR / framework.key
        venv_dir.parent.mkdir(parents=True, exist_ok=True)
        created = _run([self._uv, "venv", str(venv_dir), "--python", PYTHON_VERSION])
        if created.returncode != 0:
            raise RuntimeError(f"uv venv failed for {framework.key}: {created.stderr}")
        self._created.add(framework.key)
        return python

    def pin(self, framework: Framework, version: str) -> subprocess.CompletedProcess:
        """Re-resolve + install hexgate with ``<dist>==<version>`` pinned.

        Installing ``-e .[dev]`` alongside the pin (rather than reinstalling
        only the primary dist) lets uv move coupled companions to a coherent
        set for this version.
        """
        python = self.python_for(framework)
        specs = [f"{framework.dist}=={version}", *framework.pin_extra]
        return _run(
            [
                self._uv,
                "pip",
                "install",
                "--python",
                str(python),
                "-e",
                ".[dev]",
                *specs,
            ]
        )


def _tier_of(node_name: str) -> int | None:
    for fragment, tier in _TIER_BY_FRAGMENT.items():
        if fragment in node_name:
            return tier
    return None


def parse_junit(xml_path: Path) -> tuple[dict[int, str], list[str]]:
    """Aggregate a JUnit report into a per-tier outcome map.

    Within a tier: any fail/error -> fail; else any pass -> pass; else all
    skipped -> skip. Testcases whose name maps to no tier are returned
    separately so the caller can flag a stale fragment map — silently
    dropping a failing unmapped test would render the cell falsely green.
    """
    raw: dict[int, list[str]] = {0: [], 1: [], 2: []}
    unclassified: list[str] = []
    tree = ET.parse(xml_path)
    for case in tree.iter("testcase"):
        name = case.get("name", "")
        tier = _tier_of(name)
        if tier is None:
            unclassified.append(name)
            continue
        child_tags = {child.tag for child in case}
        if {"failure", "error"} & child_tags:
            raw[tier].append(TIER_FAIL)
        elif "skipped" in child_tags:
            raw[tier].append(TIER_SKIP)
        else:
            raw[tier].append(TIER_PASS)

    tiers: dict[int, str] = {}
    for tier, outcomes in raw.items():
        if not outcomes:
            tiers[tier] = TIER_NA
        elif TIER_FAIL in outcomes:
            tiers[tier] = TIER_FAIL
        elif TIER_PASS in outcomes:
            tiers[tier] = TIER_PASS
        else:
            tiers[tier] = TIER_SKIP
    return tiers, unclassified


def classify(tiers: dict[int, str]) -> str:
    """Map per-tier outcomes to a cell verdict."""
    t0, t1, t2 = tiers.get(0, TIER_NA), tiers.get(1, TIER_NA), tiers.get(2, TIER_NA)
    if t1 == TIER_SKIP and t0 == TIER_SKIP:
        return "INCOMPAT (skipped)"
    if t0 == TIER_FAIL or (t0 == TIER_NA and t1 == TIER_NA):
        return "UNUSABLE"
    if t1 == TIER_FAIL:
        return "BROKEN ⚠"
    if t1 == TIER_PASS and t2 == TIER_FAIL:
        return "T1✓ T2✗ (investigate)"
    if t1 == TIER_PASS:
        return "OK"
    return "UNKNOWN"


def _last_line(text: str) -> str:
    """Last non-empty line of ``text``, or ``""`` — safe on whitespace-only input."""
    lines = text.strip().splitlines()
    return lines[-1] if lines else ""


def run_cell(manager: VenvManager, framework: Framework, version: str) -> CellResult:
    result = CellResult(framework=framework.key, version=version)
    pin = manager.pin(framework, version)
    if pin.returncode != 0:
        result.status = "INSTALL-FAIL"
        result.detail = _last_line(pin.stderr)
        return result

    xml_path = JUNIT_DIR / f"{framework.key}-{version}.xml"
    xml_path.parent.mkdir(parents=True, exist_ok=True)
    proc = _run(
        [
            str(manager.python_for(framework)),
            "-m",
            "pytest",
            "-m",
            "version_compat",
            str(PROBE_DIR / framework.test_file),
            f"--junitxml={xml_path}",
            "-o",
            "log_cli=0",
            "-p",
            "no:cacheprovider",
            "-q",
        ],
        env=os.environ.copy(),
    )
    if not xml_path.exists():
        result.status = "ERROR"
        result.detail = (
            _last_line(proc.stdout + proc.stderr) or f"pytest rc={proc.returncode}"
        )
        return result

    result.tiers, unclassified = parse_junit(xml_path)
    result.status = classify(result.tiers)
    if unclassified:
        result.status = f"{result.status} + UNMAPPED⚠"
        result.detail = "unmapped tests: " + ", ".join(sorted(unclassified))
    return result


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------


def _cell(value: str) -> str:
    return {TIER_PASS: "✓", TIER_FAIL: "✗", TIER_SKIP: "–", TIER_NA: ""}.get(
        value, value
    )


def render_table(results: list[CellResult]) -> str:
    lines = [
        "# Framework version-compatibility matrix",
        "",
        "T0 = contract · T1 = deny-path/allow (deterministic seam) · "
        "T2 = LLM e2e (blank when no provider key).",
        "",
        "| Framework | Version | T0 | T1 | T2 | Status |",
        "| --- | --- | :-: | :-: | :-: | --- |",
    ]
    for r in results:
        lines.append(
            f"| {r.framework} | {r.version} | {_cell(r.tiers.get(0, TIER_NA))} | "
            f"{_cell(r.tiers.get(1, TIER_NA))} | {_cell(r.tiers.get(2, TIER_NA))} | "
            f"{r.status}{(' — ' + r.detail) if r.detail else ''} |"
        )
    lines.append("")
    lines.append("## Supported range (Tier 1 green)")
    lines.append("")
    by_fw: dict[str, list[CellResult]] = {}
    for r in results:
        by_fw.setdefault(r.framework, []).append(r)
    for fw, cells in by_fw.items():
        green_at = [i for i, c in enumerate(cells) if c.tiers.get(1) == TIER_PASS]
        if not green_at:
            lines.append(f"- **{fw}**: no Tier-1-green version in the tested set")
            continue
        green = [cells[i].version for i in green_at]
        # cells are in ascending-version order; a break in the index run means a
        # non-green version sits between greens — never render that as a range.
        contiguous = green_at == list(range(green_at[0], green_at[-1] + 1))
        if contiguous and len(green) > 1:
            span = f"{green[0]} … {green[-1]}"
        elif len(green) == 1:
            span = green[0]
        else:
            span = ", ".join(green)
        lines.append(f"- **{fw}**: {span} ({len(green)}/{len(cells)} green)")
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _parse_explicit(pairs: list[str] | None) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for pair in pairs or []:
        key, _, versions = pair.partition("=")
        if key not in FRAMEWORKS:
            raise SystemExit(f"unknown framework in --versions: {key!r}")
        out[key] = [v.strip() for v in versions.split(",") if v.strip()]
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--frameworks",
        help="comma-separated subset (default: all)",
        default=",".join(FRAMEWORKS),
    )
    parser.add_argument(
        "--versions",
        action="append",
        metavar="FW=1.0,1.1",
        help="explicit versions for a framework (repeatable); overrides discovery",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=DEFAULT_LIMIT,
        help=f"versions per framework when discovering (default {DEFAULT_LIMIT})",
    )
    parser.add_argument(
        "--latest-only",
        action="store_true",
        help="test only each framework's latest stable",
    )
    parser.add_argument(
        "--no-installed",
        action="store_true",
        help="don't force-include the currently installed version",
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=DEFAULT_OUT,
        help=f"markdown results path (default {DEFAULT_OUT})",
    )
    parser.add_argument(
        "--keep-venvs",
        action="store_true",
        help="don't delete the per-framework venvs on exit",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="print the plan and exit without installing",
    )
    args = parser.parse_args()

    uv = shutil.which("uv")
    if uv is None:
        raise SystemExit("uv not found on PATH")
    if shutil.which("opa") is None:
        print(
            "warning: opa not on PATH — local policy compile will fail", file=sys.stderr
        )

    selected = [k.strip() for k in args.frameworks.split(",") if k.strip()]
    unknown = [k for k in selected if k not in FRAMEWORKS]
    if unknown:
        raise SystemExit(f"unknown frameworks: {unknown}")
    explicit = _parse_explicit(args.versions)

    plan: list[tuple[Framework, list[str], str | None]] = []
    for key in selected:
        fw = FRAMEWORKS[key]
        try:
            versions = select_versions(
                fw,
                limit=args.limit,
                explicit=explicit.get(key),
                include_installed=not args.no_installed,
                latest_only=args.latest_only,
            )
            error: str | None = None
        except RuntimeError as exc:
            versions, error = [], str(exc)
        plan.append((fw, versions, error))

    print("Plan:")
    for fw, versions, error in plan:
        detail = error or (", ".join(versions) or "(none found)")
        print(f"  {fw.key:11} ({fw.dist}): {detail}")
    total = sum(len(v) for _, v, _ in plan)
    print(f"  → {total} cells\n")
    if args.dry_run:
        return 0

    WORK_DIR.mkdir(parents=True, exist_ok=True)
    manager = VenvManager(uv)
    results: list[CellResult] = []
    try:
        for fw, versions, error in plan:
            if error is not None:
                results.append(
                    CellResult(fw.key, "?", status="DISCOVERY-FAIL", detail=error[:200])
                )
                continue
            if not versions:
                continue
            try:
                manager.ensure(fw)
            except RuntimeError as exc:
                for version in versions:
                    results.append(
                        CellResult(
                            fw.key, version, status="ENV-FAIL", detail=str(exc)[:200]
                        )
                    )
                continue
            for version in versions:
                print(f"[{fw.key} {version}] installing + testing…", flush=True)
                cell = run_cell(manager, fw, version)
                results.append(cell)
                print(f"    → {cell.status}", flush=True)
    finally:
        if not args.keep_venvs and VENVS_DIR.exists():
            shutil.rmtree(VENVS_DIR, ignore_errors=True)

    table = render_table(results)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(table, encoding="utf-8")
    print("\n" + table)
    print(f"Results written to {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
