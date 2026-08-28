"""Tests for the sandbox-runtime (`srt`) presence-and-version probe."""

from __future__ import annotations

import subprocess
from typing import Any

import pytest

from hexgate.runtime import srt as srt_module
from hexgate.runtime.srt import (
    SrtUnavailableError,
    ensure_srt_available,
    find_srt,
    srt_version,
)

# ---------------------------------------------------------------------------
# find_srt: presence detection.
# ---------------------------------------------------------------------------


def test_find_srt_returns_path_when_binary_present(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When `srt` is on PATH, find_srt returns its absolute path."""
    monkeypatch.setattr(srt_module.sys, "platform", "linux")
    monkeypatch.setattr(srt_module.shutil, "which", lambda name: "/usr/local/bin/srt")

    assert find_srt() == "/usr/local/bin/srt"


def test_find_srt_raises_when_binary_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A missing `srt` raises with install instructions in the message."""
    monkeypatch.setattr(srt_module.sys, "platform", "linux")
    monkeypatch.setattr(srt_module.shutil, "which", lambda name: None)

    with pytest.raises(SrtUnavailableError) as info:
        find_srt()

    message = str(info.value)
    assert "not found on PATH" in message
    assert "npm install -g @anthropic-ai/sandbox-runtime" in message


def test_find_srt_raises_on_windows(monkeypatch: pytest.MonkeyPatch) -> None:
    """Windows is unsupported; the error is platform-specific, not PATH-shaped."""
    monkeypatch.setattr(srt_module.sys, "platform", "win32")
    # Even if the binary is somehow on PATH, we still refuse.
    monkeypatch.setattr(srt_module.shutil, "which", lambda name: r"C:\srt.exe")

    with pytest.raises(SrtUnavailableError) as info:
        find_srt()

    message = str(info.value)
    assert "Windows" in message
    assert "PATH" not in message


def test_find_srt_passes_correct_binary_name_to_shutil_which(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """find_srt should look up the literal `srt` binary, not anything else."""
    monkeypatch.setattr(srt_module.sys, "platform", "linux")
    seen: list[str] = []

    def fake_which(name: str) -> str | None:
        seen.append(name)
        return f"/usr/local/bin/{name}"

    monkeypatch.setattr(srt_module.shutil, "which", fake_which)

    find_srt()

    assert seen == ["srt"]


# ---------------------------------------------------------------------------
# ensure_srt_available: convenience wrapper.
# ---------------------------------------------------------------------------


def test_ensure_srt_available_is_noop_when_present(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(srt_module.sys, "platform", "linux")
    monkeypatch.setattr(srt_module.shutil, "which", lambda name: "/usr/local/bin/srt")

    # Should not raise.
    ensure_srt_available()


def test_ensure_srt_available_raises_when_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(srt_module.sys, "platform", "linux")
    monkeypatch.setattr(srt_module.shutil, "which", lambda name: None)

    with pytest.raises(SrtUnavailableError):
        ensure_srt_available()


# ---------------------------------------------------------------------------
# srt_version: best-effort version probe.
# ---------------------------------------------------------------------------


def _stub_subprocess_run(
    monkeypatch: pytest.MonkeyPatch,
    *,
    stdout: str = "",
    stderr: str = "",
    returncode: int = 0,
    raises: type[BaseException] | BaseException | None = None,
) -> list[list[str]]:
    """Replace subprocess.run with a stub that records argv and returns canned data."""
    seen: list[list[str]] = []

    def fake_run(argv: list[str], **_kwargs: Any) -> subprocess.CompletedProcess[str]:
        seen.append(list(argv))
        if raises is not None:
            raise raises if isinstance(raises, BaseException) else raises("boom")
        return subprocess.CompletedProcess(
            args=argv, returncode=returncode, stdout=stdout, stderr=stderr
        )

    monkeypatch.setattr(srt_module.subprocess, "run", fake_run)
    return seen


def test_srt_version_returns_stdout_on_success(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A clean `srt --version` run yields the trimmed output string."""
    monkeypatch.setattr(srt_module.sys, "platform", "linux")
    monkeypatch.setattr(srt_module.shutil, "which", lambda name: "/usr/local/bin/srt")
    seen = _stub_subprocess_run(monkeypatch, stdout="0.42.0\n")

    assert srt_version() == "0.42.0"
    assert seen == [["/usr/local/bin/srt", "--version"]]


def test_srt_version_falls_back_to_stderr_when_stdout_empty(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Some CLIs print the version banner on stderr; accept that too."""
    monkeypatch.setattr(srt_module.sys, "platform", "linux")
    monkeypatch.setattr(srt_module.shutil, "which", lambda name: "/usr/local/bin/srt")
    _stub_subprocess_run(monkeypatch, stdout="", stderr="srt 0.42.0  ")

    assert srt_version() == "srt 0.42.0"


def test_srt_version_returns_none_when_binary_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """No binary on PATH means no version, but no exception either."""
    monkeypatch.setattr(srt_module.sys, "platform", "linux")
    monkeypatch.setattr(srt_module.shutil, "which", lambda name: None)

    assert srt_version() is None


def test_srt_version_returns_none_on_nonzero_exit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A non-zero exit from `srt --version` shouldn't surface garbage."""
    monkeypatch.setattr(srt_module.sys, "platform", "linux")
    monkeypatch.setattr(srt_module.shutil, "which", lambda name: "/usr/local/bin/srt")
    _stub_subprocess_run(monkeypatch, stdout="unknown flag --version", returncode=2)

    assert srt_version() is None


def test_srt_version_returns_none_on_oserror(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """If exec itself fails (permissions, deleted-but-cached path), return None."""
    monkeypatch.setattr(srt_module.sys, "platform", "linux")
    monkeypatch.setattr(srt_module.shutil, "which", lambda name: "/usr/local/bin/srt")
    _stub_subprocess_run(monkeypatch, raises=PermissionError("denied"))

    assert srt_version() is None


def test_srt_version_returns_none_on_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A hung `srt --version` shouldn't propagate; treat as 'unknown version'."""
    monkeypatch.setattr(srt_module.sys, "platform", "linux")
    monkeypatch.setattr(srt_module.shutil, "which", lambda name: "/usr/local/bin/srt")
    _stub_subprocess_run(
        monkeypatch,
        raises=subprocess.TimeoutExpired(cmd=["srt", "--version"], timeout=5),
    )

    assert srt_version() is None


def test_srt_version_returns_none_when_output_blank(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Empty stdout *and* stderr yields None, not an empty string."""
    monkeypatch.setattr(srt_module.sys, "platform", "linux")
    monkeypatch.setattr(srt_module.shutil, "which", lambda name: "/usr/local/bin/srt")
    _stub_subprocess_run(monkeypatch, stdout="   ", stderr="\n")

    assert srt_version() is None
