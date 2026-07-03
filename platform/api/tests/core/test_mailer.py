"""Tests for :mod:`mailer` — the Resend wiring in particular.

The dev-mode :class:`StderrEmailSender` is covered indirectly by the
auth flow tests (test_auth.py's ``outbox`` fixture swaps a capturing
sender in). This file is for the production sender: assert it shapes
the Resend payload correctly, runs the (sync) SDK off the event loop,
and swallows provider failures so they don't 500 the caller.
"""

from __future__ import annotations

import asyncio
import logging
import threading

import pytest

from hexgate_api.core.mailer import ResendEmailSender, _redact_email


# ---- _redact_email -------------------------------------------------------


@pytest.mark.parametrize(
    "raw, expected",
    [
        ("alice@example.com", "al***@example.com"),
        ("alice.smith+tag@host.io", "al***@host.io"),
        ("abcde@x.y", "ab***@x.y"),  # exactly above the threshold
        ("abcd@x.y", "***@x.y"),  # at threshold — full mask, 2 of 4 leaks too much
        ("ab@x.y", "***@x.y"),
        ("a@x.y", "***@x.y"),
        ("noatchar", "***"),  # malformed input
        ("", "***"),
    ],
)
def test_redact_email_cases(raw: str, expected: str) -> None:
    assert _redact_email(raw) == expected


@pytest.fixture
def fake_resend(monkeypatch: pytest.MonkeyPatch):
    """Replace ``resend.Emails.send`` with a list-capturing stub.

    Returns the list — tests can append-then-assert on payload shape.
    """
    import resend

    calls: list[dict] = []

    def _fake_send(params, options=None):  # noqa: ARG001 — match real signature
        calls.append(params)

    monkeypatch.setattr(resend.Emails, "send", _fake_send)
    return calls


def test_send_builds_resend_payload(fake_resend: list[dict]) -> None:
    """The payload Resend sees has the expected from/to/subject/text."""
    sender = ResendEmailSender(
        api_key="re_test_key", from_addr="Hexgate <noreply@hexgate.ai>"
    )

    asyncio.run(
        sender.send(
            to="alice@example.com",
            subject="Verify your Hexgate account",
            body="Click https://hexgate.ai/verify-email/abc to verify.",
        )
    )

    assert len(fake_resend) == 1
    params = fake_resend[0]
    assert params["from"] == "Hexgate <noreply@hexgate.ai>"
    assert params["to"] == ["alice@example.com"]  # list-wrapped per SDK contract
    assert params["subject"] == "Verify your Hexgate account"
    assert "verify-email/abc" in params["text"]


def test_send_uses_per_instance_api_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Each ResendEmailSender carries its own api_key on the instance.
    The module global gets set under a lock immediately before each
    send — a second sender instantiated later doesn't poison the first
    sender's outgoing calls."""
    import resend

    monkeypatch.setattr(resend, "api_key", None, raising=False)
    observed_keys: list[str | None] = []

    def _spy_send(params, options=None):  # noqa: ARG001
        observed_keys.append(resend.api_key)

    monkeypatch.setattr(resend.Emails, "send", _spy_send)
    sender_a = ResendEmailSender(api_key="re_key_A", from_addr="a@x.y")
    sender_b = ResendEmailSender(api_key="re_key_B", from_addr="b@x.y")

    # Constructing sender_b does NOT mutate the global — only send() does.
    assert resend.api_key is None

    asyncio.run(sender_a.send(to="t@x.y", subject="s", body="b"))
    asyncio.run(sender_b.send(to="t@x.y", subject="s", body="b"))

    assert observed_keys == ["re_key_A", "re_key_B"]


def test_send_runs_off_event_loop(monkeypatch: pytest.MonkeyPatch) -> None:
    """The SDK is sync; if we called it directly on the loop a slow
    network would block every other coroutine. Use ``asyncio.to_thread``
    so it lands on a worker thread — proved here by checking the thread
    id the fake observes is NOT the main thread."""
    import resend

    captured_thread: dict[str, int] = {}

    def _fake_send(params, options=None):  # noqa: ARG001
        captured_thread["tid"] = threading.get_ident()

    monkeypatch.setattr(resend.Emails, "send", _fake_send)
    sender = ResendEmailSender(api_key="re_test_key", from_addr="x@y.z")
    asyncio.run(sender.send(to="a@b.c", subject="s", body="b"))

    assert captured_thread["tid"] != threading.get_ident(), (
        "ResendEmailSender ran the sync SDK on the event loop — would "
        "block on a real network call"
    )


def test_send_reraises_provider_error(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """Re-raise contract: callers (invitation flow, future health check)
    need to observe Resend failures. The fastapi-users `on_after_*` hooks
    wrap us in their own try/except so endpoint 5xx is prevented one
    level up; we don't double-swallow here."""
    import resend

    def _exploding_send(params, options=None):  # noqa: ARG001
        raise RuntimeError("simulated resend outage")

    monkeypatch.setattr(resend.Emails, "send", _exploding_send)
    sender = ResendEmailSender(api_key="re_test_key", from_addr="x@y.z")

    with caplog.at_level(logging.ERROR, logger="hexgate.platform.email"):
        with pytest.raises(RuntimeError, match="simulated resend outage"):
            asyncio.run(sender.send(to="alice@example.com", subject="s", body="b"))

    # An ERROR log went out for grep-ability.
    assert any(
        "resend send failed" in rec.getMessage() and rec.levelno == logging.ERROR
        for rec in caplog.records
    ), f"expected an ERROR-level 'resend send failed' log, got {caplog.records}"


def test_send_error_log_does_not_leak_recipient_local_part(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """PII guard: the recipient's local-part must never reach the logs.
    Operators get the domain (useful: "all our gmail users failing")
    but not the address — log stores stay outside the PII boundary."""
    import resend

    def _exploding_send(params, options=None):  # noqa: ARG001
        raise RuntimeError("boom")

    monkeypatch.setattr(resend.Emails, "send", _exploding_send)
    sender = ResendEmailSender(api_key="re_test_key", from_addr="x@y.z")

    with caplog.at_level(logging.ERROR, logger="hexgate.platform.email"):
        with pytest.raises(RuntimeError):
            asyncio.run(
                sender.send(
                    to="alice.smith+tag@example.com",
                    subject="Verify your account",
                    body="Click https://app/verify-email/SECRET_TOKEN to verify.",
                )
            )

    full_log_text = "\n".join(
        rec.getMessage() + (rec.exc_text or "") for rec in caplog.records
    )
    assert "alice.smith" not in full_log_text, (
        "recipient local-part leaked into error log — PII violation"
    )
    assert "+tag" not in full_log_text, "recipient tag leaked into error log"
    # Partial-preserve format: first 2 chars + *** + domain. Just enough
    # for support to recognize a reported user; not enough to be the address.
    assert "al***@example.com" in full_log_text, (
        "expected partial-redacted form (al***@domain) — see _redact_email"
    )
    # Body must never reach logs — would expose the magic-link token.
    assert "SECRET_TOKEN" not in full_log_text, (
        "verification token leaked into error log — security violation"
    )


# ---- boot wiring: _configure_email_sender in main.py ----------------------


@pytest.fixture
def reset_sender():
    """Snapshot + restore the module-level sender AND resend.api_key so each
    test starts clean. ResendEmailSender mutates the resend module global
    inside _send_sync; without restoring it here a later test would see
    a stray "re_test_key" left by an earlier one."""
    from hexgate_api.core import mailer
    import resend

    original_sender = mailer.get_email_sender()
    original_key = resend.api_key
    yield
    mailer.set_email_sender(original_sender)
    resend.api_key = original_key


def test_configure_email_sender_wires_resend_when_both_env_vars_set(
    monkeypatch: pytest.MonkeyPatch, reset_sender: None
) -> None:
    """Both env vars present → real ResendEmailSender, configured with
    the exact values from the env (not a half-broken fallback)."""
    from hexgate_api.main import _configure_email_sender
    from hexgate_api.core.mailer import ResendEmailSender, get_email_sender

    monkeypatch.setenv("RESEND_API_KEY", "re_test_key_42")
    monkeypatch.setenv("HEXGATE_EMAIL_FROM", "noreply@hexgate.ai")
    _configure_email_sender()
    sender = get_email_sender()
    assert isinstance(sender, ResendEmailSender)
    # Pin the env→sender wiring so a typo'd env-var read can't silently
    # construct an empty ResendEmailSender that passes isinstance.
    assert sender._from == "noreply@hexgate.ai"  # noqa: SLF001 — invariant under test
    assert sender._api_key == "re_test_key_42"  # noqa: SLF001


def test_configure_email_sender_warns_on_partial_config(
    monkeypatch: pytest.MonkeyPatch,
    reset_sender: None,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Exactly one env var set = operator misconfig. Must log WARNING
    (distinguishable from clean dev mode) naming the missing var so the
    fix is obvious without grepping the .env."""
    from hexgate_api import main as main_module
    from hexgate_api.main import _configure_email_sender
    from hexgate_api.core.mailer import ResendEmailSender, get_email_sender

    monkeypatch.setenv("RESEND_API_KEY", "re_test_key")
    monkeypatch.delenv("HEXGATE_EMAIL_FROM", raising=False)
    with caplog.at_level(logging.WARNING, logger=main_module.__name__):
        _configure_email_sender()
    assert not isinstance(get_email_sender(), ResendEmailSender)
    warns = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert warns, "partial config should emit a WARNING-level log"
    assert "HEXGATE_EMAIL_FROM" in warns[-1].getMessage(), (
        "warning should name the missing var"
    )


def test_configure_email_sender_clean_dev_mode_logs_info(
    monkeypatch: pytest.MonkeyPatch,
    reset_sender: None,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Both unset = clean dev mode. INFO log only — no false alarm
    that would teach operators to ignore the partial-config warning."""
    from hexgate_api import main as main_module
    from hexgate_api.main import _configure_email_sender
    from hexgate_api.core.mailer import ResendEmailSender, get_email_sender

    monkeypatch.delenv("RESEND_API_KEY", raising=False)
    monkeypatch.delenv("HEXGATE_EMAIL_FROM", raising=False)
    with caplog.at_level(logging.INFO, logger=main_module.__name__):
        _configure_email_sender()
    assert not isinstance(get_email_sender(), ResendEmailSender)
    assert not any(r.levelno == logging.WARNING for r in caplog.records), (
        "clean dev mode should not emit a WARNING — that's reserved for misconfig"
    )


def test_configure_email_sender_resets_to_stderr_when_env_cleared(
    monkeypatch: pytest.MonkeyPatch, reset_sender: None
) -> None:
    """A re-config (lifespan-restart, test) with env vars cleared must
    actively reset to StderrEmailSender — otherwise a stale Resend
    sender keeps shipping mail while the log says 'dev stderr sender'."""
    from hexgate_api.main import _configure_email_sender
    from hexgate_api.core.mailer import ResendEmailSender, get_email_sender

    monkeypatch.setenv("RESEND_API_KEY", "re_test_key")
    monkeypatch.setenv("HEXGATE_EMAIL_FROM", "noreply@hexgate.ai")
    _configure_email_sender()
    assert isinstance(get_email_sender(), ResendEmailSender)

    monkeypatch.delenv("RESEND_API_KEY")
    monkeypatch.delenv("HEXGATE_EMAIL_FROM")
    _configure_email_sender()
    assert not isinstance(get_email_sender(), ResendEmailSender), (
        "re-config with env cleared must reset away from ResendEmailSender"
    )
