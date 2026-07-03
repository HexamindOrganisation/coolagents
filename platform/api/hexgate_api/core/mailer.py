"""Outbound email — the seam between FastAPI Users' lifecycle hooks
(``on_after_register`` / ``on_after_request_verify`` /
``on_after_forgot_password``) and however the platform actually ships
mail at deploy time.

One method (``send(to, subject, body)``) so swapping providers is a
one-line change at boot. Tests swap in a list-capturing sender via
:func:`set_email_sender` to read tokens without parsing stderr.

Two implementations:
  * :class:`StderrEmailSender` — dev default; prints to stderr.
  * :class:`ResendEmailSender` — production; calls the Resend API.
"""

from __future__ import annotations

import asyncio
import logging
import sys
import threading
from typing import Protocol

logger = logging.getLogger("hexgate.platform.email")


def _redact_email(addr: str) -> str:
    """Redact for logging — keep domain + first 2 chars of local-part so
    support can recognize a reported user without dumping addresses into
    log stores. Short local-parts (<=4) are fully masked since 2 of 3
    chars is barely a redaction.

      alice@example.com         -> al***@example.com
      alice.smith+tag@host.io   -> al***@host.io
      ab@example.com            -> ***@example.com   (too short)
      noplaceholder             -> ***               (no @)
    """
    if "@" not in addr:
        return "***"
    local, _, domain = addr.partition("@")
    if len(local) <= 4:
        return f"***@{domain}"
    return f"{local[:2]}***@{domain}"


class EmailSender(Protocol):
    """Anything with an ``async send(to, subject, body)``.

    Production wires a Resend / Postmark / SMTP implementation that
    actually delivers; the seam stops the UserManager from caring
    about the difference. Methods are async so a future implementation
    can ``await`` the provider's HTTP call without changing callers.
    """

    async def send(self, *, to: str, subject: str, body: str) -> None: ...


class StderrEmailSender:
    """Default dev-mode sender — print the email to stderr.

    The whole point of FastAPI Users' verification + reset flows is the
    magic link inside the body. Printing to stderr lets a dev see the
    link, copy it, and exercise the flow end-to-end without an SMTP
    server set up. Production swaps this for a real provider via
    :func:`set_email_sender` at boot.
    """

    async def send(self, *, to: str, subject: str, body: str) -> None:
        bar = "-" * 60
        print(
            f"\n[email] {bar}\n"
            f"        to:      {to}\n"
            f"        subject: {subject}\n"
            f"        body:\n{_indent(body, '          ')}\n"
            f"        {bar}\n",
            file=sys.stderr,
            flush=True,
        )


def _indent(text: str, prefix: str) -> str:
    return "\n".join(prefix + line for line in text.splitlines())


# Held while we set resend.api_key and call resend.Emails.send. The SDK
# reads the key from a module global at request-build time, so a per-
# instance key requires serializing "set then send". Today only one
# ResendEmailSender ever exists (configured once in main.py's lifespan),
# so the lock is "belt and suspenders": the key never actually changes,
# so we never actually race. If we ever instantiate a second sender
# (multi-tenant), the lock is what keeps the global from being torn
# between two concurrent sends.
#
# Cost: serializes every Resend HTTP call process-wide. Acceptable at
# our scale (single-digit emails/sec at peak: registration + reset +
# invite). If volume grows, the right fix is to capture the api_key
# into the Authorization header under the lock and release before the
# network call — but that reaches into resend.request.Request private
# API, so we punt until volume actually motivates it.
_resend_send_lock = threading.Lock()


class ResendEmailSender:
    """Send via Resend's HTTPS API.

    Wraps the (sync) ``resend.Emails.send`` in :func:`asyncio.to_thread`
    so the event loop isn't blocked on the provider's HTTP round trip.

    Failures **re-raise** — provider outages and configuration errors
    must reach the caller so the invitation flow (which logs with
    org-slug context) and a future health endpoint can observe them.
    The fastapi-users `on_after_*` hooks wrap us in try/except so the
    register/reset endpoints still return 200 to the user.

    Production wires this in main.py's lifespan when both
    ``RESEND_API_KEY`` and ``HEXGATE_EMAIL_FROM`` are set.
    """

    def __init__(self, *, api_key: str, from_addr: str) -> None:
        self._api_key = api_key
        self._from = from_addr

    async def send(self, *, to: str, subject: str, body: str) -> None:
        try:
            await asyncio.to_thread(self._send_sync, to, subject, body)
        except Exception:
            # PII-safe error log (recipient local-part redacted) so a
            # Resend outage is grep-able without dumping user emails into
            # log stores. Re-raise so the caller decides what to do.
            logger.error(
                "resend send failed: to_domain=%s subject=%r",
                _redact_email(to),
                subject,
                exc_info=True,
            )
            raise

    def _send_sync(self, to: str, subject: str, body: str) -> None:
        """Synchronous helper that runs on a thread-pool worker.

        The lock + immediate set+send pattern keeps the module-global
        ``resend.api_key`` from racing across concurrent senders. Only
        one sender exists today, but the constraint is brittle enough
        to defend against.
        """
        import resend

        params: resend.Emails.SendParams = {
            "from": self._from,
            "to": [to],
            "subject": subject,
            "text": body,
        }
        with _resend_send_lock:
            resend.api_key = self._api_key
            resend.Emails.send(params)


# Module-level singleton so the UserManager hooks (synchronous code path
# inside fastapi-users) can reach the sender without an extra dependency
# injection wire. Tests swap it via :func:`set_email_sender`; production
# swaps it once at boot via the same call before the lifespan finishes.
_current_sender: EmailSender = StderrEmailSender()


def get_email_sender() -> EmailSender:
    """Return the currently configured sender (used by auth.UserManager)."""
    return _current_sender


def set_email_sender(sender: EmailSender) -> None:
    """Replace the currently configured sender.

    Production boot calls this with a real provider implementation;
    tests call it with a capturing fake. There's no provider registry
    yet — when we wire Resend in production we'll do it in main.py's
    lifespan.
    """
    global _current_sender
    _current_sender = sender
