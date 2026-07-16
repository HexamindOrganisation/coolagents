"""Bootstrap helpers for hexgate."""

from __future__ import annotations

import logging
import os

from dotenv import find_dotenv, load_dotenv

from hexgate import audit
from hexgate.config.env import resolve_api_key
from hexgate.config.settings import Settings
from hexgate.tracing._senders import _LOCAL_MODE_ENV

_log = logging.getLogger(__name__)


def bootstrap(env_file: str = ".env", *, local_only: bool = False) -> Settings:
    """Load environment variables and return validated settings.

    ``override=False`` so a shell-set env var wins over the same key in
    ``.env`` — matches the convention every other tool (uvicorn, vite,
    cargo, npm…) follows. Treats ``.env`` as a default-provider, not
    an authoritative override.

    Configures the process-wide audit sender unless ``local_only=True``,
    in which case ``HEXGATE_LOCAL_MODE=1`` is set in the environment
    BEFORE :func:`audit.configure` runs — that's what makes the gate
    stick: any later adapter wrapper that re-``configure``s (every
    ``wrap_*_agent``, ``HexgateAgent.enforce_policy``) checks the same
    env var and stays inert. ``hexgate chat`` opts in this way; the
    examples and unit tests inherit it transitively.

    Audit sends are fire-and-forget background tasks: when the event loop
    tears down at exit they are cancelled, not finished, so events
    emitted shortly before exit are lost unless the teardown path
    explicitly drains with ``await audit.shutdown()``.

    The ``HEXGATE_API_KEY + HEXGATE_LOCAL_POLICY`` combination almost always
    means a dev forgot to clean up their env between an "I'm trying the
    platform" session and an "I'm iterating on a YAML policy" session.
    Log a single WARNING line so the surprise lands at startup, not three
    debug sessions later when they wonder why their policy edits
    aren't taking.
    """
    # Search the consumer's cwd, not this installed module's dir — their
    # .env lives where they run `hexgate register`. "" (not found) → no-op.
    env_path = find_dotenv(env_file, usecwd=True)
    # override=False: shell wins over .env (uvicorn/vite/cargo/npm convention).
    load_dotenv(env_path, override=False)
    if local_only:
        # Set BEFORE audit.configure() so the first call sees the gate.
        os.environ[_LOCAL_MODE_ENV] = "1"
    if resolve_api_key() and os.environ.get("HEXGATE_LOCAL_POLICY"):
        _log.warning(
            "HEXGATE_API_KEY and HEXGATE_LOCAL_POLICY are both set; the local "
            "policy override wins. Unset one to remove the ambiguity."
        )
    audit.configure()
    return Settings.from_env()
