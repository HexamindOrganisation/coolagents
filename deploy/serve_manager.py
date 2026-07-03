"""Run the hexgate serve loop IN-KERNEL, bound to a live agent object.

The visitor defines tools and the agent as real Python in notebook cells, so the
kernel holds an actual `agent` object. Rather than shipping its *source* to a
separate `hexgate serve` process, we run the serve loop here in the marimo
kernel (a background thread) bound to that exact object — what the dashboard
talks to *is* the object you defined. Edit the cells, click Apply, and the loop
restarts with the new object.

This is the same flow as `hexgate serve <spec>`:
    bootstrap() → build_runtime_from_local_agent(agent_obj=...) → run_serve(...)
only with a live object instead of a `module:attr` spec, run off-thread.

BYOK: the visitor's OpenAI key is set into this process's env (their own key,
their own throwaway container). HEXGATE_API_KEY (platform/relay auth) is read from
the file boot.py wrote.
"""

from __future__ import annotations

import asyncio
import os
import threading
from pathlib import Path

KEY_FILE = Path(os.environ.get("HEXGATE_SERVE_KEY_FILE", "/tmp/hexgate_serve_key"))

_thread: threading.Thread | None = None
_loop: asyncio.AbstractEventLoop | None = None
_task: asyncio.Task | None = None
_status: str = "stopped"


def _ensure_platform_env() -> None:
    """HexgateConfig.from_env() reads HEXGATE_API_KEY / HEXGATE_API_URL — make sure
    they're present in this process (boot.py writes the key to a file).

    The minted key in KEY_FILE is the source of truth for *this* container's
    freshly-seeded project, so it **overrides** any stale HEXGATE_API_KEY inherited
    from the shell / `.env` (otherwise auto-register 401s against the wrong
    project). `bootstrap()`'s later dotenv load won't clobber it — python-dotenv
    doesn't override existing env vars by default."""
    if KEY_FILE.is_file():
        os.environ["HEXGATE_API_KEY"] = KEY_FILE.read_text().strip()
    os.environ.setdefault("HEXGATE_API_URL", "http://127.0.0.1:8000")


def status() -> str:
    if _thread and _thread.is_alive():
        return _status
    return "stopped" if _status in ("running", "stopped") else _status


def _demo_settings():
    """Settings for the demo without bootstrap()'s repo-relative ``.env`` load.

    ``bootstrap()`` reads a ``.env`` next to the hexgate package, which doesn't
    exist in a fresh BYOK container — the notebook injects keys straight into
    the process env instead. So do bootstrap's other real work (configure audit
    + load settings) and skip the file load. Missing provider keys are fine:
    the web_search/fetch tools raise a clear error at *call* time if their key
    is absent.
    """
    from hexgate import audit
    from hexgate.config.settings import Settings

    audit.configure()
    return Settings.from_env()


def _run(agent_obj) -> None:
    global _loop, _task, _status
    from hexgate.cli._common import build_runtime_from_local_agent
    from hexgate.cli.serve import RelayApprovalHandler, run_serve
    from rich.console import Console

    _loop = asyncio.new_event_loop()
    asyncio.set_event_loop(_loop)
    try:
        settings = _demo_settings()
        # Same default as `hexgate serve` (see hexgate/cli/serve.py): route
        # NEEDS_APPROVAL to the connected playground tab via the WS relay.
        # Without this the notebook BYOK container silently auto-approved
        # every approval_required tool — the demo would ship the wrong
        # security contract.
        approval_handler = RelayApprovalHandler()
        runtime = build_runtime_from_local_agent(
            settings,
            agent_obj=agent_obj,
            description=None,
            approval_handler=approval_handler,
            auto_register=True,  # idempotent register of the agent manifest
            console=Console(),
        )
        _task = _loop.create_task(
            run_serve(runtime, approval_handler=approval_handler)
        )
        _status = "running"
        _loop.run_until_complete(_task)
    except asyncio.CancelledError:
        pass
    except Exception as exc:  # noqa: BLE001 — surface to the notebook, don't crash the kernel
        _status = f"error: {exc}"
        return
    finally:
        try:
            _loop.close()
        except Exception:  # noqa: BLE001
            pass
    _status = "stopped"


def stop() -> None:
    """Cancel the running serve loop and join its thread."""
    global _thread, _loop, _task
    if _loop and _task and not _task.done():
        _loop.call_soon_threadsafe(_task.cancel)
    if _thread and _thread.is_alive():
        _thread.join(timeout=10)
    _thread = _loop = _task = None


def apply(agent_obj) -> None:
    """(Re)start the in-kernel serve loop bound to ``agent_obj``.

    Requires ``OPENAI_API_KEY`` already in the process env — the notebook sets
    it from the key cell (BYOK) and builds the agent *afterwards*, since
    ``create_agent(model=str)`` instantiates ``ChatOpenAI`` eagerly and the
    key must be present at that point. The dashboard picks up the new agent on
    its next ``hello`` frame.
    """
    global _thread, _status
    if not os.environ.get("OPENAI_API_KEY"):
        raise ValueError("set OPENAI_API_KEY first (enter your key in the notebook)")
    _ensure_platform_env()
    stop()
    _status = "starting"
    _thread = threading.Thread(target=_run, args=(agent_obj,), daemon=True)
    _thread.start()
