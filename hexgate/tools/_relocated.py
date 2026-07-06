"""Tools that used to ship in the hexgate core and now live in ``examples/``.

Single source of truth for the relocation, so both entry points give the same
hint instead of an opaque error: ``resolve_tools`` (an ``agent.yaml`` still
listing one) and the module-level ``__getattr__`` hooks on ``hexgate`` /
``hexgate.tools`` (a direct ``from hexgate import web_search``).
"""

RELOCATED_TOOLS: dict[str, str] = {
    "web_search": "examples/tools/websearch.py",
    "fetch": "examples/tools/fetch.py",
    "refund_order": "examples/tools/refund.py",
}


def relocated_import_error(name: str) -> ImportError:
    """Build the ``ImportError`` for a direct import of a relocated tool."""
    target = RELOCATED_TOOLS[name]
    return ImportError(
        f'"{name}" is no longer built into hexgate — it moved to {target}. '
        "Import it from there, or pass it via extra_tools=."
    )
