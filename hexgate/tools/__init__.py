"""Tool definitions.

Attributes load lazily via ``__getattr__`` — scaffolding for the follow-up
PR that also lazifies ``hexgate/__init__.py``. Until then the top-level
package still eager-imports every name here, so the savings don't land
yet; the split is in place so the second PR only has to touch one file.
"""

from importlib import import_module as _import_module
from typing import Any as _Any

_LAZY_ATTRS: dict[str, str] = {
    "agent_tool": "hexgate.tools.decorators",
    "bash": "hexgate.tools.bash",
    "edit_file": "hexgate.tools.files",
    "glob": "hexgate.tools.files",
    "grep": "hexgate.tools.files",
    "read_file": "hexgate.tools.files",
    "write_file": "hexgate.tools.files",
}

__all__ = list(_LAZY_ATTRS)


def __getattr__(name: str) -> _Any:
    """Resolve a public attribute lazily."""
    module_path = _LAZY_ATTRS.get(name)
    if module_path is not None:
        value = getattr(_import_module(module_path), name)
        globals()[name] = value
        return value

    from hexgate.tools._relocated import RELOCATED_TOOLS, relocated_import_error

    if name in RELOCATED_TOOLS:
        raise relocated_import_error(name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__() -> list[str]:
    """Public names in ``dir(hexgate.tools)``."""
    return sorted(_LAZY_ATTRS)
