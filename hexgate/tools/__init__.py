"""Tool definitions."""

from hexgate.tools.bash import bash
from hexgate.tools.decorators import agent_tool
from hexgate.tools.files import edit_file, glob, grep, read_file, write_file

__all__ = [
    "agent_tool",
    "bash",
    "edit_file",
    "glob",
    "grep",
    "read_file",
    "write_file",
]


def __getattr__(name: str) -> object:
    from hexgate.tools._relocated import RELOCATED_TOOLS, relocated_import_error

    if name in RELOCATED_TOOLS:
        raise relocated_import_error(name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
