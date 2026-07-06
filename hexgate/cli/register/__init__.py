"""The `hexgate register` CLI + platform-registration API.

Manifest models and the builder now live in :mod:`hexgate.manifest`;
this package only carries platform registration (`register_agent`,
`post_manifest`) and the CLI entry point.
"""

from hexgate.cli.register.main import add_parser, main
from hexgate.cli.register.register import register_agent

__all__ = ["register_agent", "add_parser", "main"]
