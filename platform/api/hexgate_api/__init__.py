"""Hexgate control-plane API package."""

from pathlib import Path

# The api project root (the dir holding this package): anchors runtime paths
# (SQLite db, signing-key dir, dev dashboard dist) regardless of how deeply a
# module is nested under the package.
API_ROOT = Path(__file__).resolve().parent.parent
