"""Transport layer for the Hexgate control plane — HTTP client + Biscuit verify.

The agent-loader equivalent (`load_hexgate_agent`) lives in `hexgate.agents.loader`
alongside `load_local_agent`; this package only carries the client and token
verification primitives the loader uses.
"""

from hexgate.cloud.attenuate import attenuate_for_user
from hexgate.cloud.biscuit import (
    TokenError,
    TokenSignatureError,
    extract_facts,
    parse_envelope,
    verify_biscuit,
)
from hexgate.cloud.client import (
    HexgateClient,
    HexgateConfig,
    HexgateError,
)

__all__ = [
    "HexgateClient",
    "HexgateConfig",
    "HexgateError",
    "TokenError",
    "TokenSignatureError",
    "attenuate_for_user",
    "extract_facts",
    "parse_envelope",
    "verify_biscuit",
]
