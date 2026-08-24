"""Regenerate the committed cross-language fixture.

The fixture pins the one guarantee the extension's hermetic Go-minted tests
cannot reach: that biscuit-go verifies what biscuit-python actually signs —
wire format, symbol table, date literals, envelope and all. It is consumed by
TestVerifyBiscuit_when_token_was_minted_by_the_python_platform_then_it_verifies.

The keypair is a throwaway generated below; its private half is never written
anywhere, so the committed token is a credential for nothing. The mint goes
through the real platform code path (core/biscuits.py), not a re-implementation.

Run from platform/api so its venv resolves:

    cd platform/api && PYTHONPATH=. uv run python \
        ../collector/extension/hexgatebiscuitauth/testdata/python_minted/mint_fixture.py

Only needed if biscuit-python's output format ever changes; the Go test's
assertions below must be kept in sync with the MintRequest values here.
"""

from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from hexgate_api.core.biscuits import MintRequest, make_envelope, mint_token

HERE = Path(__file__).parent

private_key = Ed25519PrivateKey.generate()
private_bytes = private_key.private_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PrivateFormat.Raw,
    encryption_algorithm=serialization.NoEncryption(),
)
public_bytes = private_key.public_key().public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw,
)

biscuit_b64 = mint_token(
    private_bytes,
    MintRequest(
        project_id="fixture-project",
        token_id="tok_pyfixture0001",
        name="python-fixture",
        scopes=("mint_user_token", "read_audit"),
        env="live",
        # Like tokens/service.py:mint_api_key — and the fixture must never expire.
        ttl_seconds=None,
    ),
)

# root.pub matches keystore.py's on-disk format: the raw 32 bytes.
(HERE / "root.pub").write_bytes(public_bytes)
(HERE / "envelope.txt").write_text(
    make_envelope("live", "fixture-project", biscuit_b64) + "\n"
)
print(f"wrote {HERE / 'root.pub'} and {HERE / 'envelope.txt'}")
