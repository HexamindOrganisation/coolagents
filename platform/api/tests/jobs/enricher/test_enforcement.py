"""enforcement.py — parity with the SDK's as_payload redaction/cap semantics."""

from __future__ import annotations

import json

from hexgate.audit import MAX_VIOLATIONS
from hexgate_api.jobs.enricher.enforcement import (
    capped_arguments,
    capped_attributes,
    capped_hint,
    capped_violations,
)


def test_capped_arguments_happy_path() -> None:
    assert capped_arguments({"query": "hello"}) == {"query": "hello"}
    assert capped_arguments(None) is None


def test_when_argument_key_contains_token_then_redacted() -> None:
    # Substring match: "api_key_id" merely contains a secret-ish word.
    result = capped_arguments({"api_key_id": "abc", "safe": "x"})
    assert result == {"api_key_id": "[REDACTED]", "safe": "x"}


def test_when_attribute_key_is_authorization_tier_then_not_redacted() -> None:
    # Anchored match: policy facts like authorization_tier stay readable;
    # a key named exactly "token" is still blanked.
    result = capped_attributes({"authorization_tier": "gold", "token": "s3cr3t"})
    assert result == {"authorization_tier": "gold", "token": "[REDACTED]"}


def test_when_arguments_exceed_cap_then_truncated_to_marker() -> None:
    result = capped_arguments({"blob": "x" * 20_000})
    assert result["_truncated"] is True
    assert result["original_bytes"] > 8 * 1024
    assert len(json.dumps(result).encode()) <= 8 * 1024


def test_when_hint_over_cap_then_truncated_but_never_redacted() -> None:
    # A hint key containing "token" survives; only the size is enforced.
    small = capped_hint({"token_paths": ["/a"]})
    assert small == {"token_paths": ["/a"]}
    big = capped_hint({"paths": ["x" * 100] * 100})
    assert big["_truncated"] is True


def test_when_attributes_are_an_empty_dict_then_none() -> None:
    assert capped_attributes({}) is None
    assert capped_attributes(None) is None


def test_when_violations_exceed_cap_then_bounded() -> None:
    bounded = capped_violations([f"v{i}" for i in range(MAX_VIOLATIONS + 10)])
    assert len(bounded) == MAX_VIOLATIONS
    assert bounded[-1] == "(+11 more)"
