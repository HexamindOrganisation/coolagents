"""Detector tests: provider patterns, the entropy fallback + its false-positive
corpus, JSON-walk field paths, redaction, and the value-free text builders."""

from __future__ import annotations

import pytest

from hexgate.plugins.secrets import (
    redact_secrets,
    safe_detail,
    safe_reason,
    scan_secrets,
)

# One synthetic token per provider pattern, at the pattern's required length
# (content is filler; the prefix + length is what the detector keys on).
PROVIDER_SAMPLES = {
    "aws_access_key": "AKIAIOSFODNN7EXAMPLE",  # AKIA + 16
    "github_token": "ghp_" + "A" * 36,
    "github_fine_grained_pat": "github_pat_" + "A" * 22,
    "anthropic_key": "sk-ant-" + "A" * 24,
    "openai_key": "sk-" + "A" * 24,
    "slack_token": "xoxb-" + "A" * 20,
    "google_api_key": "AIza" + "A" * 35,
    "stripe_key": "sk_live_" + "A" * 24,
    "hexgate_token": "fty_" + "A" * 16,
}

# Long, random-looking, but routinely legitimate arguments. None match a
# provider prefix, so a prefix-only detector flags none of them (the base64
# digest is the class that a per-string entropy test would wrongly block).
FALSE_POSITIVE_CORPUS = [
    "356a192b7913b04c54574d18c28d46e6395428ab",  # 40-char git sha (hex)
    "550e8400-e29b-41d4-a716-446655440000",  # UUID
    "k3Jd9fL2mNp0qRsTuVwXyZ1aB4cD6eF8gH0iJ2kL3m=",  # base64 content hash
    "the quick brown fox jumps over the lazy dog",  # prose (spaces)
    "/usr/local/lib/python3.13/site-packages",  # a file path
    "https://example.com/orders/12345/refund",  # a URL
    "order_12345",  # short id
    "2026-08-18T14:30:00Z",  # a timestamp
]


@pytest.mark.parametrize("category,sample", PROVIDER_SAMPLES.items())
def test_each_provider_prefix_is_detected(category: str, sample: str) -> None:
    hits = scan_secrets(sample)
    assert [h.category for h in hits] == [category]


def test_private_key_block_is_detected_and_fully_redacted() -> None:
    # The whole block must be redacted, not just the header — otherwise the key
    # body would be forwarded to the tool.
    pem = (
        "-----BEGIN OPENSSH PRIVATE KEY-----\n"
        "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAA\n"
        "AAAABAAABlwAAAAdzc2gtcnNhAAAAAwEAAQ\n"
        "-----END OPENSSH PRIVATE KEY-----"
    )
    assert [h.category for h in scan_secrets(pem)] == ["private_key"]
    cleaned, _ = redact_secrets(pem)
    assert cleaned == "[REDACTED:private_key]"
    assert "b3BlbnNz" not in cleaned  # key body is gone, not just the header


@pytest.mark.parametrize("value", FALSE_POSITIVE_CORPUS)
def test_false_positive_corpus_is_clean(value: str) -> None:
    assert scan_secrets(value) == []


def test_sk_ant_prefers_the_specific_anthropic_category() -> None:
    # `sk-ant-...` matches both sk- patterns; the specific one must win, once.
    hits = scan_secrets("sk-ant-api03-" + "aB3dEfGh1jKlMn0pQrStUv")
    assert [h.category for h in hits] == ["anthropic_key"]


def test_scan_reports_json_field_paths() -> None:
    args = {
        "user": "bob",
        "auth": {"token": "AKIAIOSFODNN7EXAMPLE"},
        "keys": ["clean", "ghp_" + "a" * 36],
    }
    by_field = {h.field: h.category for h in scan_secrets(args)}
    assert by_field == {
        "auth.token": "aws_access_key",
        "keys[1]": "github_token",
    }


def test_opaque_and_scalar_leaves_are_skipped() -> None:
    assert scan_secrets({"n": 5, "ok": True, "obj": object(), "nil": None}) == []


def test_redact_replaces_the_span_and_leaves_surrounding_text() -> None:
    args = {"body": "use key AKIAIOSFODNN7EXAMPLE now"}
    cleaned, hits = redact_secrets(args)
    assert cleaned == {"body": "use key [REDACTED:aws_access_key] now"}
    assert [h.category for h in hits] == ["aws_access_key"]


def test_redact_walks_lists_and_leaves_scalars_untouched() -> None:
    cleaned, hits = redact_secrets(
        {"items": ["clean", "AKIAIOSFODNN7EXAMPLE", 7], "n": None}
    )
    assert cleaned == {"items": ["clean", "[REDACTED:aws_access_key]", 7], "n": None}
    assert [h.field for h in hits] == ["items[1]"]


def test_redact_does_not_mutate_the_input() -> None:
    original = {"auth": {"token": "AKIAIOSFODNN7EXAMPLE"}}
    cleaned, _ = redact_secrets(original)
    assert original == {"auth": {"token": "AKIAIOSFODNN7EXAMPLE"}}  # untouched
    assert cleaned["auth"]["token"] == "[REDACTED:aws_access_key]"


def test_reason_and_detail_never_carry_the_value() -> None:
    secret = "AKIAIOSFODNN7EXAMPLE"
    hits = scan_secrets({"auth": {"token": secret}})
    reason, detail = safe_reason(hits), safe_detail(hits)
    assert secret not in reason and secret not in detail
    assert "aws_access_key" in reason and "auth.token" in reason
    assert "auth.token" in detail  # fingerprint is a hash, so the value is gone
