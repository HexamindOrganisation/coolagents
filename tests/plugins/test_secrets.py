"""Detector tests: provider patterns, the entropy fallback + its false-positive
corpus, JSON-walk field paths, redaction, and the value-free text builders."""

from __future__ import annotations

import pytest

from hexgate.plugins.secrets import (
    _looks_high_entropy,
    _shannon_entropy,
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

# High-entropy, token-shaped, not hex, not a UUID -> caught by the fallback.
HIGH_ENTROPY = "xQ7bN2kR9wL4mP1vZ8cT5yA3jF6hD0sU7gE2iO9nB"

# Things that are long and random-ish but routinely legitimate arguments.
FALSE_POSITIVE_CORPUS = [
    "356a192b7913b04c54574d18c28d46e6395428ab",  # 40-char git sha (hex)
    "550e8400-e29b-41d4-a716-446655440000",  # UUID
    "the quick brown fox jumps over the lazy dog",  # prose (spaces)
    "/usr/local/lib/python3.13/site-packages",  # a file path
    "https://example.com/orders/12345/refund",  # a URL
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",  # long but zero entropy
    "order_12345",  # short id
    "2026-08-18T14:30:00Z",  # a timestamp
]


@pytest.mark.parametrize("category,sample", PROVIDER_SAMPLES.items())
def test_each_provider_prefix_is_detected(category: str, sample: str) -> None:
    hits = scan_secrets(sample)
    assert [h.category for h in hits] == [category]


def test_private_key_header_is_detected() -> None:
    pem = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1r...\n"
    assert [h.category for h in scan_secrets(pem)] == ["private_key"]


def test_high_entropy_token_is_detected() -> None:
    assert _looks_high_entropy(HIGH_ENTROPY)
    assert [h.category for h in scan_secrets(HIGH_ENTROPY)] == ["high_entropy"]


@pytest.mark.parametrize("value", FALSE_POSITIVE_CORPUS)
def test_false_positive_corpus_is_clean(value: str) -> None:
    assert scan_secrets(value) == []


def test_entropy_is_bits_per_char() -> None:
    assert _shannon_entropy("") == 0.0
    assert _shannon_entropy("aaaa") == 0.0
    assert _shannon_entropy("ab") == 1.0  # two equally likely symbols


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
