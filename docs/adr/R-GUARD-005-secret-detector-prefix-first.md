# R-GUARD-005: The secret detector is prefix-only and value-free (v1)

**Status:** Accepted · 2026-08-18
**Applies to:** `hexgate/plugins/**`

## Decision

The official secret detector matches **only high-confidence provider prefixes**
(AWS `AKIA`/`ASIA`, GitHub `ghp_`/`github_pat_`, OpenAI/Anthropic `sk-`/`sk-ant-`,
Slack `xox…`, Google `AIza…`, Stripe `sk_live_`, Hexgate `fty_`, and full PEM
`BEGIN … END PRIVATE KEY` blocks). There is **no entropy fallback in v1**.

A detection is a `SecretHit(category, field, fingerprint)` where `fingerprint` is a
truncated SHA-256, **never the value**. Both the model-facing `safe_reason` and the
operator-facing `safe_detail` name the category and JSON field but never render the
value. `secret_guard` fails closed (halt), `secret_redactor` strips the full match
and records a `Modification`, `secret_watch` is observe-only.

## Why

A before-guard false positive blocks a real tool call, so for v1 **precision beats
recall**. Provider prefixes are near-zero false positive and cover the credentials
that matter.

Detecting *unprefixed* secrets by Shannon entropy was tried and removed: a
per-string entropy test cannot tell a base64-encoded secret from a base64-encoded
content hash / etag / opaque ID — they are identically random — so on the
fail-closed path it blocks legitimate calls. (It also had a dead band: since a
string's entropy is capped at `log2(len)`, a `4.5` bits/char threshold is
unreachable below 23 characters, so part of the configured range never fired.)
Entropy detection returns only when it can be gated so a false positive is
harmless — observe-only, or combined with regex context the way gitleaks does.

Because a guard halt must not hand the input back (that both leaks the secret and
invites a tweak-and-resend loop), the detector's entire public surface carries
category + field + hash, never the value.

## Consequences

- A homegrown secret with no known prefix is not caught. Accepted for v1; the
  high-value known providers are, and prefix/gated-entropy tuning is a later
  config/factory follow-up.
- The detector is JSON-ish only — it walks `dict` / `list` / `str`. An opaque result
  object is skipped, so `secret_watch` cannot scan it until result projection lands
  (R-GUARD-003).
- PII / email is deliberately out of v1: email in arguments is routine business
  data, an observe signal or a later redactor, not a refuse.

## Rejected alternatives

- **An entropy fallback** (shipped in the first draft, removed here). It blocks
  legitimate git SHAs, base64 hashes, and opaque IDs on the fail-closed path — the
  worst place for a false positive — and cannot distinguish those from real secrets.
- **Surface a masked value in the reason** (e.g. `AKIA…MPLE`). Even a partial value
  leaks and gives the model a substring to reshape; category + field is enough to
  fix the call.

## Verify

```
pytest tests/plugins/test_secrets.py -k "false_positive_corpus or provider_prefix or never_carry_the_value or private_key_block"
```

passes.
