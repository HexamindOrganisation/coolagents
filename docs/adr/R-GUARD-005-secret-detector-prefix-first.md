# R-GUARD-005: The secret detector is prefix-first, entropy-strict, value-free

**Status:** Accepted · 2026-08-18
**Applies to:** `hexgate/plugins/**`

## Decision

The official secret detector matches **high-confidence provider prefixes first**
(AWS `AKIA`/`ASIA`, GitHub `ghp_`/`github_pat_`, OpenAI/Anthropic `sk-`/`sk-ant-`,
Slack `xox…`, Google `AIza…`, Stripe `sk_live_`, Hexgate `fty_`, PEM private-key
headers) and falls back to a **strict Shannon-entropy** test only when no prefix
matched: a leaf must be one contiguous token in the base64 charset, at least
`_ENTROPY_MIN_LEN` long, over `_ENTROPY_THRESHOLD` bits/char, and **not** a plain
hex digest or a UUID.

A detection is a `SecretHit(category, field, fingerprint)` where `fingerprint` is a
truncated SHA-256, **never the value**. Both the model-facing `safe_reason` and the
operator-facing `safe_detail` name the category and JSON field but never render the
value. `secret_guard` fails closed (halt), `secret_redactor` strips and records a
`Modification`, `secret_watch` is observe-only in v1.

## Why

A before-guard false positive blocks a real tool call, so for v1 **precision beats
recall**. Provider prefixes are near-zero false positive and cover the credentials
that actually matter. Entropy alone false-positives on git SHAs, UUIDs, and base64
payloads — all routine tool arguments — so it is a strict, explicitly-excluded
fallback, not the primary signal. And because a guard halt must not hand the input
back (that both leaks the secret and invites a tweak-and-resend loop), the
detector's entire public surface carries category + field + hash, never the value.

## Consequences

- Secrets with no known prefix that fall under the entropy bar are missed. Accepted
  for v1; the high-value known providers are caught, and threshold/pattern tuning is
  a later config/factory follow-up.
- The detector is JSON-ish only — it walks `dict` / `list` / `str`. An opaque result
  object is skipped, so `secret_watch` cannot scan it until result projection lands
  (R-GUARD-003).
- PII / email is deliberately out of v1: email in arguments is routine business
  data, an observe signal or a later redactor, not a refuse.

## Rejected alternatives

- **Entropy-first (or entropy-only).** Simpler, but it blocks legitimate git SHAs,
  UUIDs, and base64 data on the fail-closed path — the worst place for a false
  positive.
- **Surface a masked value in the reason** (e.g. `AKIA…MPLE`). Even a partial value
  leaks and gives the model a substring to reshape; category + field is enough to
  fix the call.

## Verify

```
pytest tests/plugins/test_secrets.py -k "false_positive_corpus or provider_prefix or never_carry_the_value"
```

passes.
