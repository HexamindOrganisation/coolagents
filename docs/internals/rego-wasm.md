# Compiling agent policies to signed WebAssembly

> Status: snapshot as of Milestone 2 (2026-05) — a point-in-time narrative, not a maintained reference. Code may have moved on.

*How we turned a YAML policy file into a cryptographically signed, portable enforcement artifact — without changing how anyone writes policies.*

## The starting point

Hexgate governs what an AI agent's tools are allowed to do. You write a `policy.yaml` — "billing can refund up to $500, support needs approval for credits, everyone else is denied" — and the runtime checks every tool call against it before the tool runs.

Until recently, that check ran in-process through a pydantic-based constraint evaluator. It worked, but it had two limits we wanted to outgrow:

1. **No portable artifact.** The policy was interpreted live from YAML every time. There was nothing you could compile once, content-address, sign, and ship with confidence that "what runs in production is exactly what I reviewed."
2. **No authenticity story.** Nothing proved a policy came from the platform untampered.

This work set out to fix both by compiling policies to **WebAssembly** and **signing** the result — while keeping the YAML authoring experience identical and the old engine as a safety net.

## Why WASM, and why a second engine

The natural question: if pydantic works, why add a whole second evaluator?

Because a compiled WASM module is a fundamentally better *artifact*. It's:

- **Portable** — one self-contained binary, evaluable anywhere wasmtime runs.
- **Byte-for-byte reproducible** — the same policy compiles to the same bytes, so you can content-address and diff it.
- **Signable** — a stable artifact is something you can attach a signature to and verify later.

We chose [Open Policy Agent](https://www.openpolicyagent.org/) (OPA) as the compiler: policy YAML → Rego (OPA's policy language) → WASM via `opa build`. The constraint grammar was already Rego-shaped (`args.amount <= 500`), so the translation is mechanical.

Crucially, **both engines must agree.** A parity test suite evaluates the same inputs through pydantic and through real WASM and asserts identical decisions. That parity is what lets WASM become the default later without changing any agent's behavior.

## A design fork worth remembering

Early on we hit a real decision. OPA WASM returns whatever the policy's entrypoint rule evaluates to. The simplest design exposes a boolean `allow` rule — but then a denied tool call gives you `false` and nothing else. "Denied. Why? No idea."

We had two clean options:

- **Multiple rule heads** — emit a separate `violations` set rule alongside `allow`, eval both.
- **One structured `decision` object** — `{allow, requires_approval, violations}` returned from a single entrypoint.

We went with the structured object. It's the pattern OPA's own ecosystem converged on, it's one eval per decision, and adding a new field later (obligations, audit metadata) doesn't mean adding another entrypoint. The payoff: a denied call now comes back with the *exact constraint strings* that failed —

```
✗ DENY · billing → refund_order({"amount": 700})
  violations:
    • args.amount <= 500
```

— the same text the developer wrote in their YAML. No translation, no guessing.

## The trust model: one root key, two artifacts

Here's the part I think is genuinely elegant.

The platform already has an Ed25519 root keypair that signs **biscuit tokens** (the per-request identity tokens). We reused that same key to sign **policy bundles**. The SDK already fetches the platform's public key (from a JWKS endpoint) to verify tokens — so bundle verification reuses the exact same trusted key. No new key distribution, no new config.

It also lines up with a nice conceptual split:

| | Who authors it | Where the crypto happens |
|---|---|---|
| **Identity** (biscuit) | Platform issues, dev *attenuates* per-request | dev side |
| **Rules** (policy bundle) | Platform *authors + signs* | platform side |

The developer's runtime asserts *who* is calling (attenuating a token down to a user + role). The platform dictates *what* they're allowed to do (a signed bundle the dev can't forge). A dev can no more hand themselves a more permissive policy than they can attenuate up to a role they weren't granted.

## What gets signed (and the one subtlety)

A bundle is a directory:

| File | What it is |
|---|---|
| `policy.yaml` | the source (verbatim) |
| `policy.rego` | the compiled Rego |
| `policy.wasm` | the WebAssembly module — what actually evaluates |
| `policy.bundle.json` | a manifest with sha256 hashes of each artifact |
| `policy.bundle.json.sig` | a detached Ed25519 signature over the manifest |

The signature covers the **manifest**, and the manifest's hashes cover the **files**. So one signature transitively authenticates everything. The subtlety we got right: sign the *exact bytes* of the manifest as written to disk, and verify over those exact bytes — never re-serialize the JSON, because `json.dumps` isn't byte-stable across environments. Store it, ship it, verify it, all as the same literal bytes.

This catches an attack the hash chain alone couldn't: editing a file *and* updating the manifest hash to match. The hashes line up, but the signature breaks.

## The full path, end to end

1. A developer saves a policy through the dashboard.
2. The control plane compiles it (`policy.yaml → Rego → WASM`), builds the manifest, signs it with the root key, and stores the bundle.
3. The agent runtime fetches the agent — and now gets the signed bundle alongside the YAML.
4. The SDK verifies the signature against the platform's published key (the one it already trusts for tokens), checks the wasm matches the signed manifest, and enforces every tool call through wasmtime.
5. If anything's missing or unsigned, it falls back to the pydantic engine. If a bundle is present but *fails* verification, it refuses to run — a bad signature is never silently downgraded.

A practical worry we talked through: doesn't running OPA in the control plane hurt scalability? Answer: no. Compilation happens on **policy save** — a human config action at human frequency — not on the request-serving hot path. The hot path (evaluating tool calls) is wasmtime in the SDK and never touches OPA. The one thing to get right was not blocking the web server's event loop, and FastAPI already runs sync handlers in a threadpool, so the blocking `opa build` is off the loop for free.

## The dev escape hatch

Production always pulls a signed bundle from the platform. But a developer iterating on a policy shouldn't need the platform in the loop. So there's `HEXGATE_LOCAL_POLICY`: point it at a locally-built bundle directory and the runtime enforces *that* instead — no platform round-trip. Edit YAML, rebuild, restart, see the change. This was the direct answer to a concern that platform-only compilation would block local iteration.

---

# New `hexgate` CLI commands

This work adds a `hexgate policy` command group for authoring, inspecting, and signing policies locally.

> **Prerequisite:** the compile-to-WASM steps shell out to `opa`. Install it once: `brew install opa` (macOS) or see the [OPA downloads page](https://www.openpolicyagent.org/docs/latest/#running-opa). Commands that don't compile to WASM (`validate`, `test --engine pydantic`) don't need it.

The examples below use the demo policy shipped at `examples/demo_policy.yaml` (a support agent with `default` / `support` / `billing` roles), run from the repo root — so they're copy-paste runnable.

### `hexgate policy validate` — check a policy without the network

Parses the YAML and checks every constraint against the grammar. Same checks the platform runs at save time, but local and offline.

```bash
hexgate policy validate examples/demo_policy.yaml
```

Exit 0 on success, 1 with all errors printed otherwise. Good for a pre-commit hook or CI.

### `hexgate policy show-rego` — see what your YAML compiles to

Prints the generated Rego to stdout. Useful for understanding (or debugging) what rules your policy actually produces — pipe it to a file or to `opa`.

```bash
hexgate policy show-rego examples/demo_policy.yaml
hexgate policy show-rego examples/demo_policy.yaml > policy.rego
```

### `hexgate policy build` — compile a bundle

Compiles `policy.yaml` to a bundle directory (yaml + rego + wasm + manifest).

```bash
# Compile next to the source
hexgate policy build examples/demo_policy.yaml

# Compile into a specific directory
hexgate policy build examples/demo_policy.yaml --out ./bundle

# Skip the WASM step (no opa needed — emits yaml + rego only)
hexgate policy build examples/demo_policy.yaml --no-wasm

# Compile AND sign (see keygen below)
hexgate policy build examples/demo_policy.yaml --out ./bundle --sign-key ./keys/dev.private
```

With `--sign-key`, it also writes `policy.bundle.json.sig`. A malformed key fails fast before anything is written.

### `hexgate policy test` — dry-run one decision

Evaluate a single role/tool/args decision without spinning up an agent. Great for policy unit tests in CI.

```bash
# Default pydantic engine (no opa needed)
hexgate policy test examples/demo_policy.yaml \
    --role billing --tool refund_order \
    --args '{"amount": 200, "currency": "USD"}'

# Evaluate through the real WASM engine (matches production)
hexgate policy test examples/demo_policy.yaml \
    --role billing --tool refund_order \
    --args '{"amount": 700}' --engine wasm
```

Output is `ALLOW` / `DENY` / `APPROVAL_REQUIRED`, exit code 0 (allow/approval) or 1 (deny). On a WASM deny it prints the violated constraints:

```
✗ DENY · billing → refund_order({"amount": 700})
  violations:
    • args.amount <= 500
```

`--engine wasm` is the way to confirm locally that the compiled bundle decides what you expect.

### `hexgate policy keygen` — make a signing keypair

Generates an Ed25519 keypair for signing bundles locally (production keys live in the platform keystore).

```bash
hexgate policy keygen --out ./keys/dev
# writes ./keys/dev.private (chmod 0600) and ./keys/dev.public
# --force to overwrite existing files
```

The private key signs (`build --sign-key`); the public key verifies (`HEXGATE_BUNDLE_PUBKEY_PATH`). Keys are raw Ed25519, base64url-encoded — the same format the platform's JWKS endpoint publishes.

> `*.private` and `*.pem` are gitignored so a signing key never gets committed. Public keys are safe to commit.

---

# Runtime environment variables

These control how the runtime loads and verifies bundles. All optional.

| Variable | What it does |
|---|---|
| `HEXGATE_LOCAL_POLICY` | Path to a bundle directory. Overrides the agent's policy with that bundle (WASM engine). The dev-iteration path. |
| `HEXGATE_BUNDLE_PUBKEY_PATH` | Path to a base64url public key used to verify a local bundle's signature. |
| `HEXGATE_BUNDLE_REQUIRE_SIGNATURE` | `true` to refuse unsigned or unverifiable bundles. Default: warn but proceed. Set this in CI/prod. |
| `HEXGATE_OPA_BIN` | Override the `opa` binary location (default: search `PATH`). |

The signature-enforcement matrix, in short:

| Bundle | pubkey set | `REQUIRE_SIGNATURE` | Result |
|---|---|---|---|
| signed | yes | either | verify — **refuse if it fails** |
| signed | no | `false` | load with a warning |
| signed | no | `true` | refuse |
| unsigned | — | `false` (default) | load with a warning |
| unsigned | — | `true` | refuse |

A *present-but-invalid* signature always refuses, regardless of the require flag.

---

# A full local workflow

Putting it together — author, sign, and test a policy end to end without the platform:

```bash
# 1. One-time: make a dev signing keypair
hexgate policy keygen --out ./keys/dev

# 2. Validate as you edit
hexgate policy validate examples/demo_policy.yaml

# 3. Build + sign a bundle
hexgate policy build examples/demo_policy.yaml --out ./bundle --sign-key ./keys/dev.private

# 4. Confirm a decision through the real WASM engine
hexgate policy test examples/demo_policy.yaml \
    --role billing --tool refund_order \
    --args '{"amount": 200, "currency": "USD"}' --engine wasm

# 5. Run an agent against the signed bundle, verifying the signature
HEXGATE_LOCAL_POLICY=./bundle \
HEXGATE_BUNDLE_PUBKEY_PATH=./keys/dev.public \
HEXGATE_BUNDLE_REQUIRE_SIGNATURE=true \
hexgate chat --agent example_agent
# [hexgate] HEXGATE_LOCAL_POLICY active: ./bundle (wasm_hash=..., signed)
```

In production you skip steps 1, 3, and 5's env vars entirely — the platform signs the bundle, and the SDK verifies it against the same key it already trusts for your tokens.

---

# What's next

A few things are deliberately left for later:

- **Wire the other adapters.** Only the LangChain integration dispatches through WASM today; OpenAI / Google ADK / Pydantic-AI still use pydantic.
- **Make WASM the default.** Once the path has run in the wild, retire the pydantic fallback.
- **Key rotation.** Single root key for now.

But the spine is in place: a policy you write in YAML now becomes a signed, portable, verifiable WebAssembly artifact — and the path that compiles it is the same one that signs the tokens it trusts.
