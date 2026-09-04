# Docs

Project documentation. Each file carries a `Status:` line at the top — check it
before trusting the contents.

| Doc | What it is | Status |
|-----|------------|--------|
| [architecture.md](architecture.md) | How `hexgate` is structured, runtime flow, file responsibilities | ⚠️ STALE — needs a refresh |
| [audit-pipeline.md](audit-pipeline.md) | End-to-end audit pipeline: SDK spans → OTLP collector → Redpanda → span-enricher → ClickHouse → dashboard | Living |
| [rego-wasm.md](rego-wasm.md) | How agent policies compile to signed WebAssembly | Snapshot (Milestone 2) |

Conventions:
- **Living** docs track the code — update them in the same PR as the change they describe.
- **Snapshot** docs are point-in-time narratives — dated and left frozen, not maintained.
</content>
