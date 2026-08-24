"""Span-enricher job: Kafka → OTLP decode → enrich → ClickHouse batch inserts.

A standalone long-running process (``python -m hexgate_api.jobs.enricher``),
not part of the FastAPI app — it shares the app's settings, ClickHouse client,
and DB session factory, and consumes the OTLP records the Collector produces.
"""
