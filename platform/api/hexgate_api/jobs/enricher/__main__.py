"""Entrypoint: ``python -m hexgate_api.jobs.enricher`` (or ``make enricher-run``).

Exit codes: 0 on a clean stop (SIGTERM/SIGINT), 1 when a startup check
fails — stale ClickHouse schema or missing topics — so a supervisor sees
the difference between "done" and "misconfigured".
"""

from __future__ import annotations

import asyncio
import logging
import sys

from dotenv import load_dotenv

from hexgate_api.core.clickhouse import SchemaOutOfDate
from hexgate_api.jobs.enricher.consumer import EnricherJob, TopicsMissing
from hexgate_api.settings import get_settings

_log = logging.getLogger(__name__)


def main() -> int:
    load_dotenv()
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    try:
        asyncio.run(EnricherJob(get_settings()).run())
    except (SchemaOutOfDate, TopicsMissing) as exc:
        _log.error("startup check failed: %s", exc)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
