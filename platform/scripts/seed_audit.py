from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from clickhouse_connect.driver.client import Client

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / 'api'))

from hexgate_api.constants import DEFAULT_PROJECT_ID, DEFAULT_PROJECT_NAME
from hexgate_api.features.audit.service import (
    _DECISION_COLUMNS,
    _DECISION_INSERT_SETTINGS,
)
from hexgate_api.core.clickhouse import get_clickhouse

# ── Agent & users ─────────────────────────────────────────────────────────────
# Uses the dev default project id (imported above) so data is visible in the dashboard.
# clear() scopes deletes to USER_IDS so real audit rows are not affected.

AGENT_NAME = DEFAULT_PROJECT_NAME
USER_IDS = ['Alice', 'Bob', 'Charlie']
ANOMALY_USER = 'Bob'

# ── Traffic shape ─────────────────────────────────────────────────────────────
# Normal: 800 rows over 30 days, outcomes weighted 80% allow / 10% deny / 10% needs_approval.
# Anomaly: Bob spikes 20 denies in a 5-minute window 10 days ago,
# probing restricted tools (refund_customer, create_ticket).

NUMBER_NORMAL_DATA = 800
NUMBER_ANOMALIES = 20

TOOL_NAMES = ['refund_customer', 'create_ticket', 'read_customer', 'web_search']
RESTRICTED_TOOLS = ['refund_customer', 'create_ticket']

# ── ClickHouse columns ────────────────────────────────────────────────────────
# Extends _DECISION_COLUMNS with received_at so the seed can control ingestion
# timestamps rather than letting ClickHouse stamp them at insert time.

_idx = _DECISION_COLUMNS.index('occurred_at')
_SEED_COLUMNS = _DECISION_COLUMNS[:_idx + 1] + ['received_at'] + _DECISION_COLUMNS[_idx + 1:]

# ── Row builders ──────────────────────────────────────────────────────────────


def _normal_row(rng: random.Random, outcome: str, timestamp: datetime) -> list:
    user_id = rng.choice(USER_IDS)
    return [
        uuid4(),
        timestamp,
        timestamp + timedelta(seconds=rng.randint(0, 5)),
        DEFAULT_PROJECT_ID,
        AGENT_NAME,
        '',
        '',
        user_id,
        rng.choice(TOOL_NAMES),
        'default',
        outcome,
        '' if outcome != 'deny' else 'permission_denied',
        '' if outcome != 'deny' else 'User does not have permission',
        [] if outcome != 'deny' else ['unauthorized_action'],
        '',
        '',
    ]


def _anomaly_row(rng: random.Random, timestamp: datetime) -> list:
    return [
        uuid4(),
        timestamp,
        timestamp + timedelta(seconds=rng.randint(0, 5)),
        DEFAULT_PROJECT_ID,
        AGENT_NAME,
        '',
        '',
        ANOMALY_USER,
        rng.choice(RESTRICTED_TOOLS),
        'default',
        'deny',
        'permission_denied',
        'User does not have permission',
        ['unauthorized_action', 'policy_violation'],
        '',
        '',
    ]


def _validate_columns(client: Client) -> None:
    result = client.query('DESCRIBE TABLE policy_decision')
    actual_columns = [row[0] for row in result.result_rows]    
    missing = set(_SEED_COLUMNS) - set(actual_columns)
    if missing:
        raise ValueError(
            f"ClickHouse table policy_decision is missing columns: {missing}"
        )


# ── Generators ────────────────────────────────────────────────────────────────


def generate_normal_data(rng: random.Random, now: datetime) -> list[list]:
    outcomes = rng.choices(
        ['allow', 'deny', 'needs_approval'],
        weights=[0.8, 0.1, 0.1],
        k=NUMBER_NORMAL_DATA,
    )
    timestamps = [
        now
        - timedelta(
            days=rng.randint(0, 29),
            hours=rng.randint(0, 23),
            minutes=rng.randint(0, 59),
        )
        for _ in range(NUMBER_NORMAL_DATA)
    ]
    return [_normal_row(rng, outcome, ts) for outcome, ts in zip(outcomes, timestamps)]


def generate_anomalies(rng: random.Random, now: datetime) -> list[list]:
    anomaly_base = now - timedelta(days=10)
    timestamps = [
        anomaly_base - timedelta(minutes=rng.randint(0, 5))
        for _ in range(NUMBER_ANOMALIES)
    ]
    return [_anomaly_row(rng, ts) for ts in timestamps]


# ── Public API ────────────────────────────────────────────────────────────────


def build_rows() -> list[list]:
    now = datetime.now(timezone.utc)
    rng = random.Random(0)
    return generate_normal_data(rng, now) + generate_anomalies(rng, now)


def seed(client: Client) -> int:
    clear(client)
    rows = build_rows()
    client.insert(
        'policy_decision', rows, column_names=_SEED_COLUMNS, settings=_DECISION_INSERT_SETTINGS
    )
    return len(rows)


def clear(client: Client) -> None:
    users = ', '.join(f"'{u}'" for u in USER_IDS)
    client.command(f"ALTER TABLE policy_decision DELETE WHERE user_id IN ({users}) AND project_id = '{DEFAULT_PROJECT_ID}'",
                   settings={'mutations_sync': '2'})




# ── CLI ───────────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(
        description='Seed ClickHouse with audit test data.'
    )
    parser.add_argument(
        '--clear', action='store_true', help='Delete seed rows instead of inserting.'
    )
    args = parser.parse_args()

    client = get_clickhouse()

    if args.clear:
        clear(client)
        print('Seed rows cleared.')
    else:
        _validate_columns(client)
        n = seed(client)
        print(
            f'Inserted {n} rows ({NUMBER_NORMAL_DATA} normal + {NUMBER_ANOMALIES} anomalies).'
        )
