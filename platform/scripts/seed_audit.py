# Example: generate data for 40 users and 3 anomalies, project 00000000-0000-0000-0000-000000000003 and agent support-bot.
# cd platform/api && uv run python ../scripts/seed_audit.py --number_users 40 --number_anomalies 3 --project_id 00000000-0000-0000-0000-000000000003 --agent_name support-bot
#
# Example: clear seed rows for project 00000000-0000-0000-0000-000000000003.
# cd platform/api && uv run python ../scripts/seed_audit.py --clear --project_id 00000000-0000-0000-0000-000000000003

from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from clickhouse_connect.driver.client import Client

import sys
from pathlib import Path

from typing import Tuple

import logging

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

sys.path.insert(0, str(Path(__file__).parent.parent / "api"))

from hexgate_api.constants import DEFAULT_PROJECT_ID, DEFAULT_PROJECT_NAME
from hexgate_api.features.audit.service import (
    _DECISION_COLUMNS,
    _DECISION_INSERT_SETTINGS,
)
from hexgate_api.core.clickhouse import get_clickhouse

# ── Agent & users ─────────────────────────────────────────────────────────────
# Uses the dev default project id (imported above) so data is visible in the dashboard.
# clear() scopes deletes to USER_IDS so real audit rows are not affected.

USER_IDS = [
    f"test_{name}"
    for name in [
        "Alice",
        "Bob",
        "Charlie",
        "Dave",
        "Eve",
        "Frank",
        "Grace",
        "Heidi",
        "Ivan",
        "Judy",
        "Karl",
        "Liam",
        "Mallory",
        "Nina",
        "Oscar",
        "Peggy",
        "Quentin",
        "Rupert",
        "Sybil",
        "Trent",
        "Uma",
        "Victor",
        "Wendy",
        "Xander",
        "Yara",
        "Zach",
        "Amber",
        "Brian",
        "Clara",
        "Derek",
        "Elena",
        "Felix",
        "Gina",
        "Hugo",
        "Iris",
        "Jack",
        "Kira",
        "Leo",
        "Maya",
        "Noah",
    ]
]
ANOMALY_USERS = ["test_Bob", "test_Mallory"]

# ── Traffic shape ─────────────────────────────────────────────────────────────
# Normal: 300 rows per user over 30 days, outcomes weighted 80% allow / 10% deny / 10% needs_approval.
# Anomaly: for each anomaly, one user (sampled from ANOMALY_USERS) spikes 20-50 denies
# in a 5-minute window at a random point in the last 30 days,
# probing restricted tools (refund_customer, create_ticket).

ROWS_PER_USER = 300
NUMBER_ANOMALIES = 1
REQUESTS_PER_ANOMALY_MIN = 20
REQUESTS_PER_ANOMALY_MAX = 50

TOOL_NAMES = ["refund_customer", "create_ticket", "read_customer", "web_search"]
RESTRICTED_TOOLS = ["refund_customer", "create_ticket"]

# ── ClickHouse columns ────────────────────────────────────────────────────────
# Extends _DECISION_COLUMNS with received_at so the seed can control ingestion
# timestamps rather than letting ClickHouse stamp them at insert time.

_idx = _DECISION_COLUMNS.index("occurred_at")
_SEED_COLUMNS = (
    _DECISION_COLUMNS[: _idx + 1] + ["received_at"] + _DECISION_COLUMNS[_idx + 1 :]
)

# ── Row builders ──────────────────────────────────────────────────────────────


def _normal_row(
    rng: random.Random,
    outcome: str,
    timestamp: datetime,
    project_id: str,
    agent_name: str,
    number_users: int,
) -> list:
    user_id = rng.choice(USER_IDS[:number_users])
    return [
        uuid4(),
        timestamp,
        timestamp + timedelta(seconds=rng.randint(0, 5)),
        project_id,
        agent_name,
        "",
        "",
        user_id,
        rng.choice(TOOL_NAMES),
        "default",
        outcome,
        "" if outcome != "deny" else "permission_denied",
        "" if outcome != "deny" else "User does not have permission",
        [] if outcome != "deny" else ["unauthorized_action"],
        "",
        "",
    ]


def _anomaly_row(
    rng: random.Random,
    timestamp: datetime,
    project_id: str,
    agent_name: str,
    anomaly_user: str,
) -> list:
    return [
        uuid4(),
        timestamp,
        timestamp + timedelta(seconds=rng.randint(0, 5)),
        project_id,
        agent_name,
        "",
        "",
        anomaly_user,
        rng.choice(RESTRICTED_TOOLS),
        "default",
        "deny",
        "permission_denied",
        "User does not have permission",
        ["unauthorized_action", "policy_violation"],
        "",
        "",
    ]


def _validate_columns(client: Client) -> None:
    result = client.query("DESCRIBE TABLE policy_decision")
    actual_columns = [row[0] for row in result.result_rows]
    missing = set(_SEED_COLUMNS) - set(actual_columns)
    if missing:
        raise ValueError(
            f"ClickHouse table policy_decision is missing columns: {missing}"
        )


# ── Generators ────────────────────────────────────────────────────────────────


def generate_normal_data(
    rng: random.Random,
    now: datetime,
    project_id: str,
    agent_name: str,
    number_users: int,
) -> list[list]:
    number_rows = ROWS_PER_USER * number_users
    outcomes = rng.choices(
        ["allow", "deny", "needs_approval"],
        weights=[0.8, 0.1, 0.1],
        k=number_rows,
    )
    timestamps = [
        now
        - timedelta(
            days=rng.randint(0, 29),
            hours=rng.randint(0, 23),
            minutes=rng.randint(0, 59),
        )
        for _ in range(number_rows)
    ]
    return [
        _normal_row(rng, outcome, ts, project_id, agent_name, number_users)
        for outcome, ts in zip(outcomes, timestamps)
    ]


def generate_anomalies(
    rng: random.Random,
    now: datetime,
    agent_name: str,
    project_id: str,
    number_anomalies: int,
) -> list[list]:
    rows = []
    for _ in range(number_anomalies):
        anomaly_user = rng.choice(ANOMALY_USERS)
        anomaly_base = now - timedelta(days=rng.randint(0, 29))
        requests = rng.randint(REQUESTS_PER_ANOMALY_MIN, REQUESTS_PER_ANOMALY_MAX)
        timestamps = [
            anomaly_base - timedelta(minutes=rng.randint(0, 5)) for _ in range(requests)
        ]
        rows.extend(
            _anomaly_row(rng, ts, project_id, agent_name, anomaly_user)
            for ts in timestamps
        )
    return rows


# ── Public API ────────────────────────────────────────────────────────────────


def build_rows(
    agent_name: str, project_id: str, number_users: int, number_anomalies: int
) -> list[list]:
    now = datetime.now(timezone.utc)
    rng = random.Random(0)
    return generate_normal_data(
        rng, now, project_id, agent_name, number_users
    ) + generate_anomalies(rng, now, agent_name, project_id, number_anomalies)


def _validate_seed_args(number_users: int, number_anomalies: int) -> Tuple[int, int]:
    if number_users < 1:
        logging.info("number_users < 1, defaulting to 1")
        number_users = 1
    elif number_users > len(USER_IDS):
        logging.info(
            "number_users > %d, defaulting to %d", len(USER_IDS), len(USER_IDS)
        )
        number_users = len(USER_IDS)
    if number_anomalies < 0:
        logging.info("number_anomalies < 0, defaulting to 0")
        number_anomalies = 0
    elif number_anomalies > 100:
        logging.info("number_anomalies > 100, defaulting to 100")
        number_anomalies = 100
    return number_users, number_anomalies


def seed(
    client: Client,
    agent_name: str,
    project_id: str,
    number_users: int,
    number_anomalies: int,
) -> int:
    clear(client, project_id)
    rows = build_rows(agent_name, project_id, number_users, number_anomalies)
    client.insert(
        "policy_decision",
        rows,
        column_names=_SEED_COLUMNS,
        settings=_DECISION_INSERT_SETTINGS,
    )
    return len(rows)


def clear(client: Client, project_id: str) -> None:
    client.command(
        "ALTER TABLE policy_decision DELETE WHERE user_id IN {users:Array(String)} "
        "AND project_id = {pid:String}",
        parameters={"users": USER_IDS, "pid": project_id},
        settings={"mutations_sync": "2"},
    )


# ── CLI ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Seed ClickHouse with audit test data."
    )
    parser.add_argument(
        "--clear",
        action="store_true",
        help="Delete seed rows instead of inserting.",
    )
    parser.add_argument(
        "--agent_name",
        default=DEFAULT_PROJECT_NAME,
        help="Agent name to use for seed rows.",
    )
    parser.add_argument(
        "--project_id",
        default=DEFAULT_PROJECT_ID,
        help="Project ID to use for seed rows.",
    )
    parser.add_argument(
        "--number_users",
        type=int,
        default=3,
        help="Number of distinct users to draw from (max 40).",
    )
    parser.add_argument(
        "--number_anomalies",
        type=int,
        default=NUMBER_ANOMALIES,
        help="Number of anomaly spikes to generate.",
    )
    args = parser.parse_args()

    client = get_clickhouse()

    if args.clear:
        clear(client, args.project_id)
        print("Seed rows cleared.")
    else:
        _validate_columns(client)
        args.number_users, args.number_anomalies = _validate_seed_args(
            args.number_users, args.number_anomalies
        )
        n = seed(
            client,
            args.agent_name,
            args.project_id,
            args.number_users,
            args.number_anomalies,
        )
        normal_count = ROWS_PER_USER * args.number_users
        anomalous_count = n - normal_count
        print(
            f"Inserted {n} rows ({normal_count} normal + {anomalous_count} anomalous)."
        )
