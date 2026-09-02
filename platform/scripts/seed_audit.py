# Example: generate data for 40 users and 3 anomalies, project 00000000-0000-0000-0000-000000000003 and agent support-bot.
# cd platform/api && uv run python ../scripts/seed_audit.py --number_users 40 --number_anomalies 3 --project_id 00000000-0000-0000-0000-000000000003 --agent_name support-bot
#
# Example: clear seed rows for project 00000000-0000-0000-0000-000000000003.
# cd platform/api && uv run python ../scripts/seed_audit.py --clear --project_id 00000000-0000-0000-0000-000000000003

from __future__ import annotations

import json
import logging
import random
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterator, Tuple
from uuid import UUID, uuid4

from clickhouse_connect.driver.client import Client

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

sys.path.insert(0, str(Path(__file__).parent.parent / "api"))

# The sys.path bootstrap above has to run before these resolve.
from hexgate_api.constants import DEFAULT_PROJECT_ID  # noqa: E402
from hexgate_api.core.clickhouse import get_clickhouse  # noqa: E402
from hexgate_api.features.audit.service import (  # noqa: E402
    _DECISION_COLUMNS,
    _DECISION_INSERT_SETTINGS,
)

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

# ── Traffic shape ─────────────────────────────────────────────────────────────
# Normal: ~300 rows per user over 30 days, grouped into short runs (one
# session_id + one run_id each), outcomes weighted 80% allow / 10% deny /
# 10% needs_approval.
# Anomaly: for each anomaly, one user (sampled from the seeded normal subset,
# USER_IDS[:number_users]) spikes 20-50 denies inside a single run in a
# 5-minute window at a random point in the last 30 days, probing restricted
# tools (refund_customer, create_ticket).
# Sampling from the seeded subset (not a fixed list) ensures the anomaly user
# already has normal-behavior rows, so the anomaly reads as a deviation rather
# than a user's only activity.

ROWS_PER_USER = 300
NUMBER_ANOMALIES = 1
REQUESTS_PER_ANOMALY_MIN = 20
REQUESTS_PER_ANOMALY_MAX = 50

SEED_WINDOW_DAYS = 30
DECISIONS_PER_RUN_MIN = 3
DECISIONS_PER_RUN_MAX = 12
SECONDS_BETWEEN_DECISIONS_MAX = 45
INGEST_LAG_SECONDS_MAX = 5
TOKENS_PER_LLM_CALL_MIN = 300
TOKENS_PER_LLM_CALL_MAX = 4_000

OUTCOMES = ["allow", "deny", "needs_approval"]
OUTCOME_WEIGHTS = [0.8, 0.1, 0.1]
DENY_OUTCOME = "deny"

TOOL_NAMES = ["refund_customer", "create_ticket", "read_customer", "web_search"]
RESTRICTED_TOOLS = ["refund_customer", "create_ticket"]

DENY_ERROR_TYPE = "permission_denied"
DENY_REASON = "User does not have permission"
DENY_VIOLATIONS = ["unauthorized_action"]
ANOMALY_VIOLATIONS = ["unauthorized_action", "policy_violation"]

# Role sets are per-user and stable, so the dashboard's by-role breakdown
# (which reads `has(user_roles, …)`) tells a consistent story across runs.
# `deciding_role` is empty on a deny — the schema's "every role denied".
ROLE_SETS = [
    ["support_agent"],
    ["support_agent", "billing_agent"],
    ["readonly"],
]

# Caller ABAC bags (ctx.*), seeded so the "Context attributes" drawer section
# has something to render. Deliberately non-PII — the same shape the docs use.
ATTRIBUTE_BAGS = [
    {"department": "finance", "region": "EU", "clearance_level": 3},
    {"department": "support", "region": "EU", "clearance_level": 1},
    {"department": "support", "region": "US", "clearance_level": 2},
]
ATTRIBUTES_POPULATED_RATIO = 0.66
ANOMALY_ATTRIBUTES = {"department": "support", "region": "EU", "clearance_level": 1}

# ── ClickHouse columns ────────────────────────────────────────────────────────
# Extends _DECISION_COLUMNS with received_at so the seed can control ingestion
# timestamps rather than letting ClickHouse stamp them at insert time.

_OCCURRED_AT = "occurred_at"
_idx = _DECISION_COLUMNS.index(_OCCURRED_AT)
_SEED_COLUMNS = (
    _DECISION_COLUMNS[: _idx + 1] + ["received_at"] + _DECISION_COLUMNS[_idx + 1 :]
)

Row = list[Any]
Fields = dict[str, Any]


@dataclass(frozen=True, slots=True)
class SeedTarget:
    project_id: str
    agent_name: str


# ── Run attribution ───────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class RunSnapshot:
    """The five run counters as of one decision, plus the run they belong to."""

    run_id: UUID
    tool_calls: int
    llm_calls: int
    denials: int
    total_tokens: int
    elapsed_ms: int

    def as_fields(self) -> Fields:
        """Only the run columns this build's audit contract declares.

        The six run_* columns landed after the multi-role ones, so an API
        image from either side of that change is expected here; narrowing to
        _SEED_COLUMNS writes run attribution where the columns exist and
        leaves the older shape untouched, rather than failing the insert.
        """
        return {
            column: value
            for column, value in (
                ("run_id", self.run_id),
                ("run_tool_calls", self.tool_calls),
                ("run_llm_calls", self.llm_calls),
                ("run_denials", self.denials),
                ("run_total_tokens", self.total_tokens),
                ("run_elapsed_ms", self.elapsed_ms),
            )
            if column in _SEED_COLUMNS
        }


class RunProgress:
    """Counters for one synthetic run.

    Snapshot-then-record, because the enforcer reads the run namespace before
    the decision it is about to make lands. A denial does not increment
    tool_calls — it must not consume a legitimate caller's budget
    (RunFacts.record_denial).
    """

    def __init__(self, rng: random.Random, run_id: UUID) -> None:
        self._rng = rng
        self._run_id = run_id
        self._tool_calls = 0
        self._llm_calls = 0
        self._denials = 0
        self._total_tokens = 0

    def snapshot(self, elapsed_ms: int) -> RunSnapshot:
        return RunSnapshot(
            run_id=self._run_id,
            tool_calls=self._tool_calls,
            llm_calls=self._llm_calls,
            denials=self._denials,
            total_tokens=self._total_tokens,
            elapsed_ms=elapsed_ms,
        )

    def record(self, outcome: str) -> None:
        self._llm_calls += 1
        self._total_tokens += self._rng.randint(
            TOKENS_PER_LLM_CALL_MIN, TOKENS_PER_LLM_CALL_MAX
        )
        if outcome == DENY_OUTCOME:
            self._denials += 1
        else:
            self._tool_calls += 1


# ── Row builders ──────────────────────────────────────────────────────────────


def _role_set(user_id: str) -> list[str]:
    return ROLE_SETS[USER_IDS.index(user_id) % len(ROLE_SETS)]


def _project_row(fields: Fields) -> Row:
    """Order ``fields`` into a _SEED_COLUMNS row, failing on any drift.

    _SEED_COLUMNS is derived from _DECISION_COLUMNS, so a column added
    upstream surfaces here as a missing key rather than as the driver's
    count-mismatch error, which names neither side.
    """
    missing = [column for column in _SEED_COLUMNS if column not in fields]
    unknown = sorted(set(fields) - set(_SEED_COLUMNS))
    if missing or unknown:
        raise ValueError(
            f"seed row does not match the {len(_SEED_COLUMNS)} audit columns — "
            f"missing {missing}, unknown {unknown}"
        )
    return [fields[column] for column in _SEED_COLUMNS]


def _envelope(
    target: SeedTarget,
    rng: random.Random,
    *,
    timestamp: datetime,
    session_id: str,
    user_id: str,
) -> Fields:
    return {
        "event_id": uuid4(),
        "occurred_at": timestamp,
        "received_at": timestamp
        + timedelta(seconds=rng.randint(0, INGEST_LAG_SECONDS_MAX)),
        "project_id": target.project_id,
        "agent_name": target.agent_name,
        "agent_version_id": "",
        "session_id": session_id,
        "user_id": user_id,
    }


def _normal_row(
    target: SeedTarget,
    rng: random.Random,
    *,
    outcome: str,
    timestamp: datetime,
    session_id: str,
    user_id: str,
    run: RunSnapshot,
) -> Row:
    denied = outcome == DENY_OUTCOME
    roles = _role_set(user_id)
    return _project_row(
        {
            **_envelope(
                target,
                rng,
                timestamp=timestamp,
                session_id=session_id,
                user_id=user_id,
            ),
            "tool_name": rng.choice(TOOL_NAMES),
            "outcome": outcome,
            "error_type": DENY_ERROR_TYPE if denied else "",
            "reason": DENY_REASON if denied else "",
            "violations": list(DENY_VIOLATIONS) if denied else [],
            "hint": "",
            "arguments": "",
            # Empty a third of the time so the drawer's "omit when absent" path
            # shows up in the seeded data too, not just the populated one.
            "attributes": json.dumps(rng.choice(ATTRIBUTE_BAGS))
            if rng.random() < ATTRIBUTES_POPULATED_RATIO
            else "",
            "user_roles": list(roles),
            "deciding_role": "" if denied else roles[0],
            **run.as_fields(),
        }
    )


def _anomaly_row(
    target: SeedTarget,
    rng: random.Random,
    *,
    timestamp: datetime,
    session_id: str,
    user_id: str,
    run: RunSnapshot,
) -> Row:
    return _project_row(
        {
            **_envelope(
                target,
                rng,
                timestamp=timestamp,
                session_id=session_id,
                user_id=user_id,
            ),
            "tool_name": rng.choice(RESTRICTED_TOOLS),
            "outcome": DENY_OUTCOME,
            "error_type": DENY_ERROR_TYPE,
            "reason": DENY_REASON,
            "violations": list(ANOMALY_VIOLATIONS),
            "hint": "",
            "arguments": "",
            # Always populated: the anomaly is a restricted-tool deny, and the
            # low-clearance bag is what makes it explainable in the drawer.
            "attributes": json.dumps(ANOMALY_ATTRIBUTES),
            "user_roles": _role_set(user_id),
            "deciding_role": "",
            **run.as_fields(),
        }
    )


def _validate_columns(client: Client) -> None:
    result = client.query("DESCRIBE TABLE policy_decision")
    actual_columns = [row[0] for row in result.result_rows]
    missing = set(_SEED_COLUMNS) - set(actual_columns)
    if missing:
        raise ValueError(
            f"ClickHouse table policy_decision is missing columns: {missing}"
        )


# ── Generators ────────────────────────────────────────────────────────────────


def _run_start(rng: random.Random, now: datetime) -> datetime:
    return now - timedelta(
        days=rng.randint(0, SEED_WINDOW_DAYS - 1),
        hours=rng.randint(0, 23),
        minutes=rng.randint(0, 59),
    )


def _run_timestamps(
    rng: random.Random, start: datetime, count: int
) -> Iterator[datetime]:
    timestamp = start
    for _ in range(count):
        yield timestamp
        timestamp += timedelta(seconds=rng.randint(1, SECONDS_BETWEEN_DECISIONS_MAX))


def _elapsed_ms(start: datetime, timestamp: datetime) -> int:
    return int((timestamp - start).total_seconds() * 1_000)


def generate_normal_data(
    target: SeedTarget,
    rng: random.Random,
    now: datetime,
    number_users: int,
) -> list[Row]:
    rows: list[Row] = []
    for user_id in USER_IDS[:number_users]:
        emitted = 0
        while emitted < ROWS_PER_USER:
            decisions = min(
                rng.randint(DECISIONS_PER_RUN_MIN, DECISIONS_PER_RUN_MAX),
                ROWS_PER_USER - emitted,
            )
            start = _run_start(rng, now)
            session_id = str(uuid4())
            progress = RunProgress(rng, uuid4())
            outcomes = rng.choices(OUTCOMES, weights=OUTCOME_WEIGHTS, k=decisions)
            for outcome, timestamp in zip(
                outcomes, _run_timestamps(rng, start, decisions)
            ):
                rows.append(
                    _normal_row(
                        target,
                        rng,
                        outcome=outcome,
                        timestamp=timestamp,
                        session_id=session_id,
                        user_id=user_id,
                        run=progress.snapshot(_elapsed_ms(start, timestamp)),
                    )
                )
                progress.record(outcome)
            emitted += decisions
    return rows


def generate_anomalies(
    target: SeedTarget,
    rng: random.Random,
    now: datetime,
    number_anomalies: int,
    number_users: int,
) -> list[Row]:
    rows: list[Row] = []
    for _ in range(number_anomalies):
        anomaly_user = rng.choice(USER_IDS[:number_users])
        anomaly_base = now - timedelta(days=rng.randint(0, SEED_WINDOW_DAYS - 1))
        requests = rng.randint(REQUESTS_PER_ANOMALY_MIN, REQUESTS_PER_ANOMALY_MAX)
        session_id = str(uuid4())
        progress = RunProgress(rng, uuid4())
        timestamps = sorted(
            anomaly_base - timedelta(minutes=rng.randint(0, 5)) for _ in range(requests)
        )
        start = timestamps[0]
        for timestamp in timestamps:
            rows.append(
                _anomaly_row(
                    target,
                    rng,
                    timestamp=timestamp,
                    session_id=session_id,
                    user_id=anomaly_user,
                    run=progress.snapshot(_elapsed_ms(start, timestamp)),
                )
            )
            progress.record(DENY_OUTCOME)
    return rows


# ── Public API ────────────────────────────────────────────────────────────────


def build_rows(
    target: SeedTarget, number_users: int, number_anomalies: int
) -> Tuple[list[Row], list[Row]]:
    now = datetime.now(timezone.utc)
    rng = random.Random(0)
    normal = generate_normal_data(target, rng, now, number_users)
    anomalous = generate_anomalies(target, rng, now, number_anomalies, number_users)
    return normal, anomalous


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
    target: SeedTarget,
    number_users: int,
    number_anomalies: int,
) -> Tuple[int, int]:
    clear(client, target.project_id)
    normal, anomalous = build_rows(target, number_users, number_anomalies)
    client.insert(
        "policy_decision",
        normal + anomalous,
        column_names=_SEED_COLUMNS,
        settings=_DECISION_INSERT_SETTINGS,
    )
    return len(normal), len(anomalous)


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
        default="support-agent",
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
        normal_count, anomalous_count = seed(
            client,
            SeedTarget(project_id=args.project_id, agent_name=args.agent_name),
            args.number_users,
            args.number_anomalies,
        )
        print(
            f"Inserted {normal_count + anomalous_count} rows "
            f"({normal_count} normal + {anomalous_count} anomalous)."
        )
