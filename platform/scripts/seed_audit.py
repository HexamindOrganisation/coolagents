# Example: generate data for 40 users and 3 anomalies, project 00000000-0000-0000-0000-000000000003 and agent support-bot.
# cd platform/api && uv run python ../scripts/seed_audit.py --number_users 40 --number_anomalies 3 --project_id 00000000-0000-0000-0000-000000000003 --agent_name support-bot
#
# Example: clear seed rows for project 00000000-0000-0000-0000-000000000003.
# cd platform/api && uv run python ../scripts/seed_audit.py --clear --project_id 00000000-0000-0000-0000-000000000003

from __future__ import annotations

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
from hexgate_api.core.clickhouse import (  # noqa: E402
    BATCH_INSERT_SETTINGS,
    get_clickhouse,
)
from hexgate_api.features.audit.service import (  # noqa: E402
    _ANOMALY_MIN_REQUESTS,
    _DECISION_COLUMNS,
    _decision_row,
    _TIMEDELTA_ANOMALY_HOURS,
)
from hexgate_api.schemas import AuditOutcome, DecisionEvent  # noqa: E402

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
# Normal: exactly 300 rows per user over 30 days, grouped into short runs (one
# session_id + one run_id each) spaced beyond one detector window, outcomes
# weighted 80% allow / 10% deny / 10% needs_approval. The grouping is what
# gives session_id and run_id meaning; see the run bounds below for why it
# must stay under the anomaly threshold.
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
SECONDS_BETWEEN_DECISIONS_MAX = 45
INGEST_LAG_SECONDS_MAX = 5

# Background traffic must not read as anomalous. The detector flags a user with
# _ANOMALY_MIN_REQUESTS or more decisions inside a _TIMEDELTA_ANOMALY_HOURS
# window at a >= 30% deny rate, so a normal run stays strictly below that
# request count and consecutive runs are spaced beyond one window — a run
# grouping that packed more decisions into a window than the threshold would
# make the seeded baseline flag ~140 medium anomalies on its own, drowning the
# deliberate spikes below. Bounds are derived from the detector's own
# constants so retuning it cannot silently reintroduce that.
DECISIONS_PER_RUN_MIN = 3
DECISIONS_PER_RUN_MAX = _ANOMALY_MIN_REQUESTS - 1
_MAX_RUN_DURATION = timedelta(
    seconds=(DECISIONS_PER_RUN_MAX - 1) * SECONDS_BETWEEN_DECISIONS_MAX
)
_MIN_RUN_SEPARATION = timedelta(hours=_TIMEDELTA_ANOMALY_HOURS) + _MAX_RUN_DURATION
TOKENS_PER_LLM_CALL_MIN = 300
TOKENS_PER_LLM_CALL_MAX = 4_000

OUTCOMES = [AuditOutcome.ALLOW, AuditOutcome.DENY, AuditOutcome.NEEDS_APPROVAL]
OUTCOME_WEIGHTS = [0.8, 0.1, 0.1]

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
# Platform-resolved from the agent registry in production; seeded rows belong
# to no registered agent version, and "" is what the column defaults to.
AGENT_VERSION_ID = ""
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

    def as_event_fields(self) -> Fields:
        """Only the run fields this build's DecisionEvent declares.

        As of this commit that is NONE of them: the six run_* fields exist
        only on the unmerged run-attribution branch, so against main this
        returns an empty dict and every seeded row takes ClickHouse's
        zero-run defaults. Keying off model_fields rather than hardcoding the
        six is what lets one script serve an API image from either side of
        that merge, with no edit needed when the fields land.
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
            if column in DecisionEvent.model_fields
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

    def record(self, outcome: AuditOutcome) -> None:
        """Apply one decision's effect, following RunFacts' record_* methods.

        Only an allow dispatches the tool, so only an allow is a tool_call. A
        denial is counted separately (record_denial) and an approval gate is
        counted as neither — "execution is counted separately, so an approval
        never granted consumes no budget" (RunFacts.record_approval), and
        approvals have no column here. The model was still called either way.
        """
        self._llm_calls += 1
        self._total_tokens += self._rng.randint(
            TOKENS_PER_LLM_CALL_MIN, TOKENS_PER_LLM_CALL_MAX
        )
        if outcome == AuditOutcome.DENY:
            self._denials += 1
        elif outcome == AuditOutcome.ALLOW:
            self._tool_calls += 1


# ── Row builders ──────────────────────────────────────────────────────────────
# Rows come from the API's own _decision_row, not from a local column list.
# That builder is the single place the row-shaping rules live (payload
# serialization, the falsy-attributes normalisation, the legacy role shim), so
# reusing it means the seed names no audit column at all beyond splicing
# received_at, and cannot drift from the ingest contract the way it did
# through the multi-role change (#120).


def _role_set(user_id: str) -> list[str]:
    return ROLE_SETS[USER_IDS.index(user_id) % len(ROLE_SETS)]


@dataclass(frozen=True, slots=True)
class SeededDecision:
    """What differs between a background decision and an anomaly probe.

    Everything else — the envelope, the deny fields, the role set — follows
    from these, so both traffic shapes go through one builder instead of two
    near-identical ones.
    """

    timestamp: datetime
    session_id: str
    user_id: str
    tool_name: str
    outcome: AuditOutcome
    violations: list[str]
    attributes: dict | None
    run: RunSnapshot


def _decision_seed_row(
    target: SeedTarget, rng: random.Random, decision: SeededDecision
) -> Row:
    """One policy_decision row, built by the API and given a seeded received_at.

    received_at is server-stamped in production, so it is absent from
    DecisionEvent and from _decision_row's output; splicing it in at the
    position _SEED_COLUMNS puts it is what lets the seed backdate ingestion
    instead of having every row land at insert time.
    """
    denied = decision.outcome == AuditOutcome.DENY
    roles = list(_role_set(decision.user_id))
    event = DecisionEvent(
        event_id=uuid4(),
        occurred_at=decision.timestamp,
        agent_name=target.agent_name,
        session_id=decision.session_id,
        user_id=decision.user_id,
        tool_name=decision.tool_name,
        outcome=decision.outcome,
        user_roles=roles,
        deciding_role="" if denied else roles[0],
        error_type=DENY_ERROR_TYPE if denied else "",
        reason=DENY_REASON if denied else "",
        violations=list(decision.violations),
        attributes=decision.attributes,
        **decision.run.as_event_fields(),
    )
    row = _decision_row(
        event, project_id=target.project_id, agent_version_id=AGENT_VERSION_ID
    )
    row.insert(
        _idx + 1,
        decision.timestamp + timedelta(seconds=rng.randint(0, INGEST_LAG_SECONDS_MAX)),
    )
    return row


def _background_decision(
    rng: random.Random,
    *,
    outcome: AuditOutcome,
    timestamp: datetime,
    session_id: str,
    user_id: str,
    run: RunSnapshot,
) -> SeededDecision:
    denied = outcome == AuditOutcome.DENY
    return SeededDecision(
        timestamp=timestamp,
        session_id=session_id,
        user_id=user_id,
        tool_name=rng.choice(TOOL_NAMES),
        outcome=outcome,
        violations=DENY_VIOLATIONS if denied else [],
        # Absent a third of the time so the drawer's "omit when absent" path
        # shows up in the seeded data too, not just the populated one.
        attributes=(
            rng.choice(ATTRIBUTE_BAGS)
            if rng.random() < ATTRIBUTES_POPULATED_RATIO
            else None
        ),
        run=run,
    )


def _anomaly_decision(
    rng: random.Random,
    *,
    timestamp: datetime,
    session_id: str,
    user_id: str,
    run: RunSnapshot,
) -> SeededDecision:
    return SeededDecision(
        timestamp=timestamp,
        session_id=session_id,
        user_id=user_id,
        tool_name=rng.choice(RESTRICTED_TOOLS),
        outcome=AuditOutcome.DENY,
        violations=ANOMALY_VIOLATIONS,
        # Always populated: the anomaly is a restricted-tool deny, and the
        # low-clearance bag is what makes it explainable in the drawer.
        attributes=ANOMALY_ATTRIBUTES,
        run=run,
    )


def _validate_row_shape(rows: list[Row]) -> None:
    """Guard the one seam left between the seed and the API's row builder.

    _decision_row emits _DECISION_COLUMNS order and the splice puts
    received_at where _SEED_COLUMNS expects it, so a mismatch here means the
    ingest contract moved received_at or _idx no longer describes it — not a
    forgotten column, which is no longer possible to have.
    """
    widths = {len(row) for row in rows}
    if widths - {len(_SEED_COLUMNS)}:
        raise ValueError(
            f"seed row widths {sorted(widths)} != {len(_SEED_COLUMNS)} columns "
            f"({_SEED_COLUMNS}) — the audit row contract moved"
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


def _run_sizes(rng: random.Random, total: int) -> list[int]:
    """Partition ``total`` decisions into runs, each within the per-run bounds.

    The run count is drawn first and the total spread across it, rather than
    filling greedily: a greedy fill leaves a 1-2 decision remainder for most
    users, and folding that remainder into its neighbour would push one run
    to or past DECISIONS_PER_RUN_MAX + 1 — over the detector's request
    threshold, which is the one thing the bounds exist to prevent.
    """
    if total <= DECISIONS_PER_RUN_MAX:
        return [total]
    fewest = -(-total // DECISIONS_PER_RUN_MAX)
    most = max(total // DECISIONS_PER_RUN_MIN, fewest)
    count = rng.randint(fewest, most)
    size, larger = divmod(total, count)
    sizes = [size + 1] * larger + [size] * (count - larger)
    rng.shuffle(sizes)
    return sizes


def _past_instant(rng: random.Random, now: datetime) -> datetime:
    """A time inside the seed window, far enough back to stay in the past.

    Every row's received_at carries up to INGEST_LAG_SECONDS_MAX on top of
    its occurred_at, so a base drawn right up to ``now`` puts rows seconds
    into the future — which the dashboard's windows read as not-yet-happened.
    Reserving _MIN_RUN_SEPARATION at the recent end keeps that impossible.
    """
    span = timedelta(days=SEED_WINDOW_DAYS)
    latest = now - _MIN_RUN_SEPARATION
    return latest - timedelta(
        seconds=rng.uniform(0, (span - _MIN_RUN_SEPARATION).total_seconds())
    )


def _run_starts(rng: random.Random, now: datetime, count: int) -> list[datetime]:
    """One jittered start per run, one run per evenly-sized slot of the window.

    Slotting rather than a free scatter: two independently placed runs land in
    the same detector window often enough to flag the user, and jitter bounded
    by the slot minus _MIN_RUN_SEPARATION keeps consecutive runs more than a
    window apart by construction instead of by luck.
    """
    span = timedelta(days=SEED_WINDOW_DAYS)
    slot = span / count
    jitter_seconds = max((slot - _MIN_RUN_SEPARATION).total_seconds(), 0.0)
    earliest = now - span
    return [
        earliest + slot * index + timedelta(seconds=rng.uniform(0, jitter_seconds))
        for index in range(count)
    ]


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
        sizes = _run_sizes(rng, ROWS_PER_USER)
        for decisions, start in zip(sizes, _run_starts(rng, now, len(sizes))):
            session_id = str(uuid4())
            progress = RunProgress(rng, uuid4())
            outcomes = rng.choices(OUTCOMES, weights=OUTCOME_WEIGHTS, k=decisions)
            for outcome, timestamp in zip(
                outcomes, _run_timestamps(rng, start, decisions)
            ):
                rows.append(
                    _decision_seed_row(
                        target,
                        rng,
                        _background_decision(
                            rng,
                            outcome=outcome,
                            timestamp=timestamp,
                            session_id=session_id,
                            user_id=user_id,
                            run=progress.snapshot(_elapsed_ms(start, timestamp)),
                        ),
                    )
                )
                progress.record(outcome)
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
        anomaly_base = _past_instant(rng, now)
        requests = rng.randint(REQUESTS_PER_ANOMALY_MIN, REQUESTS_PER_ANOMALY_MAX)
        session_id = str(uuid4())
        progress = RunProgress(rng, uuid4())
        timestamps = sorted(
            anomaly_base - timedelta(minutes=rng.randint(0, 5)) for _ in range(requests)
        )
        start = timestamps[0]
        for timestamp in timestamps:
            rows.append(
                _decision_seed_row(
                    target,
                    rng,
                    _anomaly_decision(
                        rng,
                        timestamp=timestamp,
                        session_id=session_id,
                        user_id=anomaly_user,
                        run=progress.snapshot(_elapsed_ms(start, timestamp)),
                    ),
                )
            )
            progress.record(AuditOutcome.DENY)
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
    _validate_row_shape(normal + anomalous)
    client.insert(
        "policy_decision",
        normal + anomalous,
        column_names=_SEED_COLUMNS,
        settings=BATCH_INSERT_SETTINGS,
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
