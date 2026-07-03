"""Minimal ITSM datastore for examples/itsm_agent.py.

Backed by stdlib ``sqlite3`` in an in-memory database (no extra
dependency), seeded from the Attachment B DDL verbatim — so the
``CHECK (state IN (...))`` enum and the ``cmdb_ci`` foreign key are a
real bottom layer of defense beneath the agent's policy + state guard.

The tools in ``itsm_agent.py`` call these repository functions; they
never embed raw SQL. State-machine and ownership decisions live in the
tools (they read the *trusted* ``User`` identity); this module is plain
CRUD plus a local audit trail (UC-10).

Note on the minimal model: Attachment B has no dedicated assessment
columns (risk/impact/justification) or a CAB-decision column. So the
Change Manager's assessment edit operates on ``short_description``, and
the CAB decision is carried into the audit record rather than a stored
column. A fuller schema would add those columns; the security model is
identical either way.
"""

from __future__ import annotations

import sqlite3
from typing import Any

# ---------------------------------------------------------------------------
# Schema + seed — Attachment B, verbatim.
# ---------------------------------------------------------------------------

_SCHEMA = """
CREATE TABLE ci_class (
    id          INTEGER PRIMARY KEY,
    name        VARCHAR(50) NOT NULL UNIQUE,
    description VARCHAR(255)
);

CREATE TABLE cmdb_ci (
    id          INTEGER PRIMARY KEY,
    name        VARCHAR(100) NOT NULL,
    ci_class_id INTEGER NOT NULL,
    status      VARCHAR(20) NOT NULL DEFAULT 'operational',
    CONSTRAINT fk_cmdb_ci_class FOREIGN KEY (ci_class_id) REFERENCES ci_class (id)
);

CREATE TABLE change_request (
    id                INTEGER PRIMARY KEY,
    number            VARCHAR(20) NOT NULL UNIQUE,
    short_description VARCHAR(255) NOT NULL,
    state             VARCHAR(20) NOT NULL DEFAULT 'new'
                      CHECK (state IN ('new', 'Assess', 'Authorize', 'Schedule')),
    cmdb_ci_id        INTEGER,
    requester_email   VARCHAR(150),
    implementer_email VARCHAR(150),
    CONSTRAINT fk_change_ci FOREIGN KEY (cmdb_ci_id) REFERENCES cmdb_ci (id)
);
"""

_SEED = """
INSERT INTO ci_class (id, name, description) VALUES
    (1, 'server',      'Physical or virtual server'),
    (2, 'application', 'Business or technical application');

INSERT INTO cmdb_ci (id, name, ci_class_id, status) VALUES
    (1, 'srv-web-01', 1, 'operational'),
    (2, 'srv-web-02', 1, 'operational'),
    (3, 'srv-db-01',  1, 'operational'),
    (4, 'srv-app-01', 1, 'operational'),
    (5, 'CRM',     2, 'operational'),
    (6, 'ERP',     2, 'operational'),
    (7, 'Billing', 2, 'operational');

INSERT INTO change_request
    (id, number, short_description, state, cmdb_ci_id, requester_email, implementer_email)
VALUES
    (1, 'CHG0001', 'Patch CRM application server', 'new', 5,
     'demo.hexgate+alice.martin@hexamind.ai',
     'demo.hexgate+carla.robert@hexamind.ai');
"""


# ---------------------------------------------------------------------------
# Connection + audit trail.
# ---------------------------------------------------------------------------

_conn: sqlite3.Connection | None = None

# In-process audit log (UC-10). Every create / update / transition appends a
# record with actor, role, before/after state — demonstrating non-repudiation
# in the demo output. The platform additionally audits every policy decision.
AUDIT_LOG: list[dict[str, Any]] = []


def init_db() -> None:
    """(Re)create the in-memory DB and seed it. Idempotent across demo runs."""
    global _conn
    _conn = sqlite3.connect(":memory:", check_same_thread=False)
    _conn.row_factory = sqlite3.Row
    _conn.execute("PRAGMA foreign_keys = ON")  # enforce fk_change_ci at the DB layer
    _conn.executescript(_SCHEMA)
    _conn.executescript(_SEED)
    _conn.commit()
    AUDIT_LOG.clear()


def _db() -> sqlite3.Connection:
    if _conn is None:
        init_db()
    assert _conn is not None
    return _conn


def audit(
    *,
    action: str,
    actor: str,
    role: str | None,
    number: str | None,
    decision: str,
    before: str | None = None,
    after: str | None = None,
    detail: str = "",
) -> None:
    """Append an immutable-style audit record and echo it to stdout."""
    record = {
        "action": action,
        "actor": actor,
        "role": role,
        "change": number,
        "from_state": before,
        "to_state": after,
        "decision": decision,
        "detail": detail,
    }
    AUDIT_LOG.append(record)
    print(
        f"  [AUDIT] {decision:5} {action:22} actor={actor} role={role} "
        f"change={number} {before or '-'}→{after or '-'} {detail}".rstrip()
    )


# ---------------------------------------------------------------------------
# Reads.
# ---------------------------------------------------------------------------


def resolve_ci(name: str) -> dict[str, Any] | None:
    """Resolve a CI by exact name (e.g. 'srv-db-01', 'CRM'). None if unknown."""
    row = _db().execute(
        "SELECT id, name, ci_class_id FROM cmdb_ci WHERE name = ?", (name,)
    ).fetchone()
    return dict(row) if row else None


def ci_name(cmdb_ci_id: int | None) -> str | None:
    if cmdb_ci_id is None:
        return None
    row = _db().execute("SELECT name FROM cmdb_ci WHERE id = ?", (cmdb_ci_id,)).fetchone()
    return row["name"] if row else None


def get_change(number: str) -> dict[str, Any] | None:
    """Return a change_request row as a dict (with resolved CI name), or None."""
    row = _db().execute(
        "SELECT * FROM change_request WHERE number = ?", (number,)
    ).fetchone()
    if row is None:
        return None
    change = dict(row)
    change["ci"] = ci_name(change["cmdb_ci_id"])
    return change


def all_changes() -> list[dict[str, Any]]:
    """Every change_request (the tool layer filters by the caller's scope)."""
    rows = _db().execute("SELECT * FROM change_request ORDER BY id").fetchall()
    out = []
    for row in rows:
        change = dict(row)
        change["ci"] = ci_name(change["cmdb_ci_id"])
        out.append(change)
    return out


# ---------------------------------------------------------------------------
# Writes — plain persistence. Authorization is enforced upstream in the tools.
# ---------------------------------------------------------------------------


def _next_number() -> str:
    row = _db().execute("SELECT COUNT(*) AS n FROM change_request").fetchone()
    return f"CHG{row['n'] + 1:04d}"


def create_change(
    *, short_description: str, ci_name: str, requester_email: str
) -> dict[str, Any]:
    """Insert a new change in state 'new'. Raises ValueError on unknown CI."""
    ci = resolve_ci(ci_name)
    if ci is None:
        raise ValueError(f"unknown CI {ci_name!r}")
    number = _next_number()
    db = _db()
    db.execute(
        "INSERT INTO change_request "
        "(number, short_description, state, cmdb_ci_id, requester_email) "
        "VALUES (?, ?, 'new', ?, ?)",
        (number, short_description, ci["id"], requester_email),
    )
    db.commit()
    created = get_change(number)
    assert created is not None
    return created


def update_change_fields(
    number: str, *, description: str | None = None, ci_name: str | None = None
) -> dict[str, Any]:
    """Update editable fields on a change. Raises ValueError on unknown CI."""
    db = _db()
    if description is not None:
        db.execute(
            "UPDATE change_request SET short_description = ? WHERE number = ?",
            (description, number),
        )
    if ci_name is not None:
        ci = resolve_ci(ci_name)
        if ci is None:
            raise ValueError(f"unknown CI {ci_name!r}")
        db.execute(
            "UPDATE change_request SET cmdb_ci_id = ? WHERE number = ?",
            (ci["id"], number),
        )
    db.commit()
    updated = get_change(number)
    assert updated is not None
    return updated


def set_state(number: str, new_state: str) -> dict[str, Any]:
    """Persist a state transition. The CHECK constraint backstops the enum."""
    db = _db()
    db.execute(
        "UPDATE change_request SET state = ? WHERE number = ?", (new_state, number)
    )
    db.commit()
    updated = get_change(number)
    assert updated is not None
    return updated
