"""Per-project in-process locks serializing a policy write + its recompile.

A policy write (module or role edit) resolves the project, compiles a bundle,
then commits. Two overlapping writes on the same project can otherwise interleave
those steps and commit bundles out of order: writer A resolves R1 and yields on
the opa compile, B commits R2 and its bundles, then A commits the R1 bundle over
them — DB and ``/policy/resolve`` say R2 while agents enforce R1, with no error.
Holding this lock across the whole read→write→recompile makes them serial.

Scope: one event loop / process only. Under multiple uvicorn workers it does not
serialize across processes; the durable fix is a DB advisory lock (Postgres
``pg_advisory_xact_lock``), deferred here because policy writes are admin-only
and infrequent.
"""

from __future__ import annotations

import asyncio
from collections import defaultdict

_locks: defaultdict[str, asyncio.Lock] = defaultdict(asyncio.Lock)


def project_lock(project_id: str) -> asyncio.Lock:
    """The lock for one project — the same object per id within this process."""
    return _locks[project_id]
