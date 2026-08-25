"""Scheduled cleanup jobs (OBJ-006, obj-006-migration-plan.md section 4).

APScheduler chosen over pg_cron -- see that doc's "Cleanup job scheduling
mechanism" section for the full rationale (Gate-1 APPROVED 2026-08-23). The
short version: the refresh_sessions job's retention floor must track
Settings.REFRESH_TOKEN_EXPIRE_DAYS, and an in-process scheduler can read
that setting directly and never drift out of sync, whereas a pg_cron job is
pure SQL with zero visibility into the app's config -- its interval literal
would need to be kept in sync by hand.

Both jobs run as plain DML (DELETE) through the app's own AsyncSessionLocal
-- no fa_migrator/DDL rights needed, safe under the DML-only fa_app role in
any environment with role separation enabled (obj-006-migration-plan.md
section 3).

Wired into app/main.py's lifespan: started on startup, shut down on
shutdown. Intentionally never runs during the test suite -- app.main's
lifespan never executes under httpx.ASGITransport (see
tests/conftest.py's `client` fixture docstring: ASGITransport doesn't send
ASGI lifespan events unless explicitly wrapped, which that fixture doesn't
do), so these jobs are never scheduled in tests and never touch the test
database.
"""

import logging
from datetime import datetime, timedelta, timezone

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from sqlalchemy import text

from app.core.config import settings
from app.core.database import AsyncSessionLocal

logger = logging.getLogger(__name__)

# How often each job RUNS (devops-engineer's call) -- not how long it
# retains data (that's the Gate-1-approved retention window baked into
# each DELETE's WHERE clause below). Deliberately much shorter than the
# retention window itself so unbounded growth between runs stays small.
_RATE_LIMIT_HITS_CLEANUP_INTERVAL_MINUTES = 15
_REFRESH_SESSIONS_CLEANUP_INTERVAL_HOURS = 24

# Retention: 1 hour, Gate-1 APPROVED 2026-08-23 (obj-006-migration-plan.md
# section 7, item 1 / "Gate 1 -- APPROVED"). Mirrors
# docs/database/sql/cleanup_rate_limit_hits.sql exactly. Kept as a literal
# here (not read from Settings) because, unlike refresh_sessions's
# retention, this window has no corresponding app Setting to drift out of
# sync with -- it's debugging/clock-skew slack, not derived from anything
# else the app already tracks.
_RATE_LIMIT_HITS_CLEANUP_SQL = text(
    "DELETE FROM rate_limit_hits WHERE created_at < now() - interval '1 hour'"
)

# Mirrors docs/database/sql/cleanup_refresh_sessions.sql, except the cutoff
# is a bound `:cutoff` timestamp computed in Python from
# Settings.REFRESH_TOKEN_EXPIRE_DAYS (see _cleanup_refresh_sessions),
# instead of a hardcoded `interval '7 days'` literal -- this
# parameterization is the entire reason APScheduler was chosen over
# pg_cron for this job. A bound `:cutoff` timestamp (not `now() -
# :retention` with a bound interval/timedelta parameter) is deliberate --
# asyncpg cannot resolve the parameter type of a raw `timedelta` bound
# against `now() - $1` server-side (confirmed empirically: "operator does
# not exist: timestamp with time zone < interval"); computing the cutoff
# timestamp in Python and binding a plain timestamp sidesteps that
# entirely and is equivalent.
_REFRESH_SESSIONS_CLEANUP_SQL = text(
    "DELETE FROM refresh_sessions "
    "WHERE (revoked_at IS NOT NULL AND revoked_at < :cutoff) "
    "   OR (revoked_at IS NULL AND expires_at < :cutoff)"
)


async def _cleanup_rate_limit_hits() -> None:
    async with AsyncSessionLocal() as session:
        result = await session.execute(_RATE_LIMIT_HITS_CLEANUP_SQL)
        await session.commit()
        logger.info(
            "scheduler.cleanup_rate_limit_hits rows_deleted=%s", result.rowcount
        )


async def _cleanup_refresh_sessions() -> None:
    """Retention floor >= Settings.REFRESH_TOKEN_EXPIRE_DAYS (hard floor,
    Gate-1 APPROVED -- not adjustable downward without weakening
    reuse-detection, see obj-006-migration-plan.md section 7 item 2 and
    section 4's own explanation of why: revoked/expired rows here are
    load-bearing evidence for reuse-detection on /auth/refresh).

    HARD DEPENDENCY on migration 0004 (refresh_sess_fk_ondelete) already
    being applied -- without its `ON DELETE SET NULL` on `replaced_by`,
    this DELETE can raise a FK violation once a chain is long enough that
    a purge-eligible row is still pointed at by a newer row's
    `replaced_by`. Migration 0004 is inside the safe 0001-0007 ceiling
    (see this repo's CI workflow / obj-006-migration-plan.md's CRITICAL
    finding on migration 0008), so this holds in every environment this
    scheduler runs in today.
    """
    retention = timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    cutoff = datetime.now(timezone.utc) - retention
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            _REFRESH_SESSIONS_CLEANUP_SQL, {"cutoff": cutoff}
        )
        await session.commit()
        logger.info(
            "scheduler.cleanup_refresh_sessions rows_deleted=%s", result.rowcount
        )


def build_scheduler() -> AsyncIOScheduler:
    """Constructs (but does not start) the scheduler. Split from start/stop
    so app.main's lifespan controls the actual start/shutdown explicitly."""
    scheduler = AsyncIOScheduler()
    scheduler.add_job(
        _cleanup_rate_limit_hits,
        "interval",
        minutes=_RATE_LIMIT_HITS_CLEANUP_INTERVAL_MINUTES,
        id="cleanup_rate_limit_hits",
        # Skip a run instead of piling up a backlog if one run overruns
        # the next scheduled tick -- these are idempotent bulk deletes,
        # never need to "catch up" on a missed run.
        coalesce=True,
        max_instances=1,
    )
    scheduler.add_job(
        _cleanup_refresh_sessions,
        "interval",
        hours=_REFRESH_SESSIONS_CLEANUP_INTERVAL_HOURS,
        id="cleanup_refresh_sessions",
        coalesce=True,
        max_instances=1,
    )
    return scheduler
