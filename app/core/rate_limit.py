"""Sliding-window rate limiter, backed by a Postgres table (no Redis
dependency added to the template) -- OBJ-001 Gate 1 decision, per
docs/api/obj-001-design-notes.md section 2 / section 5 point 4.

Deliberately reuses the SAME AsyncSession the caller received via
`deps.get_db` instead of opening a separate engine/session -- this is what
lets rate-limit state participate in the same per-test transaction/rollback
as the rest of the app (see tests/README.md's testability risk note for
`tests/api/test_rate_limit.py`). A fully separate module-level engine would
make these writes invisible to the test's overridden session and any
assertion would fail with a raw connection error instead of a clean 429/200
check.
"""

import logging
from datetime import datetime, timedelta, timezone

from fastapi import HTTPException, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core import audit_log
from app.core.config import settings
from app.models.rate_limit import RateLimitHit

DEFAULT_WINDOW_SECONDS = 60


async def enforce_rate_limit(
    db: AsyncSession,
    *,
    scope: str,
    ip: str,
    email: str,
    limit: int,
    window_seconds: int = DEFAULT_WINDOW_SECONDS,
) -> None:
    """Raise 429 (with Retry-After) once `limit` requests for this
    (scope, ip, email) key have landed within the trailing `window_seconds`;
    otherwise record the current request and let the caller proceed.
    """
    now = datetime.now(timezone.utc)
    window_start = now - timedelta(seconds=window_seconds)

    result = await db.execute(
        select(func.count())
        .select_from(RateLimitHit)
        .where(
            RateLimitHit.scope == scope,
            RateLimitHit.ip == ip,
            RateLimitHit.email == email,
            RateLimitHit.created_at > window_start,
        )
    )
    hits_in_window = result.scalar_one()

    if hits_in_window >= limit:
        # OBJ-004 finding #10 (obj-004-design-notes.md section 4.2):
        # auth.rate_limit.exceeded, WARNING -- a genuine security signal
        # worth a human noticing, not routine traffic.
        audit_log.log_auth_event(
            "auth.rate_limit.exceeded", level=logging.WARNING, scope=scope, ip=ip, email=email
        )
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many requests. Please try again later.",
            headers={"Retry-After": str(window_seconds)},
        )

    db.add(RateLimitHit(scope=scope, ip=ip, email=email, created_at=now))
    await db.commit()


def client_ip(request) -> str:
    """Best-effort client IP extraction for rate-limit keying.

    OBJ-004 backlog item (obj-004-design-notes.md section 6, OBJ-001 Gate 3
    "New MEDIUM"): X-Forwarded-For is trusted only for the trailing
    `settings.TRUSTED_PROXY_COUNT` hops -- the addresses actually appended
    by infrastructure the operator controls, never anything a client could
    have prepended itself. `TRUSTED_PROXY_COUNT` defaults to 0 ("don't
    trust X-Forwarded-For at all, use the direct socket peer"), the
    maximally safe default and exactly this function's pre-OBJ-004
    behavior. Read as a live `settings.TRUSTED_PROXY_COUNT` attribute at
    call time (not captured at import time) so it stays testable via
    monkeypatch and reconfigurable without a process restart.

    `request.client` can be None depending on the ASGI server/transport
    (e.g. some test transports); fall back to a fixed label rather than
    raising, since a missing IP shouldn't take the endpoint down.
    """
    trusted = settings.TRUSTED_PROXY_COUNT
    if trusted > 0:
        xff = request.headers.get("x-forwarded-for")
        if xff:
            hops = [hop.strip() for hop in xff.split(",") if hop.strip()]
            if len(hops) >= trusted:
                # The N-th hop counting from the right is the address
                # appended by the OUTERMOST trusted proxy -- correct
                # regardless of anything a client prepends earlier in the
                # header, since each trusted proxy appends based on the
                # real TCP connection it observed, not on pre-existing
                # header content.
                return hops[-trusted]
    return request.client.host if request.client else "unknown"
