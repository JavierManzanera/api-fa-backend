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
    ip_limit: int | None = None,
    window_seconds: int = DEFAULT_WINDOW_SECONDS,
) -> None:
    """Raise 429 if EITHER the IP-only or the email-only sliding-window
    count for `scope` within `window_seconds` has reached its own
    independent limit; otherwise record the current request (one row,
    same shape as today -- both `ip` and `email` still stored for
    forensics) and let the caller proceed.

    Two independent counts, not one combined (scope, ip, email) count --
    closes audit finding #17 (obj-013-design-notes.md): an attacker who
    rotates only ONE of (ip, email) must still contend with the OTHER
    dimension's own limit, instead of resetting to a fresh zero-count
    bucket on every request.

    `limit` keeps its pre-OBJ-013 meaning: the email-keyed threshold,
    unchanged at all 6 call sites. `ip_limit` is new and optional --
    defaults to `limit * settings.RATE_LIMIT_IP_MULTIPLIER` (read live at
    call time, not captured at import time) when the caller doesn't
    override it, so all 6 existing call sites get the IP-only check for
    free with zero call-site diffs.
    """
    resolved_ip_limit = ip_limit if ip_limit is not None else limit * settings.RATE_LIMIT_IP_MULTIPLIER

    now = datetime.now(timezone.utc)
    window_start = now - timedelta(seconds=window_seconds)

    ip_hits = await db.execute(
        select(func.count())
        .select_from(RateLimitHit)
        .where(
            RateLimitHit.scope == scope,
            RateLimitHit.ip == ip,
            RateLimitHit.created_at > window_start,
        )
    )
    if ip_hits.scalar_one() >= resolved_ip_limit:
        await _raise_rate_limited(scope=scope, ip=ip, email=email, window_seconds=window_seconds, dimension="ip")

    email_hits = await db.execute(
        select(func.count())
        .select_from(RateLimitHit)
        .where(
            RateLimitHit.scope == scope,
            RateLimitHit.email == email,
            RateLimitHit.created_at > window_start,
        )
    )
    if email_hits.scalar_one() >= limit:
        await _raise_rate_limited(scope=scope, ip=ip, email=email, window_seconds=window_seconds, dimension="email")

    db.add(RateLimitHit(scope=scope, ip=ip, email=email, created_at=now))
    await db.commit()


async def _raise_rate_limited(
    *, scope: str, ip: str, email: str, window_seconds: int, dimension: str
) -> None:
    """Shared 429 path for both the IP-only and email-only checks above.

    `dimension` ("ip" or "email") is logged for security-monitoring
    visibility only -- OBJ-013 design notes section 3: it must NEVER reach
    the HTTP response (body or headers), which stay byte-for-byte identical
    regardless of which dimension tripped. Differentiating the wire
    response would create a new oracle (OBJ-007 finding #6's
    anti-enumeration property), so `dimension` is not passed to
    HTTPException below, only to the audit log.
    """
    # OBJ-004 finding #10 (obj-004-design-notes.md section 4.2):
    # auth.rate_limit.exceeded, WARNING -- a genuine security signal
    # worth a human noticing, not routine traffic.
    audit_log.log_auth_event(
        "auth.rate_limit.exceeded",
        level=logging.WARNING,
        scope=scope,
        ip=ip,
        email=email,
        dimension=dimension,
    )
    raise HTTPException(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        detail="Too many requests. Please try again later.",
        headers={"Retry-After": str(window_seconds)},
    )


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
