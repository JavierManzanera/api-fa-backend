import uuid

from sqlalchemy import DateTime, Index, String
from sqlalchemy.dialects.postgresql import INET, UUID
from sqlalchemy.orm import Mapped, mapped_column
from app.core.database import Base


class RateLimitHit(Base):
    """One row per accepted request against a rate-limited auth endpoint.

    Backs the sliding-window rate limiter in `app/core/rate_limit.py`:
    counting rows for a given (scope, ip, email) newer than the configured
    window decides whether the current request is allowed. Postgres-table
    backed (no Redis dependency added to the template) per OBJ-001 Gate 1 --
    see docs/api/obj-001-design-notes.md section 2 / section 5 point 4.

    `created_at` is set explicitly by the caller (app code), not a DB
    server_default -- see `app/core/rate_limit.py` for why (freezegun
    consistency with the rest of the request's timestamp arithmetic).
    """

    __tablename__ = "rate_limit_hits"
    __table_args__ = (
        # Serves the IP-only COUNT (scope, ip equality prefix + created_at
        # range) and, empirically (see migration 0009's docstring), the
        # OBJ-014 per-IP EXISTS check too (scope/ip/email are all equality
        # predicates there, so column order among them doesn't matter to
        # the planner) -- added in migration 0001.
        Index(
            "ix_rate_limit_hits_scope_ip_email_created_at",
            "scope",
            "ip",
            "email",
            "created_at",
        ),
        # Serves the email-only COUNT (scope, email equality prefix +
        # created_at range, no ip predicate) -- the hot path that runs on
        # every request to every rate-limited endpoint. NOT served by the
        # index above: `ip` sits between the equality columns and
        # `created_at` there, which breaks the range scan. `ip` is kept as
        # a trailing covering column here (not needed for this query, but
        # free, and usable for a future COUNT(DISTINCT ip) observability
        # query -- obj-014-design-notes.md section 2.7). Added in migration
        # 0009 -- see that migration's docstring and
        # docs/database/obj-006-migration-plan.md (OBJ-014 section) for the
        # full EXPLAIN ANALYZE comparison against the alternative column
        # order.
        Index(
            "ix_rate_limit_hits_scope_email_created_at_ip",
            "scope",
            "email",
            "created_at",
            "ip",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scope: Mapped[str] = mapped_column(String, nullable=False)
    ip: Mapped[str] = mapped_column(INET, nullable=False)
    email: Mapped[str] = mapped_column(String, nullable=False)
    created_at: Mapped[float] = mapped_column(DateTime(timezone=True), nullable=False)
