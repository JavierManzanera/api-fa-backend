import uuid

from sqlalchemy import DateTime, Index, String
from sqlalchemy.dialects.postgresql import UUID
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
        Index(
            "ix_rate_limit_hits_scope_ip_email_created_at",
            "scope",
            "ip",
            "email",
            "created_at",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scope: Mapped[str] = mapped_column(String, nullable=False)
    ip: Mapped[str] = mapped_column(String, nullable=False)
    email: Mapped[str] = mapped_column(String, nullable=False)
    created_at: Mapped[float] = mapped_column(DateTime(timezone=True), nullable=False)
