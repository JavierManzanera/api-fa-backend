import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, ForeignKey, Index
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column
from app.core.database import Base


class RefreshSession(Base):
    """One row per issued refresh token (login) or rotated refresh token
    (successful /auth/refresh). Stores only the token's `jti` -- never the
    raw JWT -- following the established Postgres-table style of
    `app/models/rate_limit.py` (OBJ-001). Backs OBJ-002's rotation +
    reuse-detection state machine (docs/api/obj-002-design-notes.md section 1-2).

    Unlike `RateLimitHit`/`Verification`, `user_id` IS a real FK: rows here
    are only ever created for an already-authenticated, already-existing
    user (at login or successful rotation), so there is no
    unauthenticated/nonexistent-user case to protect against (design notes
    section 1).

    `issued_at`/`expires_at` are Python-side, NOT `server_default=func.now()`
    -- same freezegun-consistency reasoning already established for
    `Verification.created_at` and `RateLimitHit.created_at` in OBJ-001: every
    timestamp in a request's lifecycle (the JWT's own `exp`/`iat` and this
    mirroring row) must agree with a frozen test clock, which a Postgres-side
    `now()` would ignore.
    """

    __tablename__ = "refresh_sessions"
    __table_args__ = (
        Index("ix_refresh_sessions_family_id", "family_id"),
        Index("ix_refresh_sessions_user_id_revoked_at", "user_id", "revoked_at"),
    )

    # == the `jti` claim of the refresh token this row represents.
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    # Constant across a rotation chain; == id of the row created at login.
    family_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id"), nullable=False
    )
    issued_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    # NULL = active; set on rotation-supersession, logout, reuse-triggered
    # family revocation, or password-reset bulk revocation.
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # Audit-trail pointer set at rotation time; not required for correctness
    # (family_id + revoked_at already suffice for the state machine).
    replaced_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("refresh_sessions.id"), nullable=True
    )
