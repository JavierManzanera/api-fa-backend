import uuid
from datetime import datetime, timezone

from sqlalchemy import String, DateTime, Integer, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column
from app.core.database import Base

class Verification(Base):
    __tablename__ = "verifications"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email: Mapped[str] = mapped_column(String, index=True, nullable=False)
    code: Mapped[str] = mapped_column(String, nullable=False)
    purpose: Mapped[str] = mapped_column(String, nullable=False) # e.g., 'reset_password', 'verify_email'
    # OBJ-001 (audit finding #2): shared failed-attempt counter across
    # /verify-otp and /reset-password -- see app/api/v1/endpoints/auth.py's
    # `_check_and_consume_otp` for the increment/lockout logic.
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    expires_at: Mapped[float] = mapped_column(DateTime(timezone=True), nullable=False)
    # Python-side default (not just server_default) is deliberate: it makes
    # created_at respect freezegun's frozen time in tests (e.g.
    # tests/api/test_otp_resend_cooldown.py), whereas a Postgres-side
    # func.now() would always resolve to real wall-clock time regardless of
    # the test's frozen `datetime.now()`.
    created_at: Mapped[float] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        server_default=func.now(),
    )
