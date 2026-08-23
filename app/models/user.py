import uuid
from sqlalchemy import String, Boolean, DateTime, Integer, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column
from app.core.database import Base

class User(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email: Mapped[str] = mapped_column(String, unique=True, index=True, nullable=False)
    hashed_password: Mapped[str] = mapped_column(String, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    is_verified: Mapped[bool] = mapped_column(Boolean, default=False)
    # OBJ-002 (audit finding #3): bumped on /auth/reset-password to
    # invalidate every access/refresh token issued before the bump (see
    # `ver` claim comparison in app/api/deps.py and
    # app/api/v1/endpoints/auth.py's /auth/refresh handler).
    token_version: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_at: Mapped[float] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[float] = mapped_column(DateTime(timezone=True), onupdate=func.now(), server_default=func.now())
