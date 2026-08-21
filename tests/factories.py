"""
DB-object factories for tests (OBJ-000). Kept deliberately minimal --
no factory_boy dependency; these are thin async helper functions bound to a
caller-supplied `AsyncSession` (see tests/conftest.py's `user_factory` /
`verification_factory` fixtures for the bound versions tests actually use).
"""

import uuid
from datetime import datetime, timedelta, timezone

from app.core import security
from app.models.user import User
from app.models.verification import Verification

DEFAULT_PASSWORD = "ValidPass123!"  # meets validate_password_strength: upper+digit+special


def _unique_email() -> str:
    return f"user-{uuid.uuid4().hex[:12]}@example.com"


async def create_user(
    db_session,
    *,
    email: str | None = None,
    password: str = DEFAULT_PASSWORD,
    is_active: bool = True,
    is_verified: bool = False,
):
    """Creates and persists a User with a real bcrypt hash of `password`.

    Returns (user, plaintext_password) since the plaintext is needed by
    tests that exercise /auth/login and is otherwise thrown away by the
    hash.
    """
    user = User(
        email=email or _unique_email(),
        hashed_password=security.get_password_hash(password),
        is_active=is_active,
        is_verified=is_verified,
    )
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)
    return user, password


async def create_verification(
    db_session,
    *,
    email: str,
    code: str = "123456",
    purpose: str = "reset_password",
    ttl_minutes: int = 10,
    expires_at=None,
):
    """Seeds a Verification row directly, bypassing /auth/forgot-password.

    Necessary because the OTP is never returned in any HTTP response (only
    ever "sent" via the print-based mock sender) -- there is no black-box
    way to learn a real, endpoint-issued OTP value from a test.
    """
    verification = Verification(
        email=email,
        code=code,
        purpose=purpose,
        expires_at=expires_at or (datetime.now(timezone.utc) + timedelta(minutes=ttl_minutes)),
    )
    db_session.add(verification)
    await db_session.commit()
    await db_session.refresh(verification)
    return verification
