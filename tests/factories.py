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
    is_verified: bool = True,
):
    """Creates and persists a User with a real bcrypt hash of `password`.

    Returns (user, plaintext_password) since the plaintext is needed by
    tests that exercise /auth/login and is otherwise thrown away by the
    hash.

    OBJ-005 (docs/testing/obj-005-test-report.md's flagged cross-cutting
    risk, required non-optional carry-over): `is_verified` now defaults to
    True, not False. Once /auth/login enforces is_verified, every
    pre-OBJ-005 test across ~13 files that logs in via a bare
    `user_factory(...)` call (never passing is_verified) would otherwise
    start failing with 400 "Email not verified" instead of 200. Tests that
    specifically need an UNVERIFIED user (this objective's own new test
    files) all pass `is_verified=False` explicitly regardless of this
    default.
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

    OBJ-003 (audit finding #7, obj-003-design-notes.md section 1.5):
    `Verification.code` is now an HMAC-SHA256 hex digest, not plaintext --
    this factory seeds `security.hash_otp(code)` into the column, not `code`
    itself, so the stored row matches what the real /forgot-password flow
    will store once finding #7 lands (module ownership: `hash_otp` lives in
    app.core.security, the single source of truth for the HMAC
    construction -- this factory must never reimplement it inline, or the
    two could silently drift). The plaintext `code` is still returned to
    the caller UNCHANGED (needed for the caller to submit it over HTTP --
    see the docstring paragraph above); only the *stored* value changes.

    REQUIRED, NOT OPTIONAL -- explicitly flagged by design notes section
    1.5: "every existing OTP test... will otherwise silently start failing
    every 'correct code' assertion... unless the factory is updated in the
    same pass." This is that update.

    KNOWN, DOCUMENTED RED-PHASE CONSEQUENCE (not a broken factory): until
    `app.core.security.hash_otp` exists, this call raises AttributeError --
    every test using the `verification_factory` fixture ERRORS (not a clean
    assertion failure) until `developer` implements finding #7. See
    .ai-context/dependency_graph.md's "OBJ-003 -- Phase 2 (red phase)"
    section for the exact count of previously-green tests this affects and
    why that number is real, not a sign this factory (or those tests) is
    wrong.
    """
    verification = Verification(
        email=email,
        code=security.hash_otp(code),
        purpose=purpose,
        expires_at=expires_at or (datetime.now(timezone.utc) + timedelta(minutes=ttl_minutes)),
    )
    db_session.add(verification)
    await db_session.commit()
    await db_session.refresh(verification)
    return verification
