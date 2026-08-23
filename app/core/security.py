import hashlib
import hmac
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional, Any, Union
from jose import jwt, JWTError
from fastapi import HTTPException, status
from passlib.context import CryptContext
from app.core.config import settings

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

ALGORITHM = settings.ALGORITHM
SECRET_KEY = settings.SECRET_KEY

TOKEN_TYPE_ACCESS = "access"
TOKEN_TYPE_REFRESH = "refresh"

# OBJ-003 finding #7 (obj-003-design-notes.md section 1.1, Option B --
# decided): the OTP-hashing HMAC key is DERIVED from SECRET_KEY, not the
# raw SECRET_KEY bytes themselves -- this gives key separation (a
# verifications-table dump alone can't forge/verify OTP hashes without also
# having SECRET_KEY) without adding a new required secret. Computed once at
# import time, not per-call.
_OTP_HMAC_CONTEXT = b"api-fa-backend:otp-hmac:v1"
_OTP_HMAC_KEY = hmac.new(
    settings.SECRET_KEY.encode("utf-8"), _OTP_HMAC_CONTEXT, hashlib.sha256
).digest()


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


# OBJ-003 finding #5 (obj-003-design-notes.md section 3.1): a precomputed
# dummy bcrypt hash, computed once at process startup (not per-request), so
# verify_password_or_dummy always has a real bcrypt target to verify against
# even when no matching user/record exists. Deriving it via
# get_password_hash(...) keeps it automatically consistent with whatever
# bcrypt cost factor passlib is configured with.
DUMMY_PASSWORD_HASH = get_password_hash(secrets.token_urlsafe(32))


def verify_password_or_dummy(plain_password: str, hashed_password: Optional[str]) -> bool:
    """OBJ-003 finding #5 (obj-003-design-notes.md section 3.1): always
    performs exactly ONE bcrypt verify call, regardless of whether
    `hashed_password` is known -- this is the structural guarantee that
    closes the timing side-channel (a nonexistent user must not let the
    caller short-circuit past the expensive bcrypt call). When
    `hashed_password` is None, verifies against DUMMY_PASSWORD_HASH instead
    (purely for its constant-cost side effect) and unconditionally returns
    False -- the dummy verify's own boolean result is never trusted."""
    target = hashed_password if hashed_password is not None else DUMMY_PASSWORD_HASH
    result = verify_password(plain_password, target)
    return result if hashed_password is not None else False


def hash_otp(code: str) -> str:
    """OBJ-003 finding #7 (obj-003-design-notes.md section 1.1, Option B):
    HMAC-SHA256 of `code`, keyed by _OTP_HMAC_KEY (itself derived from
    SECRET_KEY, never the raw SECRET_KEY bytes) -- returns a 64-char hex
    digest. Single source of truth for OTP-at-rest hashing; every write
    site (app/api/v1/endpoints/auth.py, tests/factories.py) must call this
    rather than reimplementing the construction inline."""
    return hmac.new(_OTP_HMAC_KEY, code.encode("utf-8"), hashlib.sha256).hexdigest()


def verify_otp_hash(code: str, stored_hash: str) -> bool:
    """Constant-time comparison (hmac.compare_digest) of a freshly-hashed
    `code` against `stored_hash` -- closes a secondary digest-comparison
    timing concern as a side effect of finding #7's storage-format fix
    (obj-003-design-notes.md section 1.3). Fails closed (returns False,
    never raises) against a malformed/still-plaintext `stored_hash`."""
    return hmac.compare_digest(hash_otp(code), stored_hash)


def create_access_token(
    subject: Union[str, Any],
    ver: int = 0,
    expires_delta: Optional[timedelta] = None,
) -> str:
    """`ver` (OBJ-002, design notes section 3) is the issuing user's
    `token_version` at mint time -- defaults to 0 so pre-OBJ-002 call sites
    (and unit tests that don't care about token_version) keep working
    unchanged; every real call site in app/api/v1/endpoints/auth.py passes
    the user's actual current value explicitly."""
    expire = datetime.now(timezone.utc) + (
        expires_delta if expires_delta else timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    to_encode = {
        "exp": expire,
        "iat": datetime.now(timezone.utc),
        "sub": str(subject),
        "type": TOKEN_TYPE_ACCESS,
        "ver": ver,
    }
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def create_refresh_token(
    subject: Union[str, Any],
    ver: int = 0,
    jti: Optional[Union[str, uuid.UUID]] = None,
    expires_delta: Optional[timedelta] = None,
) -> str:
    """`jti` (OBJ-002, design notes section 1-2) identifies the
    `refresh_sessions` row this token represents. Auto-generated when not
    given, so this function stays self-sufficient for direct/unit-test
    callers -- but every real issuance call site (login, rotation) passes
    an explicit `jti` so the JWT claim matches the DB row it creates."""
    expire = datetime.now(timezone.utc) + (
        expires_delta if expires_delta else timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    )
    to_encode = {
        "exp": expire,
        "iat": datetime.now(timezone.utc),
        "sub": str(subject),
        "type": TOKEN_TYPE_REFRESH,
        "ver": ver,
        "jti": str(jti) if jti is not None else str(uuid.uuid4()),
    }
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def _decode_refresh_payload(token: str) -> dict:
    """Single decode path for a refresh token: signature, `exp`, `type`,
    and presence of `sub` are all validated here so nothing else in the
    codebase decodes a refresh token inline (design notes module-ownership
    rule)."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired refresh token",
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        if payload.get("type") != TOKEN_TYPE_REFRESH:
            raise credentials_exception
        if payload.get("sub") is None:
            raise credentials_exception
        return payload
    except JWTError:
        raise credentials_exception


def verify_refresh_token(token: str) -> str:
    """OBJ-001 contract, unchanged: pure JWT-level validation, no DB/session
    lookup -- returns just the subject email. Kept independently unit-
    testable without Postgres (tests/unit/test_security.py)."""
    return _decode_refresh_payload(token)["sub"]


def decode_refresh_token_claims(token: str) -> dict:
    """OBJ-002: same validation as verify_refresh_token, but returns the
    full payload (sub, jti, ver, exp, iat) for /auth/refresh's
    rotation/reuse-detection state machine, which needs more than the
    subject alone."""
    return _decode_refresh_payload(token)


def extract_jti_if_present(token: str) -> Optional[str]:
    """Best-effort decode used only by /auth/logout's idempotent
    revoke-if-possible path (design notes section 4). Unlike
    verify_refresh_token/decode_refresh_token_claims, this NEVER raises: an
    invalid signature, expired token, or malformed string all just yield
    `None` (nothing to revoke) -- exactly logout's no-oracle contract.
    Signature verification still gates any DB write that follows: an
    unverified/attacker-controlled `jti` is never returned to a caller that
    hasn't validated the signature first.
    """
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError:
        return None
    return payload.get("jti")
