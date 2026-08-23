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


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


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
