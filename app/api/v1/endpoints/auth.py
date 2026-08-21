import secrets
import string
from datetime import datetime, timedelta, timezone
from typing import Any
from fastapi import APIRouter, Depends, HTTPException, Request, status, Body
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, delete

from app.api import deps
from app.core import security
from app.core import rate_limit
from app.models.user import User
from app.models.verification import Verification
from app.schemas.user import UserCreate, UserResponse, Token, EmailRequest, OTPVerifyRequest, PasswordResetRequest

router = APIRouter()

# OBJ-001 Gate 1 decisions (dependency_graph.md, 2026-08-21). Hardcoded here
# (not wired to Settings) per tests/README.md's note to qa-engineer's own
# constants -- update both places together if these thresholds ever change.
MAX_OTP_ATTEMPTS = 5
OTP_RESEND_COOLDOWN_SECONDS = 60
FORGOT_PASSWORD_RATE_LIMIT_PER_MINUTE = 5
VERIFY_OTP_RATE_LIMIT_PER_MINUTE = 10
RESET_PASSWORD_RATE_LIMIT_PER_MINUTE = 10

RESET_PASSWORD_PURPOSE = "reset_password"
GENERIC_OTP_SENT_MESSAGE = "If the email exists, an OTP has been sent."
GENERIC_OTP_INVALID_MESSAGE = "Invalid or expired OTP"


def _generate_otp() -> str:
    """CSPRNG-backed 6-digit OTP (audit finding #2: the old stdlib `random`
    module is not cryptographically secure)."""
    return "".join(secrets.choice(string.digits) for _ in range(6))


async def _check_and_consume_otp(db: AsyncSession, email: str, otp: str) -> Verification:
    """Validates `otp` against the live `reset_password` Verification row for
    `email`, sharing ONE failed-attempt budget between /verify-otp and
    /reset-password (audit finding #2 -- design notes section 2).

    - No live (unexpired) row at all -> generic 400, no state change (only
      /forgot-password creates rows; nothing here should become a row-spam
      vector).
    - Live row, wrong code -> increments `attempts`; once it reaches
      MAX_OTP_ATTEMPTS the row is invalidated (expires_at pulled to "now")
      so it stops matching future "live row" lookups too. Same generic 400
      either way -- lockout, expiry, and wrong-code are indistinguishable
      by design (no new oracle).
    - Live row, correct code -> returned to the caller to finish the
      business flow (verify-otp just reports success; reset-password also
      deletes it after use).
    """
    generic_error = HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=GENERIC_OTP_INVALID_MESSAGE)

    result = await db.execute(
        select(Verification).filter(
            Verification.email == email,
            Verification.purpose == RESET_PASSWORD_PURPOSE,
            Verification.expires_at > datetime.now(timezone.utc),
        )
    )
    verification = result.scalars().first()

    if verification is None:
        raise generic_error

    if verification.code != otp:
        verification.attempts += 1
        if verification.attempts >= MAX_OTP_ATTEMPTS:
            verification.expires_at = datetime.now(timezone.utc)
        await db.commit()
        raise generic_error

    return verification


@router.get("/me", response_model=UserResponse)
async def read_current_user(
    current_user: User = Depends(deps.get_current_active_user),
) -> Any:
    return current_user


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def register(
    user_in: UserCreate,
    db: AsyncSession = Depends(deps.get_db)
) -> Any:
    result = await db.execute(select(User).filter(User.email == user_in.email))
    user = result.scalars().first()
    if user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="The user with this email already exists in the system.",
        )

    user = User(
        email=user_in.email,
        hashed_password=security.get_password_hash(user_in.password),
        is_active=True,
        is_verified=False
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)
    return user


@router.post("/login", response_model=Token)
async def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: AsyncSession = Depends(deps.get_db)
) -> Any:
    result = await db.execute(select(User).filter(User.email == form_data.username))
    user = result.scalars().first()

    if not user or not security.verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Incorrect email or password")

    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Inactive user")

    access_token = security.create_access_token(user.email)
    refresh_token = security.create_refresh_token(user.email)

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "refresh_token": refresh_token
    }


@router.post("/forgot-password")
async def forgot_password(
    http_request: Request,
    payload: EmailRequest,
    db: AsyncSession = Depends(deps.get_db)
) -> Any:
    await rate_limit.enforce_rate_limit(
        db,
        scope="forgot_password",
        ip=rate_limit.client_ip(http_request),
        email=payload.email,
        limit=FORGOT_PASSWORD_RATE_LIMIT_PER_MINUTE,
    )

    result = await db.execute(select(User).filter(User.email == payload.email))
    user = result.scalars().first()
    if not user:
        return {"msg": GENERIC_OTP_SENT_MESSAGE}

    # Resend cooldown (design notes section 2): if a row for this
    # (email, purpose) was created within the last OTP_RESEND_COOLDOWN_SECONDS
    # -- whether it's still usable or already locked/expired -- don't rotate
    # it. This is deliberate even for an already-locked-out row: it stops an
    # attacker who just burned their attempt budget from immediately
    # requesting a fresh one and resetting it. Same generic 200 either way.
    existing_result = await db.execute(
        select(Verification)
        .filter(
            Verification.email == payload.email,
            Verification.purpose == RESET_PASSWORD_PURPOSE,
        )
        .order_by(Verification.created_at.desc())
    )
    existing = existing_result.scalars().first()
    if existing is not None:
        cooldown_cutoff = datetime.now(timezone.utc) - timedelta(seconds=OTP_RESEND_COOLDOWN_SECONDS)
        if existing.created_at is not None and existing.created_at > cooldown_cutoff:
            return {"msg": GENERIC_OTP_SENT_MESSAGE}

    # Rotate: invalidate any previous OTPs for this email and issue a fresh one.
    await db.execute(
        delete(Verification).where(
            Verification.email == payload.email,
            Verification.purpose == RESET_PASSWORD_PURPOSE
        )
    )

    otp = _generate_otp()
    verification = Verification(
        email=payload.email,
        code=otp,
        purpose=RESET_PASSWORD_PURPOSE,
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=10)
    )
    db.add(verification)
    await db.commit()

    # MOCK EMAIL SENDER
    print(f"============================================")
    print(f" [EMAIL MOCK] To: {payload.email} | OTP: {otp} ")
    print(f"============================================")

    return {"msg": GENERIC_OTP_SENT_MESSAGE}


@router.post("/verify-otp")
async def verify_otp(
    http_request: Request,
    payload: OTPVerifyRequest,
    db: AsyncSession = Depends(deps.get_db)
) -> Any:
    await rate_limit.enforce_rate_limit(
        db,
        scope="verify_otp",
        ip=rate_limit.client_ip(http_request),
        email=payload.email,
        limit=VERIFY_OTP_RATE_LIMIT_PER_MINUTE,
    )

    await _check_and_consume_otp(db, payload.email, payload.otp)

    return {"msg": "OTP verified successfully"}


@router.post("/reset-password")
async def reset_password(
    http_request: Request,
    payload: PasswordResetRequest,
    db: AsyncSession = Depends(deps.get_db)
) -> Any:
    await rate_limit.enforce_rate_limit(
        db,
        scope="reset_password",
        ip=rate_limit.client_ip(http_request),
        email=payload.email,
        limit=RESET_PASSWORD_RATE_LIMIT_PER_MINUTE,
    )

    verification = await _check_and_consume_otp(db, payload.email, payload.otp)

    result_user = await db.execute(select(User).filter(User.email == payload.email))
    user = result_user.scalars().first()

    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    user.hashed_password = security.get_password_hash(payload.new_password)
    await db.delete(verification)
    await db.commit()

    return {"msg": "Password updated successfully"}


@router.post("/refresh", response_model=Token)
async def refresh_token(
    refresh_token: str = Body(..., embed=True),
    db: AsyncSession = Depends(deps.get_db)
) -> Any:
    email = security.verify_refresh_token(refresh_token)

    result = await db.execute(select(User).filter(User.email == email))
    user = result.scalars().first()
    if not user or not user.is_active:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="User inactive or not found")

    new_access_token = security.create_access_token(user.email)

    return {
        "access_token": new_access_token,
        "token_type": "bearer",
        "refresh_token": refresh_token
    }
