import logging
import secrets
import string
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Optional
from fastapi import APIRouter, Depends, HTTPException, Request, status, Body
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, delete, update

from app.api import deps
from app.core import security
from app.core import rate_limit
from app.core import audit_log
from app.core.config import settings
from app.core.email.base import EmailSender, EmailSendError
from app.core.email.templates import (
    render_verification_email,
    render_already_registered_email,
    render_password_reset_email,
)
from app.models.user import User
from app.models.verification import Verification
from app.models.refresh_session import RefreshSession
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
# OBJ-009 (obj-009-design-notes.md section 1, closes audit finding #16):
# /register sends exactly one outbound email on EVERY call, on BOTH
# branches (see GENERIC_REGISTRATION_MESSAGE below) -- same "triggers an
# email send" category as FORGOT_PASSWORD_RATE_LIMIT_PER_MINUTE and
# RESEND_VERIFICATION_RATE_LIMIT_PER_MINUTE, so it gets the same tighter
# 5/min limit rather than the 10/min OTP-check group's headroom.
REGISTER_RATE_LIMIT_PER_MINUTE = 5
# Named constant, extracted from the inline `timedelta(minutes=10)` literal
# that used to sit directly at the /forgot-password call site (design notes
# section 1.2's flagged, non-blocking cleanup) -- makes both purposes' TTLs
# equally discoverable here rather than one being named and one a magic
# number.
RESET_PASSWORD_OTP_TTL_MINUTES = 10

RESET_PASSWORD_PURPOSE = "reset_password"
GENERIC_OTP_SENT_MESSAGE = "If the email exists, an OTP has been sent."
GENERIC_OTP_INVALID_MESSAGE = "Invalid or expired OTP"

# OBJ-007 (obj-007-design-notes.md section 1, closes audit finding #6):
# returned identically by BOTH branches of POST /auth/register -- the new
# generic response replacing the old 201+UserResponse / 400 split. Same
# "if X, then Y" conditional-phrasing convention as GENERIC_OTP_SENT_MESSAGE.
GENERIC_REGISTRATION_MESSAGE = (
    "If this email is not already registered, we've sent you a "
    "verification code to complete your registration."
)
# OBJ-007 (design notes section 3): identical wording on BOTH branches'
# failure mode -- deliberately branch-agnostic ("a required email", not
# "the verification code" or "the notification"), matching openapi.yaml's
# /auth/register 503 example verbatim.
REGISTER_EMAIL_SEND_FAILED_MESSAGE = (
    "Registration could not be completed because a required email could "
    "not be sent. Please try again."
)

# OBJ-005 (obj-005-design-notes.md sections 1-2): email-verification reuses
# the same Verification table/OTP mechanism as password reset, under its
# own purpose value, TTL, rate limits, and generic messages -- see
# _check_and_consume_otp's `purpose`/`max_attempts`/`invalid_message`
# parameters below for how the two stay isolated.
EMAIL_VERIFICATION_PURPOSE = "email_verification"
EMAIL_VERIFICATION_OTP_TTL_MINUTES = 30
VERIFY_EMAIL_RATE_LIMIT_PER_MINUTE = 10
RESEND_VERIFICATION_RATE_LIMIT_PER_MINUTE = 5
EMAIL_VERIFICATION_RESEND_COOLDOWN_SECONDS = 60

GENERIC_EMAIL_VERIFICATION_INVALID_MESSAGE = "Invalid or expired verification code"
GENERIC_EMAIL_VERIFICATION_SENT_MESSAGE = (
    "If the email exists and is not yet verified, a verification code has been sent."
)
UNVERIFIED_EMAIL_MESSAGE = "Email not verified"


def _generate_otp() -> str:
    """CSPRNG-backed 6-digit OTP (audit finding #2: the old stdlib `random`
    module is not cryptographically secure)."""
    return "".join(secrets.choice(string.digits) for _ in range(6))


async def _check_and_consume_otp(
    db: AsyncSession,
    email: str,
    otp: str,
    ip: str,
    *,
    purpose: str = RESET_PASSWORD_PURPOSE,
    max_attempts: int = MAX_OTP_ATTEMPTS,
    invalid_message: str = GENERIC_OTP_INVALID_MESSAGE,
) -> Verification:
    """Validates `otp` against the live Verification row for `email`
    scoped to `purpose`, sharing ONE failed-attempt budget between the two
    endpoints of that same purpose (e.g. /verify-otp and /reset-password
    for `reset_password`; /verify-email for `email_verification` -- audit
    finding #2, generalized by OBJ-005 design notes section 1.1 so a
    failed attempt against one purpose can never decrement another
    purpose's budget for the same email: the `purpose` filter below is
    what enforces that isolation).

    - No live (unexpired) row for this (email, purpose) -> generic 400, no
      state change (only the corresponding "request a code" endpoint
      creates rows; nothing here should become a row-spam vector).
    - Live row, wrong code -> increments `attempts`; once it reaches
      `max_attempts` the row is invalidated (expires_at pulled to "now")
      so it stops matching future "live row" lookups too. Same generic 400
      either way -- lockout, expiry, and wrong-code are indistinguishable
      by design (no new oracle). Every wrong guess emits
      `auth.otp.failed_attempt`; reaching the lockout threshold additionally
      emits `auth.otp.lockout` at WARNING (OBJ-004 finding #10, design
      notes section 4.2 -- both attempt tracking and lockout are genuine
      audit-worthy events).
    - Live row, correct code -> returned to the caller to finish the
      business flow (verify-otp just reports success; reset-password/
      verify-email also delete it after use).
    """
    generic_error = HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=invalid_message)

    result = await db.execute(
        select(Verification).filter(
            Verification.email == email,
            Verification.purpose == purpose,
            Verification.expires_at > datetime.now(timezone.utc),
        )
    )
    verification = result.scalars().first()

    if verification is None:
        raise generic_error

    if not security.verify_otp_hash(otp, verification.code):
        verification.attempts += 1
        audit_log.log_auth_event(
            "auth.otp.failed_attempt",
            email=email,
            ip=ip,
            purpose=purpose,
            attempts=verification.attempts,
        )
        if verification.attempts >= max_attempts:
            verification.expires_at = datetime.now(timezone.utc)
            audit_log.log_auth_event(
                "auth.otp.lockout",
                level=logging.WARNING,
                email=email,
                ip=ip,
                purpose=purpose,
            )
        await db.commit()
        raise generic_error

    return verification


async def _issue_tokens_and_session(
    db: AsyncSession, user: User, family_id: uuid.UUID, jti: uuid.UUID
) -> dict:
    """Mints one access+refresh token pair and persists the backing
    `refresh_sessions` row (OBJ-002, design notes section 1-2). Shared by
    `/auth/login` (fresh family: family_id == jti) and `/auth/refresh`
    (rotation: family_id carried over from the row being superseded, jti
    freshly generated by the caller so it can also stamp the old row's
    `replaced_by`). Does not commit -- the caller controls the transaction
    boundary (login: nothing else to persist; refresh: also revokes the
    superseded row in the same commit).
    """
    issued_at = datetime.now(timezone.utc)
    expires_at = issued_at + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)

    db.add(
        RefreshSession(
            id=jti,
            family_id=family_id,
            user_id=user.id,
            issued_at=issued_at,
            expires_at=expires_at,
        )
    )

    access_token = security.create_access_token(user.email, ver=user.token_version)
    refresh_token_str = security.create_refresh_token(
        user.email,
        ver=user.token_version,
        jti=jti,
        expires_delta=expires_at - issued_at,
    )
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "refresh_token": refresh_token_str,
    }


async def _revoke_active_sessions(db: AsyncSession, *filters: Any, now: datetime) -> None:
    """Sets `revoked_at` on every still-active (`revoked_at IS NULL`)
    `refresh_sessions` row matching `filters` -- the shared shape behind
    OBJ-002's three revocation call sites (logout: one row by `id`; reuse
    detection: a whole family by `family_id`; password reset: every row for
    a `user_id`). Does not commit -- caller controls the transaction.
    """
    await db.execute(
        update(RefreshSession)
        .where(RefreshSession.revoked_at.is_(None), *filters)
        .values(revoked_at=now)
    )


@router.get("/me", response_model=UserResponse)
async def read_current_user(
    current_user: User = Depends(deps.get_current_active_user),
) -> Any:
    return current_user


@router.post("/register")
async def register(
    http_request: Request,
    user_in: UserCreate,
    db: AsyncSession = Depends(deps.get_db),
    email_sender: EmailSender = Depends(deps.get_email_sender),
) -> Any:
    """OBJ-005 (design notes section 2.3, Gate 1 decision 3): registration
    generates an `email_verification` code and sends it via the injected
    EmailSender. If the send fails, the ENTIRE registration is rolled back
    (no User row, no Verification row survive) and the endpoint returns
    503 -- the user has no other path to receive the code, so a
    half-created, unverifiable account must never exist.

    OBJ-007 (design notes, closes audit finding #6): the response is now
    IDENTICAL -- same 200 status, same generic MessageResponse body -- for
    both a new email and an already-registered one (see
    GENERIC_REGISTRATION_MESSAGE above). The duplicate-email branch below
    (`_handle_duplicate_email_registration`) creates zero new rows, pays
    the same bcrypt-hash cost as the new-account branch (timing parity per
    design notes section 3), and sends a different notification email
    through the same EmailSender -- whose own send failure now also 503s,
    symmetrically with the new-account branch. Audit logging is exempt
    from this parity requirement (design notes section 2): outcome still
    distinguishes success/duplicate internally.

    OBJ-009 (obj-009-design-notes.md section 2, closes audit finding #16):
    `enforce_rate_limit` is called exactly ONCE, here, before the
    new-vs-duplicate-email branch decision even happens -- never
    duplicated per-branch, never keyed by a branch-specific scope. This is
    the load-bearing placement: OBJ-007's entire deliverable was making
    the two branches indistinguishable from the outside, so throttling
    them asymmetrically (or independently) would reopen finding #6 as a
    NEW timing/observability side channel. A single shared call site, one
    scope, before either branch has any information that could differ,
    makes that class of bug structurally unreachable rather than merely
    untested.
    """
    ip = rate_limit.client_ip(http_request)
    await rate_limit.enforce_rate_limit(
        db,
        scope="register",
        ip=ip,
        email=user_in.email,
        limit=REGISTER_RATE_LIMIT_PER_MINUTE,
    )

    result = await db.execute(select(User).filter(User.email == user_in.email))
    user = result.scalars().first()

    if user:
        return await _handle_duplicate_email_registration(user_in, ip, email_sender)
    return await _handle_new_email_registration(db, user_in, ip, email_sender)


async def _handle_new_email_registration(
    db: AsyncSession, user_in: UserCreate, ip: str, email_sender: EmailSender
) -> Any:
    user = User(
        email=user_in.email,
        hashed_password=security.get_password_hash(user_in.password),
        is_active=True,
        is_verified=False
    )
    db.add(user)
    await db.flush()  # assigns user.id -- needed before the Verification row, no commit yet

    otp = _generate_otp()
    verification = Verification(
        email=user.email,
        code=security.hash_otp(otp),
        purpose=EMAIL_VERIFICATION_PURPOSE,
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=EMAIL_VERIFICATION_OTP_TTL_MINUTES),
    )
    db.add(verification)
    await db.flush()

    subject, body = render_verification_email(otp)
    try:
        await email_sender.send(to=user.email, subject=subject, body=body)
    except EmailSendError:
        await db.rollback()  # undoes BOTH the User and the Verification insert -- same transaction
        audit_log.log_auth_event(
            "auth.register", email=user_in.email, ip=ip, outcome="email_send_failed"
        )
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=REGISTER_EMAIL_SEND_FAILED_MESSAGE,
        )

    await db.commit()
    audit_log.log_auth_event("auth.register", email=user_in.email, ip=ip, outcome="success")
    return {"msg": GENERIC_REGISTRATION_MESSAGE}


async def _handle_duplicate_email_registration(
    user_in: UserCreate, ip: str, email_sender: EmailSender
) -> Any:
    # OBJ-007 design notes section 3: pay the same bcrypt-HASH cost the
    # new-account branch pays (security.get_password_hash, not
    # verify_password_or_dummy -- that's a verify, a different operation,
    # not guaranteed to cost the same). Result is discarded; the call
    # exists purely for its constant-cost side effect. No User/Verification
    # row is created here (design notes section 2).
    security.get_password_hash(user_in.password)

    subject, body = render_already_registered_email()
    try:
        await email_sender.send(to=user_in.email, subject=subject, body=body)
    except EmailSendError:
        audit_log.log_auth_event(
            "auth.register", email=user_in.email, ip=ip, outcome="email_send_failed"
        )
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=REGISTER_EMAIL_SEND_FAILED_MESSAGE,
        )

    audit_log.log_auth_event("auth.register", email=user_in.email, ip=ip, outcome="duplicate")
    return {"msg": GENERIC_REGISTRATION_MESSAGE}


@router.post("/login", response_model=Token)
async def login(
    http_request: Request,
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: AsyncSession = Depends(deps.get_db)
) -> Any:
    ip = rate_limit.client_ip(http_request)
    result = await db.execute(select(User).filter(User.email == form_data.username))
    user = result.scalars().first()

    # OBJ-003 finding #5 (obj-003-design-notes.md section 3.1): always call
    # verify_password_or_dummy, regardless of whether `user` exists -- a
    # nonexistent email must not let this branch short-circuit past the
    # bcrypt call (the dominant, most exploitable timing signal). Status
    # code/message/is_active-check position are unchanged; this is purely a
    # reordering so the bcrypt call always happens first.
    credentials_valid = security.verify_password_or_dummy(
        form_data.password, user.hashed_password if user is not None else None
    )
    if not credentials_valid:
        audit_log.log_auth_event(
            "auth.login.failure", email=form_data.username, ip=ip, reason="invalid_credentials"
        )
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Incorrect email or password")

    if not user.is_active:
        audit_log.log_auth_event(
            "auth.login.failure", email=form_data.username, ip=ip, reason="inactive_user"
        )
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Inactive user")

    # OBJ-005 (design notes section 3.2): distinguishable 400, extending
    # the is_active check above by one predicate -- same accepted "business
    # -state error, distinct from credential validation" category, not a
    # new class of oracle. Positioned AFTER verify_password_or_dummy (finding
    # #5's structural bcrypt-always guarantee), so bcrypt still runs exactly
    # once per request regardless of account state.
    if not user.is_verified:
        audit_log.log_auth_event(
            "auth.login.failure", email=form_data.username, ip=ip, reason="unverified_email"
        )
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=UNVERIFIED_EMAIL_MESSAGE)

    new_family_id = uuid.uuid4()
    tokens = await _issue_tokens_and_session(db, user, family_id=new_family_id, jti=new_family_id)
    await db.commit()
    audit_log.log_auth_event("auth.login.success", email=user.email, ip=ip, user_id=str(user.id))
    return tokens


@router.post("/forgot-password")
async def forgot_password(
    http_request: Request,
    payload: EmailRequest,
    db: AsyncSession = Depends(deps.get_db),
    email_sender: EmailSender = Depends(deps.get_email_sender),
) -> Any:
    ip = rate_limit.client_ip(http_request)
    await rate_limit.enforce_rate_limit(
        db,
        scope="forgot_password",
        ip=ip,
        email=payload.email,
        limit=FORGOT_PASSWORD_RATE_LIMIT_PER_MINUTE,
    )

    result = await db.execute(select(User).filter(User.email == payload.email))
    user = result.scalars().first()

    # OBJ-003 finding #5 (obj-003-design-notes.md section 3.2, Gate 1
    # APPROVED Option A, 2026-08-23): unconditional bcrypt-dummy tax on
    # EVERY call, found or not -- this endpoint never actually checks a
    # password, so the target is always DUMMY_PASSWORD_HASH; the call exists
    # purely for its constant-cost side effect, closing the found/not-found
    # query-count asymmetry with the same mechanism /login uses.
    security.verify_password_or_dummy(payload.email, None)

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
        code=security.hash_otp(otp),
        purpose=RESET_PASSWORD_PURPOSE,
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=RESET_PASSWORD_OTP_TTL_MINUTES)
    )
    db.add(verification)
    await db.commit()

    # OBJ-004 finding #10, part 2 (obj-004-design-notes.md section 5): the
    # debug print is gone -- a non-secret-leaking audit-log line (email/ip/
    # purpose only, never the raw OTP) is logged before the send attempt.
    audit_log.log_auth_event(
        "auth.otp.requested",
        email=payload.email,
        ip=ip,
        purpose=RESET_PASSWORD_PURPOSE,
    )

    # Migrated from the interim `notifications.send_otp_notification` no-op
    # seam (OBJ-004) onto the `EmailSender` abstraction (OBJ-005 design notes
    # section 4.1 -- the Gate-1-approved end state was always exactly one
    # delivery mechanism, not two coexisting ones; audit-report.md finding
    # "notifications.py/EmailSender coexisting" flagged this migration as
    # outstanding). Mirrors /resend-verification-email's error handling
    # exactly: a send failure does NOT get /register's "roll back and fail
    # loudly" treatment -- the Verification row above is already committed,
    # and this endpoint's anti-enumeration contract already tolerates a "we
    # said we sent it" trust model. Still the same generic 200 either way.
    subject, body = render_password_reset_email(otp)
    try:
        await email_sender.send(to=payload.email, subject=subject, body=body)
    except EmailSendError:
        pass

    return {"msg": GENERIC_OTP_SENT_MESSAGE}


@router.post("/verify-otp")
async def verify_otp(
    http_request: Request,
    payload: OTPVerifyRequest,
    db: AsyncSession = Depends(deps.get_db)
) -> Any:
    ip = rate_limit.client_ip(http_request)
    await rate_limit.enforce_rate_limit(
        db,
        scope="verify_otp",
        ip=ip,
        email=payload.email,
        limit=VERIFY_OTP_RATE_LIMIT_PER_MINUTE,
    )

    await _check_and_consume_otp(db, payload.email, payload.otp, ip)

    return {"msg": "OTP verified successfully"}


@router.post("/verify-email", response_model=UserResponse)
async def verify_email(
    http_request: Request,
    payload: OTPVerifyRequest,
    db: AsyncSession = Depends(deps.get_db),
) -> Any:
    """OBJ-005 Story 1 (design notes section 2.1). Reuses OTPVerifyRequest
    (same shape as /verify-otp) and _check_and_consume_otp, scoped to
    purpose=email_verification -- its own shared-attempts budget, own TTL,
    own generic error message (deliberately distinct from /verify-otp's,
    per design notes section 2.1: no cross-endpoint oracle since the two
    purposes never share a response).

    On success: sets User.is_verified=True and DELETES the Verification
    row (consume-and-delete, matching /reset-password's pattern, not
    /verify-otp's check-without-consuming pattern) -- a replayed code then
    falls into the ordinary "no live row" generic-400 branch, no special
    -casing needed (Scenario 1.5). No tokens are issued (no auto-login);
    the client calls /auth/login normally afterward.
    """
    ip = rate_limit.client_ip(http_request)
    await rate_limit.enforce_rate_limit(
        db,
        scope="verify_email",
        ip=ip,
        email=payload.email,
        limit=VERIFY_EMAIL_RATE_LIMIT_PER_MINUTE,
    )

    verification = await _check_and_consume_otp(
        db,
        payload.email,
        payload.otp,
        ip,
        purpose=EMAIL_VERIFICATION_PURPOSE,
        invalid_message=GENERIC_EMAIL_VERIFICATION_INVALID_MESSAGE,
    )

    result = await db.execute(select(User).filter(User.email == payload.email))
    user = result.scalars().first()
    if not user:
        # Unreachable in practice (a live email_verification row implies a
        # User row was created alongside it, atomically, by /register) --
        # same generic message as any other invalid code, no new oracle.
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=GENERIC_EMAIL_VERIFICATION_INVALID_MESSAGE
        )

    user.is_verified = True
    await db.delete(verification)
    await db.commit()
    await db.refresh(user)
    audit_log.log_auth_event("auth.email_verified", email=user.email, ip=ip, user_id=str(user.id))
    return user


@router.post("/resend-verification-email")
async def resend_verification_email(
    http_request: Request,
    payload: EmailRequest,
    db: AsyncSession = Depends(deps.get_db),
    email_sender: EmailSender = Depends(deps.get_email_sender),
) -> Any:
    """OBJ-005 Story 1 (design notes section 2.2). Mirrors /forgot-password
    almost line for line: unauthenticated, always the same generic 200
    (anti-enumeration -- never reveals whether the email exists), per
    -email rate limiting, resend cooldown that preserves rather than
    rotates a still-fresh code.

    One addition /forgot-password doesn't need: an already-verified user's
    resend is a silent no-op (no new row, no email attempt) -- both an
    anti-oracle property and avoids spamming an already-verified inbox.
    """
    ip = rate_limit.client_ip(http_request)
    await rate_limit.enforce_rate_limit(
        db,
        scope="resend_verification_email",
        ip=ip,
        email=payload.email,
        limit=RESEND_VERIFICATION_RATE_LIMIT_PER_MINUTE,
    )

    result = await db.execute(select(User).filter(User.email == payload.email))
    user = result.scalars().first()

    # Gate 3 security finding (audit-report.md, "Gate 3 -- Verificacion
    # OBJ-005", "[NUEVO - MEDIO] /auth/resend-verification-email sin la
    # mitigacion de timing de finding #5"): mirrors /forgot-password's
    # unconditional bcrypt-dummy tax exactly -- called BEFORE either early
    # return below, so response cost can't be used to distinguish "email
    # doesn't exist" / "email exists and already verified" (both take the
    # fast path) from "email exists and unverified" (the slow path with
    # extra queries/writes/email send). This endpoint never checks a real
    # password, so the target is always DUMMY_PASSWORD_HASH, same as
    # /forgot-password.
    security.verify_password_or_dummy(payload.email, None)

    if not user or user.is_verified:
        return {"msg": GENERIC_EMAIL_VERIFICATION_SENT_MESSAGE}

    # Resend cooldown (mirrors /forgot-password's identical block): a row
    # created within the last EMAIL_VERIFICATION_RESEND_COOLDOWN_SECONDS is
    # left alone, whether still usable or already locked out -- stops an
    # attacker who just burned their attempt budget from immediately
    # resetting it via a resend. Same generic 200 either way.
    existing_result = await db.execute(
        select(Verification)
        .filter(
            Verification.email == payload.email,
            Verification.purpose == EMAIL_VERIFICATION_PURPOSE,
        )
        .order_by(Verification.created_at.desc())
    )
    existing = existing_result.scalars().first()
    if existing is not None:
        cooldown_cutoff = datetime.now(timezone.utc) - timedelta(
            seconds=EMAIL_VERIFICATION_RESEND_COOLDOWN_SECONDS
        )
        if existing.created_at is not None and existing.created_at > cooldown_cutoff:
            return {"msg": GENERIC_EMAIL_VERIFICATION_SENT_MESSAGE}

    # Rotate: invalidate any previous email-verification codes for this
    # email and issue a fresh one.
    await db.execute(
        delete(Verification).where(
            Verification.email == payload.email,
            Verification.purpose == EMAIL_VERIFICATION_PURPOSE,
        )
    )

    otp = _generate_otp()
    verification = Verification(
        email=payload.email,
        code=security.hash_otp(otp),
        purpose=EMAIL_VERIFICATION_PURPOSE,
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=EMAIL_VERIFICATION_OTP_TTL_MINUTES),
    )
    db.add(verification)
    await db.commit()

    audit_log.log_auth_event(
        "auth.email_verification.resend_requested",
        email=payload.email,
        ip=ip,
        purpose=EMAIL_VERIFICATION_PURPOSE,
    )

    # A resend's send failure does NOT get /register's "roll back and fail
    # loudly" treatment (design notes section 2.2 step 6) -- there is no
    # create-then-orphan risk here (the User row and the freshly-rotated
    # Verification row both already exist regardless of send outcome), and
    # /forgot-password's own anti-enumeration contract already tolerates
    # this same "we said we sent it" trust model. Still the same generic
    # 200 either way.
    subject, body = render_verification_email(otp)
    try:
        await email_sender.send(to=payload.email, subject=subject, body=body)
    except EmailSendError:
        pass

    return {"msg": GENERIC_EMAIL_VERIFICATION_SENT_MESSAGE}


@router.post("/reset-password")
async def reset_password(
    http_request: Request,
    payload: PasswordResetRequest,
    db: AsyncSession = Depends(deps.get_db)
) -> Any:
    ip = rate_limit.client_ip(http_request)
    await rate_limit.enforce_rate_limit(
        db,
        scope="reset_password",
        ip=ip,
        email=payload.email,
        limit=RESET_PASSWORD_RATE_LIMIT_PER_MINUTE,
    )

    verification = await _check_and_consume_otp(db, payload.email, payload.otp, ip)

    result_user = await db.execute(select(User).filter(User.email == payload.email))
    user = result_user.scalars().first()

    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    user.hashed_password = security.get_password_hash(payload.new_password)
    # OBJ-002 (design notes section 3, Gate 1 MANDATORY): bump token_version
    # (invalidates every access token, and every refresh token via the `ver`
    # check in /auth/refresh) AND bulk-revoke every still-live
    # refresh_sessions row for this user, in the same transaction -- defense
    # in depth, not relying on `ver` alone to be the only line of defense.
    user.token_version += 1
    await _revoke_active_sessions(
        db, RefreshSession.user_id == user.id, now=datetime.now(timezone.utc)
    )
    await db.delete(verification)
    await db.commit()
    audit_log.log_auth_event("auth.password_reset.success", email=user.email, ip=ip, user_id=str(user.id))

    return {"msg": "Password updated successfully"}


def _parse_jti(raw_jti: Optional[str]) -> Optional[uuid.UUID]:
    """Best-effort UUID parse -- a forged/garbage `jti` claim must fall
    through to 'no matching row', not crash the request (design notes
    section 2: 'covers forged/garbage jti')."""
    if raw_jti is None:
        return None
    try:
        return uuid.UUID(str(raw_jti))
    except (ValueError, AttributeError, TypeError):
        return None


@router.post("/refresh", response_model=Token)
async def refresh_token(
    http_request: Request,
    refresh_token: str = Body(..., embed=True),
    db: AsyncSession = Depends(deps.get_db)
) -> Any:
    """OBJ-002 rotation + reuse detection (design notes section 2). Every
    failure branch below raises the SAME generic 401 -- no oracle over
    which specific case (no row / reuse / expired / ver-mismatch) was hit.

    OBJ-004 finding #10 (design notes section 4.2): every branch emits a
    structured audit event -- `auth.refresh.failure` (ip, reason) for the
    four rejection paths, `auth.refresh.reuse_detected` at WARNING
    (possible token theft) for replay of an already-rotated token, and
    `auth.refresh.success` on a clean rotation.
    """
    ip = rate_limit.client_ip(http_request)
    invalid_token_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired refresh token",
    )

    payload = security.decode_refresh_token_claims(refresh_token)
    email = payload["sub"]
    jti = _parse_jti(payload.get("jti"))

    session_row = None
    if jti is not None:
        result = await db.execute(select(RefreshSession).filter(RefreshSession.id == jti))
        session_row = result.scalars().first()

    if session_row is None:
        # Covers: forged/garbage jti, a purged row, AND every pre-OBJ-002
        # legacy token (no jti claim at all).
        audit_log.log_auth_event("auth.refresh.failure", ip=ip, reason="no_session")
        raise invalid_token_exception

    now = datetime.now(timezone.utc)

    if session_row.revoked_at is not None:
        # Reuse of an already-rotated token -- revoke the ENTIRE family,
        # not just this row (design notes section 2's core rationale).
        await _revoke_active_sessions(
            db, RefreshSession.family_id == session_row.family_id, now=now
        )
        await db.commit()
        audit_log.log_auth_event(
            "auth.refresh.reuse_detected",
            level=logging.WARNING,
            user_id=str(session_row.user_id),
            family_id=str(session_row.family_id),
            jti=str(session_row.id),
        )
        raise invalid_token_exception

    if session_row.expires_at < now:
        # Ordinary expiry -- NOT treated as reuse, no family action.
        audit_log.log_auth_event("auth.refresh.failure", ip=ip, reason="expired")
        raise invalid_token_exception

    result_user = await db.execute(select(User).filter(User.email == email))
    user = result_user.scalars().first()
    if not user or not user.is_active:
        audit_log.log_auth_event("auth.refresh.failure", ip=ip, reason="user_inactive")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="User inactive or not found")

    # OBJ-005 (design notes section 3.2): same predicate, same status
    # family as /login's check above -- piggybacks on the User row already
    # loaded, no extra query. Runs fresh against the DB on every refresh,
    # never baked into a JWT claim (Scenario 2.A.3's "auditing gate, not
    # re-verification" framing).
    if not user.is_verified:
        audit_log.log_auth_event("auth.refresh.failure", ip=ip, reason="unverified_email")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=UNVERIFIED_EMAIL_MESSAGE)

    if payload.get("ver") != user.token_version:
        # Password-reset invalidation (design notes section 3).
        audit_log.log_auth_event("auth.refresh.failure", ip=ip, reason="ver_mismatch")
        raise invalid_token_exception

    new_jti = uuid.uuid4()

    # OBJ-010 (docs/database/obj-006-migration-plan.md "CRITICAL finding" +
    # section 5): revoke the OLD row first, atomically, before inserting its
    # replacement -- revoke -> insert -> link, not insert -> revoke. Two
    # problems fixed by this single reorder, both on this same code path:
    #
    #   1. Migration 0008 adds a partial unique index on
    #      refresh_sessions(family_id) WHERE revoked_at IS NULL. The old
    #      insert-then-revoke order briefly had TWO active rows in the same
    #      family visible within the transaction, which that index forbids --
    #      every rotation raised a duplicate-key IntegrityError once 0008
    #      was applied. Revoking first means at most one active row per
    #      family ever exists.
    #   2. The `WHERE revoked_at IS NULL` predicate is repeated on this
    #      UPDATE (not just relied on from the SELECT above), making it an
    #      atomic compare-and-set instead of a blind write. If a concurrent
    #      request already revoked this exact row (its own rotation, or a
    #      reuse-detection sweep on the family) between our SELECT and this
    #      UPDATE, rowcount is 0 and we fail closed -- rejecting this refresh
    #      -- instead of silently overwriting revoked_at as if we'd won the
    #      race. Closes the TOCTOU gap flagged in the same design-doc
    #      section.
    revoke_result = await db.execute(
        update(RefreshSession)
        .where(RefreshSession.id == jti, RefreshSession.revoked_at.is_(None))
        .values(revoked_at=now)
    )
    if revoke_result.rowcount != 1:
        await db.rollback()
        audit_log.log_auth_event(
            "auth.refresh.failure", ip=ip, reason="concurrent_rotation"
        )
        raise invalid_token_exception

    tokens = await _issue_tokens_and_session(
        db, user, family_id=session_row.family_id, jti=new_jti
    )
    # Flush the INSERT of the new row before pointing the old row's
    # replaced_by FK at it -- the FK still requires the new row to exist
    # first, so this remains a 3-statement sequence (revoke, insert, link)
    # rather than 2.
    await db.flush()
    await db.execute(
        update(RefreshSession)
        .where(RefreshSession.id == jti)
        .values(replaced_by=new_jti)
    )
    await db.commit()
    audit_log.log_auth_event(
        "auth.refresh.success",
        user_id=str(user.id),
        family_id=str(session_row.family_id),
        old_jti=str(jti),
        new_jti=str(new_jti),
    )
    return tokens


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(
    http_request: Request,
    refresh_token: str = Body(..., embed=True),
    db: AsyncSession = Depends(deps.get_db),
) -> None:
    """OBJ-002 (design notes section 4): always 204 for any well-formed
    request body -- no validity oracle. Revokes exactly the one
    `refresh_sessions` row matching the submitted token's `jti`, if any. An
    invalid signature, expired token, malformed string, or a well-formed
    token of the wrong type (access tokens never carry a `jti`) all fall
    through to a silent no-op: the caller's desired end state (this session
    unusable) already holds in every one of those cases. A request body
    missing the `refresh_token` field entirely is the one case that's a
    genuine schema failure (422), handled by FastAPI/Pydantic before this
    function ever runs.

    OBJ-004 finding #10 (design notes section 4.2): emits `auth.logout`
    with `jti` (nullable -- the no-op branch logs jti=null, never
    fabricates a value) and `ip`.
    """
    # OBJ-003 (obj-003-design-notes.md section 3.3, OBJ-002 Gate 3 SAST
    # fold-in): the jti-is-None branch performs an equivalent-shaped no-op
    # DB round trip instead of returning immediately, and commit() moves
    # outside the `if` so it runs unconditionally in both branches -- this
    # is what makes the two paths structurally identical (one db.execute
    # call, one db.commit call, either way), closing the "is this a
    # validly-signed JWT" timing signal.
    jti = _parse_jti(security.extract_jti_if_present(refresh_token))
    if jti is not None:
        await _revoke_active_sessions(
            db, RefreshSession.id == jti, now=datetime.now(timezone.utc)
        )
    else:
        await db.execute(select(1))
    await db.commit()
    audit_log.log_auth_event(
        "auth.logout",
        jti=str(jti) if jti is not None else None,
        ip=rate_limit.client_ip(http_request),
    )
    return None
