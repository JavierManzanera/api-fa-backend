import random
import string
from datetime import datetime, timedelta, timezone
from typing import Any
from fastapi import APIRouter, Depends, HTTPException, status, Body
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, delete

from app.api import deps
from app.core import security
from app.models.user import User
from app.models.verification import Verification
from app.schemas.user import UserCreate, UserResponse, Token, EmailRequest, OTPVerifyRequest, PasswordResetRequest

router = APIRouter()


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
    request: EmailRequest,
    db: AsyncSession = Depends(deps.get_db)
) -> Any:
    result = await db.execute(select(User).filter(User.email == request.email))
    user = result.scalars().first()
    if not user:
        return {"msg": "If the email exists, an OTP has been sent."}

    # Invalidate any previous OTPs for this email
    await db.execute(
        delete(Verification).where(
            Verification.email == request.email,
            Verification.purpose == "reset_password"
        )
    )

    otp = "".join(random.choices(string.digits, k=6))
    verification = Verification(
        email=request.email,
        code=otp,
        purpose="reset_password",
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=10)
    )
    db.add(verification)
    await db.commit()

    # MOCK EMAIL SENDER
    print(f"============================================")
    print(f" [EMAIL MOCK] To: {request.email} | OTP: {otp} ")
    print(f"============================================")

    return {"msg": "If the email exists, an OTP has been sent."}


@router.post("/verify-otp")
async def verify_otp(
    request: OTPVerifyRequest,
    db: AsyncSession = Depends(deps.get_db)
) -> Any:
    result = await db.execute(
        select(Verification)
        .filter(
            Verification.email == request.email,
            Verification.code == request.otp,
            Verification.purpose == "reset_password",
            Verification.expires_at > datetime.now(timezone.utc)
        )
    )
    verification = result.scalars().first()

    if not verification:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or expired OTP")

    return {"msg": "OTP verified successfully"}


@router.post("/reset-password")
async def reset_password(
    request: PasswordResetRequest,
    db: AsyncSession = Depends(deps.get_db)
) -> Any:
    result = await db.execute(
        select(Verification)
        .filter(
            Verification.email == request.email,
            Verification.code == request.otp,
            Verification.purpose == "reset_password",
            Verification.expires_at > datetime.now(timezone.utc)
        )
    )
    verification = result.scalars().first()

    if not verification:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or expired OTP")

    result_user = await db.execute(select(User).filter(User.email == request.email))
    user = result_user.scalars().first()

    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    user.hashed_password = security.get_password_hash(request.new_password)
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
