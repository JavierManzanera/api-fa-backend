from functools import lru_cache

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import jwt, JWTError
from pydantic import ValidationError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.core import security
from app.core.config import settings
from app.core.database import get_db
from app.core.email.base import EmailSender
from app.core.email.console import ConsoleEmailSender
from app.models.user import User
from app.schemas.user import TokenData

oauth2_scheme = OAuth2PasswordBearer(tokenUrl=f"{settings.API_V1_STR}/auth/login")


async def get_current_user(
    db: AsyncSession = Depends(get_db),
    token: str = Depends(oauth2_scheme)
) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        if payload.get("type") != security.TOKEN_TYPE_ACCESS:
            raise credentials_exception
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
        token_data = TokenData(email=email)
    except (JWTError, ValidationError):
        raise credentials_exception

    result = await db.execute(select(User).filter(User.email == token_data.email))
    user = result.scalars().first()
    if user is None:
        raise credentials_exception

    # OBJ-002 (design notes section 3): a missing `ver` claim (pre-OBJ-002
    # token) compares as None != <int>, so it fails closed the same as a
    # genuine mismatch -- no special-casing needed. Piggybacks on the User
    # row this function already had to load, no extra query.
    if payload.get("ver") != user.token_version:
        raise credentials_exception

    return user


async def get_current_active_user(
    current_user: User = Depends(get_current_user),
) -> User:
    if not current_user.is_active:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user


@lru_cache
def _email_sender_singleton() -> EmailSender:
    """Cached (singleton) EmailSender instance, selected by
    `Settings.EMAIL_PROVIDER` (design notes section 4.5). Only "console"
    ships an implementation in this template -- any other value fails
    loudly at first USE, not at import/startup, since a misconfigured email
    provider is an operational/delivery concern, not a security posture
    regression. A downstream fork wanting real SMTP/SendGrid/SES delivery
    implements one more `EmailSender` subclass and registers it here."""
    if settings.EMAIL_PROVIDER == "console":
        return ConsoleEmailSender()
    raise NotImplementedError(
        f"EMAIL_PROVIDER={settings.EMAIL_PROVIDER!r} has no implementation in this template. "
        "Implement an EmailSender subclass (app/core/email/base.py) and register it here -- "
        "SMTP/SendGrid/SES specifics are a deployment concern, out of scope for the template itself."
    )


def get_email_sender() -> EmailSender:
    return _email_sender_singleton()
