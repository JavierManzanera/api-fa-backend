from typing import Optional
from pydantic import BaseModel, EmailStr, UUID4, ConfigDict, Field, field_validator
from datetime import datetime


def validate_password_strength(value: str) -> str:
    errors = []
    if not any(c.isupper() for c in value):
        errors.append("al menos una letra mayúscula")
    if not any(c.isdigit() for c in value):
        errors.append("al menos un número")
    if not any(c in "!@#$%^&*()_+-=[]{}|;':\",./<>?" for c in value):
        errors.append("al menos un carácter especial (!@#$%^&*...)")
    if errors:
        raise ValueError("La contraseña debe contener: " + ", ".join(errors))
    return value


class UserBase(BaseModel):
    email: EmailStr


class UserCreate(UserBase):
    password: str = Field(min_length=8, max_length=128)

    @field_validator("password")
    @classmethod
    def password_strength(cls, v: str) -> str:
        return validate_password_strength(v)


class UserResponse(UserBase):
    id: UUID4
    is_active: bool
    is_verified: bool
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class Token(BaseModel):
    access_token: str
    token_type: str
    refresh_token: str


class TokenData(BaseModel):
    email: Optional[str] = None


class EmailRequest(BaseModel):
    email: EmailStr


class OTPVerifyRequest(BaseModel):
    email: EmailStr
    otp: str


class PasswordResetRequest(BaseModel):
    email: EmailStr
    otp: str
    new_password: str = Field(min_length=8, max_length=128)

    @field_validator("new_password")
    @classmethod
    def password_strength(cls, v: str) -> str:
        return validate_password_strength(v)
