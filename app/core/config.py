from typing import List
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import AnyHttpUrl, PostgresDsn, computed_field, field_validator
from functools import lru_cache

MIN_SECRET_KEY_LENGTH = 32

# OBJ-003 finding #8 (obj-003-design-notes.md section 2.1): the three
# asyncpg-translatable TLS postures. Lowercase-exact, no case-insensitive
# matching (unlike SECRET_KEY's placeholder blocklist) -- design notes
# section 2.1 does not specify one for this field.
_VALID_POSTGRES_SSL_MODES = {"disable", "require", "verify-full"}

# Known-placeholder values that must never be used as a real SECRET_KEY,
# compared case-insensitively (obj-001-design-notes.md section 3).
_SECRET_KEY_BLOCKLIST = {
    "your_secret_key_here",
    "insert_secret_key_here",
    "secret",
    "changeme",
    "change_me",
    "",
}


class Settings(BaseSettings):
    PROJECT_NAME: str
    API_V1_STR: str = "/api/v1"
    
    POSTGRES_USER: str
    POSTGRES_PASSWORD: str
    POSTGRES_SERVER: str
    POSTGRES_PORT: int
    POSTGRES_DB: str
    # OBJ-003 finding #8 (obj-003-design-notes.md section 2.1): Gate 1
    # APPROVED Option A (2026-08-23) -- configurable with a safe-default-
    # free, operator-driven escape hatch, not hard-enforced like SECRET_KEY.
    # Required, no default, matching every other POSTGRES_* field's existing
    # convention -- every environment must say what it wants.
    POSTGRES_SSL_MODE: str

    SECRET_KEY: str
    ALGORITHM: str
    ACCESS_TOKEN_EXPIRE_MINUTES: int
    REFRESH_TOKEN_EXPIRE_DAYS: int

    model_config = SettingsConfigDict(env_file=".env", case_sensitive=True)

    @field_validator("SECRET_KEY")
    @classmethod
    def validate_secret_key_strength(cls, value: str) -> str:
        if len(value) < MIN_SECRET_KEY_LENGTH:
            raise ValueError(
                f"SECRET_KEY must be at least {MIN_SECRET_KEY_LENGTH} characters "
                "long. Generate one with secrets.token_urlsafe(64)."
            )
        if value.strip().lower() in _SECRET_KEY_BLOCKLIST:
            raise ValueError(
                "SECRET_KEY must not be a known placeholder value. Generate "
                "one with secrets.token_urlsafe(64)."
            )
        return value

    @field_validator("POSTGRES_SSL_MODE")
    @classmethod
    def validate_postgres_ssl_mode(cls, value: str) -> str:
        if value not in _VALID_POSTGRES_SSL_MODES:
            raise ValueError(
                f"POSTGRES_SSL_MODE must be one of "
                f"{sorted(_VALID_POSTGRES_SSL_MODES)}, got {value!r}."
            )
        return value

    @computed_field
    @property
    def SQLALCHEMY_DATABASE_URI(self) -> PostgresDsn:
        return PostgresDsn.build(
            scheme="postgresql+asyncpg",
            username=self.POSTGRES_USER,
            password=self.POSTGRES_PASSWORD,
            host=self.POSTGRES_SERVER,
            port=self.POSTGRES_PORT,
            path=self.POSTGRES_DB,
        )

@lru_cache
def get_settings():
    return Settings()

settings = get_settings()
