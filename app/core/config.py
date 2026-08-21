from typing import List
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import AnyHttpUrl, PostgresDsn, computed_field, field_validator
from functools import lru_cache

MIN_SECRET_KEY_LENGTH = 32

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
