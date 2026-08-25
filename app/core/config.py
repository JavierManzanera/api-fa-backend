from typing import Annotated, List, Union
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict
from pydantic import AnyHttpUrl, PostgresDsn, computed_field, field_validator, model_validator
from functools import lru_cache

MIN_SECRET_KEY_LENGTH = 32

# OBJ-003 finding #8 (obj-003-design-notes.md section 2.1): the three
# asyncpg-translatable TLS postures. Lowercase-exact, no case-insensitive
# matching (unlike SECRET_KEY's placeholder blocklist) -- design notes
# section 2.1 does not specify one for this field.
_VALID_POSTGRES_SSL_MODES = {"disable", "require", "verify-full"}

# OBJ-004 finding #13 (obj-004-design-notes.md section 3): the three
# environments this template's docs-gating (and any future
# environment-aware behavior) branches on. Lowercase-exact, same
# case-sensitivity convention as _VALID_POSTGRES_SSL_MODES.
_VALID_ENVIRONMENTS = {"development", "staging", "production"}

# Security finding #15 (docs/security/audit-report.md, "Auditoria puntual --
# PYSEC-2026-1325 / python-ecdsa / ALGORITHM sin validar", 2026-08-25): only
# algorithm supported/tested by this codebase today. Deliberately widen (and
# only after confirming the state of PYSEC-2026-1325 and/or migrating to
# PyJWT) if a fork needs RS*/ES*.
_VALID_ALGORITHMS = {"HS256"}

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

    # OBJ-004 finding #13 (obj-004-design-notes.md section 3): required, no
    # default -- matching POSTGRES_SSL_MODE's "every environment must say
    # what it wants" convention. Gates /docs, /redoc, /openapi.json (section
    # 3) and is available for any future objective to branch on.
    ENVIRONMENT: str

    # OBJ-004 finding #9 (obj-004-design-notes.md section 1.1, Gate 1
    # APPROVED Option A): browser origins allowed to call this API
    # cross-origin. Empty-list default -- CORS closed until a fork opts in.
    # List[AnyHttpUrl] (not List[str]) is a deliberate type-level choice: it
    # cannot parse the literal string "*", closing audit finding #9's named
    # fear ("allow_origins=['*']") at validation time, not just by
    # convention. NoDecode opts this field out of pydantic-settings' default
    # "complex fields are JSON-decoded from the env var" behavior -- without
    # it, a comma-separated (non-JSON) env value raises a SettingsError
    # before assemble_cors_origins below ever gets a chance to parse it.
    BACKEND_CORS_ORIGINS: Annotated[List[AnyHttpUrl], NoDecode] = []

    # OBJ-004 finding #9 addendum (obj-004-design-notes.md section 1.5):
    # Host header allowlist for TrustedHostMiddleware. "*" preserves today's
    # existing (no host validation) behavior by default.
    ALLOWED_HOSTS: List[str] = ["*"]

    # OBJ-004 finding #10 (obj-004-design-notes.md section 4.4): stdlib
    # `logging` level for structured auth-event logs. A safe default --
    # misconfiguration only affects log verbosity, never security posture.
    LOG_LEVEL: str = "INFO"

    # OBJ-004 backlog item (obj-004-design-notes.md section 6.2, Gate 1
    # APPROVED Option A): how many trusted reverse proxies/load balancers
    # sit in front of this app. 0 (default) = do not trust
    # X-Forwarded-For at all -- the maximally safe default, and exactly
    # today's existing (unconfigured) behavior.
    TRUSTED_PROXY_COUNT: int = 0

    # OBJ-005 (obj-005-design-notes.md section 4.5): which EmailSender
    # implementation app.api.deps.get_email_sender() wires up. Safe default
    # ("console" -- always works, never fails) matching LOG_LEVEL's
    # convention, not POSTGRES_SSL_MODE/SECRET_KEY's fail-at-import
    # convention -- a bad value here is an operational/delivery concern,
    # not a security posture regression, so it fails at first USE (a
    # NotImplementedError from the factory) rather than at startup.
    EMAIL_PROVIDER: str = "console"
    EMAIL_FROM: str = "noreply@example.com"

    model_config = SettingsConfigDict(env_file=".env", case_sensitive=True)

    @field_validator("BACKEND_CORS_ORIGINS", mode="before")
    @classmethod
    def assemble_cors_origins(cls, value: Union[str, List[str]]):
        """Comma-separated env var -> list, same convention this FastAPI
        template family commonly uses (obj-004-design-notes.md section
        1.1). A value that's already a list (or a JSON-array string) is
        left alone for pydantic's own complex-type parsing to handle."""
        if isinstance(value, str) and not value.startswith("["):
            return [origin.strip() for origin in value.split(",") if origin.strip()]
        return value

    @field_validator("ENVIRONMENT")
    @classmethod
    def validate_environment(cls, value: str) -> str:
        if value not in _VALID_ENVIRONMENTS:
            raise ValueError(
                f"ENVIRONMENT must be one of {sorted(_VALID_ENVIRONMENTS)}, got {value!r}."
            )
        return value

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

    # Security finding #15 (docs/security/audit-report.md, "Auditoria
    # puntual -- PYSEC-2026-1325 / python-ecdsa / ALGORITHM sin validar"):
    # fail closed, same pattern as POSTGRES_SSL_MODE/ENVIRONMENT above.
    # Runtime exposure to PYSEC-2026-1325 (unfixed side-channel advisory in
    # the pure-Python `ecdsa` package, previously pulled in transitively by
    # `python-jose`) was confirmed zero even before OBJ-008 below -- this app
    # only ever used HS256 in practice -- but that was previously an
    # observed fact, not an enforced invariant. This validator makes it one.
    # OBJ-008 subsequently replaced `python-jose` with `PyJWT[crypto]`
    # (which never depends on `ecdsa` at all), removing the advisory from
    # the dependency tree entirely -- this validator is kept as defense in
    # depth, not because the dependency risk still exists.
    @field_validator("ALGORITHM")
    @classmethod
    def validate_algorithm(cls, value: str) -> str:
        if value not in _VALID_ALGORITHMS:
            raise ValueError(
                f"ALGORITHM must be one of {sorted(_VALID_ALGORITHMS)}, got "
                f"{value!r}. ES*/RS*/EdDSA algorithms are not currently "
                "supported by this template's validated configuration surface "
                "-- see audit-report.md finding #15 / OBJ-008 before enabling "
                "one."
            )
        return value

    # Gate 3 security finding (docs/security/audit-report.md, "Gate 3 --
    # Verificacion OBJ-005", "[NUEVO - MEDIO] EMAIL_PROVIDER por defecto
    # ('console') sin gate de entorno"): cross-field, so it must be a
    # model_validator (not a single-field field_validator like SECRET_KEY/
    # POSTGRES_SSL_MODE/ENVIRONMENT above) -- it needs to see both
    # ENVIRONMENT and EMAIL_PROVIDER at once. Fail-closed at startup,
    # matching this file's established convention for every other
    # security-adjacent field: ConsoleEmailSender logs the full email body
    # (always containing the OTP in plaintext by design) to stdout, which
    # would reintroduce finding #10's exposure class the moment this
    # template is deployed to production without an operator explicitly
    # choosing a real EmailSender provider.
    @model_validator(mode="after")
    def validate_email_provider_not_console_in_production(self) -> "Settings":
        if self.ENVIRONMENT == "production" and self.EMAIL_PROVIDER == "console":
            raise ValueError(
                "EMAIL_PROVIDER must not be 'console' when ENVIRONMENT is "
                "'production' -- ConsoleEmailSender logs OTP codes in "
                "plaintext to stdout, which reintroduces a closed security "
                "exposure (audit-report.md finding #10) in production. "
                "Configure a real EmailSender implementation and set "
                "EMAIL_PROVIDER accordingly."
            )
        return self

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
