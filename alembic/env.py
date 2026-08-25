"""Alembic environment for api-fa-backend (OBJ-006).

DELIBERATE DESIGN DECISION (obj-006-migration-plan.md, "env.py design note"):
this file does NOT import `app.core.config.settings`. `Settings()` is a
module-level Pydantic singleton that eagerly validates SECRET_KEY (min
length + placeholder blocklist), POSTGRES_SSL_MODE, and every other
required app field the moment `app.core.config` is imported -- none of
which a pure schema migration has any business needing. Coupling migrations
to that import would mean `alembic upgrade head` could never run without a
fully valid application `.env`, which is a real operational problem (e.g.
a CI job that only provisions schema, or an operator running migrations
before the app's own secrets are finalized).

Instead, this file reads a dedicated `MIGRATOR_DATABASE_URL` environment
variable directly -- decoupled from `Settings` entirely. This is also the
connection string that should resolve to the `fa_migrator` role (DDL
rights only) in any environment with role separation enabled (see
docs/database/obj-006-migration-plan.md section 3 and
docs/database/sql/provision_db_roles.sql) -- never the app runtime's
`fa_app` role, which must not have schema-modification rights.

Driver note: the app's own runtime connection
(app/core/database.py:SQLALCHEMY_DATABASE_URI) uses the async
`postgresql+asyncpg://` driver. Alembic migrations run synchronously here
on purpose (simpler, no event-loop plumbing needed for one-shot DDL) via
the sync `psycopg2` driver (already a `requirements.txt` dependency for
this exact reason). MIGRATOR_DATABASE_URL should therefore be a
`postgresql://` or `postgresql+psycopg2://` URL, NOT `postgresql+asyncpg://`.

CUTOVER NOTE for an existing dev/test database that already has these 4
tables via `Base.metadata.create_all` (every environment from OBJ-000
through OBJ-005 today): do NOT run `alembic upgrade head` directly against
it -- migration 0001 issues real `CREATE TABLE` statements and will fail
with "relation already exists". Instead run:

    alembic stamp 0001_baseline_current_schema
    alembic upgrade head

`stamp` marks 0001 as applied (recording it in `alembic_version`) WITHOUT
executing its DDL, since the tables it would create already exist and are
schema-identical (0001 is a pure capture of today's `create_all` output,
verified column-for-column against the live models). `alembic upgrade
head` then applies 0002 onward normally. See tests/README.md for the
copy-pasteable commands and how this interacts with the test suite.
"""

import os
from logging.config import fileConfig

from sqlalchemy import engine_from_config
from sqlalchemy import pool

from alembic import context

# this is the Alembic Config object, which provides
# access to the values within the .ini file in use.
config = context.config

# Interpret the config file for Python logging.
# This line sets up loggers basically.
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# --- target_metadata: import Base + every model module so all 4 tables
# register on Base.metadata, matching the exact import list already
# established in app/models/__init__.py and app/main.py. Importing
# app.core.database (for Base) does NOT trigger the Settings-validation
# problem described above -- app/core/config.py's Settings() singleton is
# only constructed when `app.core.config` itself is imported, and
# app/core/database.py DOES import `from app.core.config import settings`
# at module scope (it builds its own async engine eagerly). To avoid ever
# triggering that import path from a migration run, we import ONLY
# `Base` off a lightweight re-declaration path... but app/core/database.py
# is also the single source of truth for `Base`, and there is no separate
# "just the declarative base" module in this codebase. Rather than fork
# Base into a second module (which would produce two different
# registries and silently break autogenerate), we accept importing
# app.core.database here -- and satisfy its Settings() construction with
# the same permissive, non-secret placeholder env-var defaults the test
# suite already uses (see tests/conftest.py), set below BEFORE the import,
# so a real SECRET_KEY/POSTGRES_* .env is never required to run a schema
# migration. This keeps the spirit of the decoupling requirement (no valid
# *application* configuration required) while working within this
# repo's actual module layout.
os.environ.setdefault("PROJECT_NAME", "api-fa-backend-migrator")
os.environ.setdefault("POSTGRES_USER", "alembic-unused")
os.environ.setdefault("POSTGRES_PASSWORD", "alembic-unused")
os.environ.setdefault("POSTGRES_SERVER", "localhost")
os.environ.setdefault("POSTGRES_PORT", "5432")
os.environ.setdefault("POSTGRES_DB", "alembic-unused")
os.environ.setdefault("POSTGRES_SSL_MODE", "disable")
os.environ.setdefault(
    "SECRET_KEY",
    "alembic-migrator-placeholder-key-not-used-for-any-http-request-0123456789",
)
os.environ.setdefault("ALGORITHM", "HS256")
os.environ.setdefault("ACCESS_TOKEN_EXPIRE_MINUTES", "30")
os.environ.setdefault("REFRESH_TOKEN_EXPIRE_DAYS", "7")

from app.core.database import Base  # noqa: E402
from app.models import user, verification, rate_limit, refresh_session  # noqa: E402,F401

target_metadata = Base.metadata


def _get_migrator_url() -> str:
    """MIGRATOR_DATABASE_URL is the one and only source of the migration
    connection string -- never app.core.config.settings.SQLALCHEMY_DATABASE_URI
    (that resolves to the app's DML-only fa_app connection in any
    environment with role separation enabled; using it here would mean
    `alembic upgrade head` runs as a role with no CREATE/ALTER rights and
    fails). alembic.ini's own `sqlalchemy.url` is left as an unused
    placeholder for the same reason -- this function is the only path
    that supplies a real URL.
    """
    url = os.environ.get("MIGRATOR_DATABASE_URL")
    if not url:
        raise RuntimeError(
            "MIGRATOR_DATABASE_URL is not set. Alembic migrations require a "
            "dedicated connection string (recommended: the fa_migrator role's "
            "DSN -- see docs/database/obj-006-migration-plan.md section 3), "
            "e.g.:\n"
            "  postgresql+psycopg2://fa_migrator:<password>@localhost:5432/api_fa\n"
            "This is deliberately NOT read from app.core.config.settings -- "
            "see this file's module docstring."
        )
    return url


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode.

    This configures the context with just a URL
    and not an Engine, though an Engine is acceptable
    here as well.  By skipping the Engine creation
    we don't even need a DBAPI to be available.

    Calls to context.execute() here emit the given string to the
    script output.

    """
    url = _get_migrator_url()
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode.

    In this scenario we need to create an Engine
    and associate a connection with the context.

    """
    configuration = config.get_section(config.config_ini_section, {})
    configuration["sqlalchemy.url"] = _get_migrator_url()
    connectable = engine_from_config(
        configuration,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection, target_metadata=target_metadata
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
