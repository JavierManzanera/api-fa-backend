"""
Global pytest fixtures for api-fa-backend (OBJ-000 Test Infrastructure Bootstrap).

Order matters in this file: `app/core/config.py` builds a module-level
`Settings` singleton (`settings = get_settings()`) the moment it is imported,
and it currently has NO defaults for most fields. So every required env var
below MUST be set before the first `from app...`/`import app...` anywhere in
the test session -- including inside fixtures, factories, or test modules.
That is why the env-var block and the sys.path fix are the very first thing
in this file, ahead of even stdlib imports that might transitively pull in
`app.*` (none currently do, but keep the ordering defensive).

---------------------------------------------------------------------------
POSTGRES REQUIREMENT -- read this before "why did my test error instead of
fail":
---------------------------------------------------------------------------
`tests/api/**` needs a REAL PostgreSQL reachable at TEST_DATABASE_URL
(defaults to postgresql+asyncpg://test:test@localhost:5433/api_fa_test,
matching docker-compose.test.yml at the repo root). SQLite is deliberately
NOT used as a substitute: app/models/user.py and app/models/verification.py
use sqlalchemy.dialects.postgresql.UUID(as_uuid=True), a dialect-specific
type not guaranteed to behave identically on SQLite (test-gap-analysis.md
section 4 flags this explicitly).

`tests/unit/**` needs no database at all.

### KNOWN BLOCKER -- 2026-08-21 (qa-engineer, OBJ-000 red-phase pass)
This authoring environment has no Docker (`docker --version` -> command not
found). A local PostgreSQL 16 Windows service IS running on port 5432, but
this agent had no credentials for it, and two independent attempts to
obtain them (trying common default credentials; reading pg_hba.conf to
find the auth method) were both correctly blocked by the harness's own
safety classifier as credential-discovery behavior. Neither was worked
around -- that service was never touched.

Full suite verification still happened: a throwaway, self-provisioned
Postgres 16 instance was created instead, via `initdb`/`pg_ctl` from the
same already-installed binaries (own data directory outside the repo, port
5433, `trust` auth, torn down after use) -- functionally equivalent to
what `docker-compose.test.yml` sets up, just without Docker available to
run it. Against that instance, the full suite (`tests/unit` + `tests/api`)
ran to completion: 39 failed / 10 passed, every failure inspected and
confirmed to trace to a specific missing piece of OBJ-001, every pass
confirmed to document genuinely-already-correct current behavior. See
tests/README.md for the full breakdown and the risk notes for `developer`.
Do not silently skip: if TEST_DATABASE_URL is unreachable, `db_engine`
below fails LOUDLY (pytest.fail, not pytest.skip) with this same
explanation, for every test that depends on it.
"""

import os
import sys
from pathlib import Path

# --- 0. Make the `app` package importable regardless of pytest's rootdir/
#        import-mode quirks (explicit, not relying on auto-insertion). ---
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

# --- 1. Required Settings fields -- must exist before any `app.*` import ---
# POSTGRES_* here only need to be well-formed enough for PostgresDsn.build()
# to succeed at import time (app/core/database.py constructs an engine
# object eagerly, but create_async_engine() does not connect until first
# use). The real test DB connection is TEST_DATABASE_URL below, and
# `deps.get_db` is overridden per-test so this "production-shaped" engine
# is never actually connected to.
os.environ.setdefault("PROJECT_NAME", "api-fa-backend-test")
os.environ.setdefault("POSTGRES_USER", "test")
os.environ.setdefault("POSTGRES_PASSWORD", "test")
os.environ.setdefault("POSTGRES_SERVER", "localhost")
os.environ.setdefault("POSTGRES_PORT", "5433")
os.environ.setdefault("POSTGRES_DB", "api_fa_test_unused")
# Deliberately long/random-looking and NOT on any known-placeholder list, so
# that once OBJ-001 Story 3 (SECRET_KEY startup validation) is implemented,
# importing `app.*` in this suite keeps working. Story 3 itself is tested
# in tests/unit/test_secret_key_startup.py via subprocess, independent of
# this module-level singleton.
os.environ.setdefault(
    "SECRET_KEY",
    "pytest-suite-fixed-secret-key-do-not-use-in-production-0123456789",
)
os.environ.setdefault("ALGORITHM", "HS256")
os.environ.setdefault("ACCESS_TOKEN_EXPIRE_MINUTES", "30")
os.environ.setdefault("REFRESH_TOKEN_EXPIRE_DAYS", "7")

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine

TEST_DATABASE_URL = os.environ.get(
    "TEST_DATABASE_URL",
    "postgresql+asyncpg://test:test@localhost:5433/api_fa_test",
)

DB_BLOCKED_MESSAGE = (
    "\n"
    "=================================================================\n"
    " INTEGRATION TEST BLOCKED: cannot reach the test PostgreSQL.\n"
    f" Tried: {TEST_DATABASE_URL}\n"
    "\n"
    " This is a DOCUMENTED environment blocker, not a bug in the test.\n"
    " See tests/README.md and the conftest.py module docstring.\n"
    "\n"
    " Fix: docker compose -f docker-compose.test.yml up -d\n"
    " or set TEST_DATABASE_URL to a Postgres you control.\n"
    "=================================================================\n"
)


@pytest_asyncio.fixture(scope="session", loop_scope="session")
async def db_engine():
    """Session-scoped engine bound to TEST_DATABASE_URL; (re)creates the schema once.

    Deliberately does NOT reuse app.core.database.engine (that one is bound
    to the fake POSTGRES_* values above and is never meant to be connected
    to in tests) -- this is a second, independent engine pointed at the
    real test database.

    NOTE: app.main's lifespan (which also calls Base.metadata.create_all,
    against the OTHER engine) intentionally never runs in these tests --
    httpx.ASGITransport does not send ASGI lifespan events unless wrapped
    with an explicit lifespan manager, which we don't do here. That is
    what keeps the fake POSTGRES_* engine from ever being touched.
    """
    from app.core.database import Base

    # Model classes must be imported so their tables register on
    # Base.metadata BEFORE create_all runs -- app/core/database.py itself
    # doesn't import them (only app/main.py does, via
    # `from app.models import user, verification`, which hasn't happened
    # yet at this point in fixture resolution). Without this, create_all
    # silently creates zero tables and every test fails downstream with a
    # confusing "relation ... does not exist" instead of a clean signal.
    from app.models import user, verification  # noqa: F401

    engine = create_async_engine(TEST_DATABASE_URL, echo=False, future=True)
    try:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.drop_all)
            await conn.run_sync(Base.metadata.create_all)
    except Exception as exc:  # noqa: BLE001 - intentionally broad, see message
        await engine.dispose()
        pytest.fail(DB_BLOCKED_MESSAGE + f"\nOriginal error: {exc!r}\n", pytrace=False)
    yield engine
    await engine.dispose()


@pytest_asyncio.fixture
async def db_session(db_engine):
    """One isolated, rolled-back-at-teardown session per test.

    Uses SQLAlchemy 2.0's built-in savepoint-joining support
    (join_transaction_mode="create_savepoint") so that app code calling
    `await db.commit()` mid-test still works (it commits/reopens a SAVEPOINT
    instead of the outer transaction), while the outer transaction itself is
    rolled back at fixture teardown -- no test leaves data behind for the
    next one.
    """
    async with db_engine.connect() as connection:
        await connection.begin()
        async with AsyncSession(
            bind=connection,
            join_transaction_mode="create_savepoint",
            expire_on_commit=False,
        ) as session:
            yield session
        await connection.rollback()


@pytest_asyncio.fixture
async def client(db_session):
    """AsyncClient hitting the real FastAPI app in-process, with `get_db` overridden.

    CAUTION for developer (flagged, not just for qa-engineer): if OBJ-001's
    rate limiter or OTP-lockout code opens its OWN db session (e.g. via
    `AsyncSessionLocal()` directly) instead of depending on
    `deps.get_db`/going through the session injected per-request, this
    override will not catch those writes, and they'll try to hit the fake
    POSTGRES_* target above (which is never actually created) -- tests that
    exercise rate limiting / lockout would then fail with a raw connection
    error instead of a clean assertion failure. Route all persistence
    through the injected session.
    """
    from app.api import deps
    from app.main import app

    async def _override_get_db():
        yield db_session

    app.dependency_overrides[deps.get_db] = _override_get_db
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as ac:
        yield ac
    app.dependency_overrides.clear()


@pytest.fixture
def api_prefix():
    from app.core.config import settings

    return settings.API_V1_STR


@pytest_asyncio.fixture
async def user_factory(db_session):
    from tests.factories import create_user

    async def _factory(**kwargs):
        return await create_user(db_session, **kwargs)

    return _factory


@pytest_asyncio.fixture
async def verification_factory(db_session):
    from tests.factories import create_verification

    async def _factory(**kwargs):
        return await create_verification(db_session, **kwargs)

    return _factory
