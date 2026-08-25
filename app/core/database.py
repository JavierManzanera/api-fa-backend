import ssl
from typing import Optional, Union

from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import declarative_base
from app.core.config import settings


def _build_ssl_connect_arg(
    mode: str, root_cert: Optional[str] = None
) -> Union[bool, ssl.SSLContext]:
    """OBJ-003 finding #8 (obj-003-design-notes.md section 2.1): translates
    POSTGRES_SSL_MODE into the explicit `ssl` connect_arg asyncpg expects
    (False / SSLContext -- asyncpg does not parse libpq-style `sslmode=`
    strings). Built explicitly per mode rather than passed through, because
    asyncpg's own `ssl=True` already behaves like libpq's `verify-full`
    (CERT_REQUIRED + hostname check), not `require` -- so `require`'s
    weaker "encrypt, don't verify" posture must be constructed by hand.

    `root_cert` (audit finding #18 --
    docs/database/obj-012-tls-dast-verification.md, Finding 1): optional
    POSTGRES_SSL_ROOT_CERT path, forwarded as `verify-full`'s
    `ssl.create_default_context(cafile=...)` trust anchor so operators can
    pin a private/self-signed CA instead of relying solely on the OS
    default trust store. `require` intentionally ignores it -- that mode
    never verifies the server's certificate at all, so a trust anchor is
    meaningless there. `None` (the default) reproduces the exact prior
    behavior -- `ssl.create_default_context()` already treats a bare
    `cafile=None` as "OS default trust store only"."""
    if mode == "disable":
        return False
    if mode == "require":
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx
    if mode == "verify-full":
        return ssl.create_default_context(cafile=root_cert)
    raise ValueError(f"Unknown POSTGRES_SSL_MODE: {mode!r}")


engine = create_async_engine(
    str(settings.SQLALCHEMY_DATABASE_URI),
    connect_args={
        "ssl": _build_ssl_connect_arg(
            settings.POSTGRES_SSL_MODE, settings.POSTGRES_SSL_ROOT_CERT
        )
    },
    echo=False,
    future=True
)

AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False
)

Base = declarative_base()

async def get_db():
    async with AsyncSessionLocal() as session:
        try:
            yield session
        finally:
            await session.close()
