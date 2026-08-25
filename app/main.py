import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware

from app.core.config import settings
from app.core.security_headers import SecurityHeadersMiddleware
from app.api.v1.router import api_router
from app.core.database import engine, Base
from app.core.scheduler import build_scheduler
from app.models import user, verification, rate_limit, refresh_session
import uvicorn

# OBJ-004 finding #10 (obj-004-design-notes.md section 4.4): stdlib
# `logging`, configured once at startup. Structured (JSON) event lines are
# emitted to stdout by app.core.audit_log -- this call only sets the
# root/handler verbosity, it does not format audit lines itself.
logging.basicConfig(level=settings.LOG_LEVEL)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # In production, use Alembic. For quick start, this works.
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    # OBJ-006 (devops-engineer, obj-006-migration-plan.md section 4):
    # scheduled cleanup jobs for rate_limit_hits/refresh_sessions -- see
    # app/core/scheduler.py for the full design/rationale. Never runs
    # during the test suite: httpx.ASGITransport does not send ASGI
    # lifespan events unless explicitly wrapped, which tests/conftest.py's
    # `client` fixture deliberately does not do -- so this adds no risk to
    # the existing test suite.
    scheduler = build_scheduler()
    scheduler.start()
    try:
        yield
    finally:
        scheduler.shutdown(wait=False)


# OBJ-004 finding #13 (obj-004-design-notes.md section 3): docs endpoints
# reachable in development and staging only, disabled (no route at all) in
# production.
_DOCS_ENABLED_ENVIRONMENTS = {"development", "staging"}
_docs_enabled = settings.ENVIRONMENT in _DOCS_ENABLED_ENVIRONMENTS

app = FastAPI(
    title=settings.PROJECT_NAME,
    lifespan=lifespan,
    docs_url="/docs" if _docs_enabled else None,
    redoc_url="/redoc" if _docs_enabled else None,
    openapi_url="/openapi.json" if _docs_enabled else None,
)

# OBJ-004 finding #9 (obj-004-design-notes.md section 1): CORS, trusted-host
# validation, and security headers -- none of these existed before this
# objective (audit-report.md finding #9's evidence: "Sin CORS ni cabeceras
# de seguridad HTTP").
app.add_middleware(
    CORSMiddleware,
    # AnyHttpUrl's str() always carries a trailing slash
    # (http://localhost:3000 -> "http://localhost:3000/"), but a browser's
    # Origin header never does -- CORSMiddleware does an exact string match,
    # so the trailing slash must be stripped or a configured origin would
    # silently never match any real request (design notes section 1.1).
    allow_origins=[str(origin).rstrip("/") for origin in settings.BACKEND_CORS_ORIGINS],
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "Content-Type"],
    expose_headers=["Retry-After"],
)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.ALLOWED_HOSTS)
app.add_middleware(SecurityHeadersMiddleware)

app.include_router(api_router, prefix=settings.API_V1_STR)


@app.get("/")
def read_root():
    return {"msg": "Welcome to FastAPI Headless Auth API"}


if __name__ == "__main__":
    uvicorn.run("app.main:app", host="127.0.0.1", port=8000, reload=True)
