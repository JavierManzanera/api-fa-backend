"""
OBJ-004 finding #13 -- `/docs`, `/redoc`, `/openapi.json` reachability
gated by ENVIRONMENT. Companion to tests/unit/test_environment_settings.py
(which tests the ENVIRONMENT field's own validation, in isolation); this
file tests the field's actual, observable HTTP EFFECT: are these three
routes reachable or not, per environment.

No Gherkin/AC doc exists for OBJ-004 -- see test_environment_settings.py's
docstring for the shared "derived from design notes" rationale. Scenario
derivation from obj-004-design-notes.md section 3:

  - "_DOCS_ENABLED_ENVIRONMENTS = {'development', 'staging'}... Docs
    enabled for development AND staging, disabled only for production" ->
    TestDocsReachableInDevelopmentAndStaging, TestDocsDisabledInProduction.
  - "docs_url='/docs' if _docs_enabled else None" (and same for redoc_url /
    openapi_url) -- FastAPI's behavior when these are None is that the
    ROUTES DON'T EXIST AT ALL, so a request to them 404s (no route
    matched), not a deliberate "403 access denied" -- this file asserts
    404 specifically, matching that mechanism, per the task's own "(or
    however the design notes specify)" allowance.

Since app.main.app is built from the module-level `settings` singleton at
FIRST IMPORT (app = FastAPI(docs_url=... if _docs_enabled else None, ...)),
and both `settings` and `app` are constructed exactly once per process, a
different ENVIRONMENT value can only be observed by importing app.main in a
FRESH process -- same subprocess-per-config constraint documented in
tests/api/test_cors_middleware.py's module docstring, reused here via the
same ASGI-probe-in-a-subprocess technique.

Does NOT require Postgres: app.main's lifespan (the only DB-touching code
path) never runs under httpx.ASGITransport without an explicit lifespan
wrapper, and none of these subprocess scripts add one -- same reasoning
tests/conftest.py's own `client` fixture docstring already documents.
"""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]

BASE_ENV_FIELDS = {
    "PROJECT_NAME": "subprocess-test",
    "POSTGRES_USER": "test",
    "POSTGRES_PASSWORD": "test",
    "POSTGRES_SERVER": "localhost",
    "POSTGRES_PORT": "5433",
    "POSTGRES_DB": "api_fa_test_unused",
    "POSTGRES_SSL_MODE": "disable",
    "SECRET_KEY": "Kx9mP2vQ8zR4tL6wN1yB5cA3jH7fD0sG-Kx9mP2vQ8zR4tL6wN1yB5cA3jH7fD0sG",
    "ALGORITHM": "HS256",
    "ACCESS_TOKEN_EXPIRE_MINUTES": "30",
    "REFRESH_TOKEN_EXPIRE_DAYS": "7",
    # PROACTIVE FIX (same convention documented in
    # test_postgres_ssl_mode_startup.py's own docstring): this file
    # parametrizes ENVIRONMENT over all three values including
    # "production", and the new EMAIL_PROVIDER/ENVIRONMENT cross-field
    # validator (tests/unit/test_email_provider_startup.py,
    # audit-report.md Gate 3 OBJ-005) now rejects
    # ENVIRONMENT=production + EMAIL_PROVIDER="console" (the default) at
    # import time -- without this, every production-environment case here
    # would fail for an unrelated reason (Settings() raising before the
    # ASGI probe ever runs), masking this file's own docs-gating behavior
    # under test.
    "EMAIL_PROVIDER": "smtp",
}

_ASGI_PROBE_SCRIPT = """
import asyncio
import json
from httpx import ASGITransport, AsyncClient
from app.main import app

async def main():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as ac:
        results = {}
        for path in ("/docs", "/redoc", "/openapi.json"):
            resp = await ac.get(path)
            results[path] = resp.status_code
        print("RESULT=" + json.dumps(results))

asyncio.run(main())
"""


def _probe_docs_routes(environment: str) -> dict:
    env = dict(os.environ)
    env.update(BASE_ENV_FIELDS)
    env["ENVIRONMENT"] = environment
    result = subprocess.run(
        [sys.executable, "-c", _ASGI_PROBE_SCRIPT],
        cwd=str(REPO_ROOT),
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )
    for line in result.stdout.splitlines():
        if line.startswith("RESULT="):
            return json.loads(line[len("RESULT="):])
    raise AssertionError(
        f"subprocess ASGI probe produced no RESULT= line.\n"
        f"returncode={result.returncode}\nstdout={result.stdout!r}\nstderr={result.stderr!r}"
    )


class TestDocsReachableInDevelopmentAndStaging:
    @pytest.mark.parametrize("environment", ["development", "staging"])
    def test_all_three_docs_routes_return_200(self, environment):
        results = _probe_docs_routes(environment)
        for path, status in results.items():
            assert status == 200, (
                f"{path} must be reachable (200) when ENVIRONMENT="
                f"{environment!r} (design notes section 3: docs enabled for "
                f"development and staging) -- got {status}"
            )


class TestDocsDisabledInProduction:
    def test_all_three_docs_routes_404_in_production(self):
        results = _probe_docs_routes("production")
        for path, status in results.items():
            assert status == 404, (
                f"{path} must be unreachable (404 -- no route registered, "
                f"matching FastAPI's docs_url=None mechanism) when "
                f"ENVIRONMENT='production' (audit finding #13) -- got {status}"
            )
