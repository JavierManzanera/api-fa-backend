"""
OBJ-004 finding #9, part 1 -- CORS middleware HTTP-level behavior. Companion
to tests/unit/test_cors_settings.py (which tests BACKEND_CORS_ORIGINS
parsing/validation in isolation); this file tests what a browser actually
observes: does CORSMiddleware restrict/allow cross-origin requests per the
configured origin list.

No Gherkin/AC doc exists for OBJ-004 -- see test_environment_settings.py's
docstring for the full "derived from design notes, not Gherkin" rationale
shared by this whole objective. Scenario derivation from
obj-004-design-notes.md sections 1.1-1.4:

  - "defaulting to an empty list... CORS is effectively closed to all
    browser cross-origin calls" (Gate 1 Option A) ->
    TestDefaultEmptyOriginsRestrictsCrossOrigin, using the SUITE-WIDE
    default (tests/conftest.py does not set BACKEND_CORS_ORIGINS, so it
    defaults to [] for every test in this whole suite via the shared
    `client` fixture -- see that class's own docstring for why this is the
    one CORS scenario that does NOT need a subprocess).
  - "Trailing-slash gotcha... AnyHttpUrl's str() output always has a
    trailing slash... Fix: strip the trailing slash before handing to
    CORSMiddleware" -> TestConfiguredOriginAllowsMatchingRequest's
    test_trailing_slash_bug_fix_matching_origin_gets_cors_header is the
    load-bearing regression test for this exact bug: it configures an
    origin WITHOUT a trailing slash (the only shape a real browser Origin
    header is ever sent in) and asserts the CORS header appears. If the bug
    were reintroduced (str(origin) used directly, un-stripped), this
    specific test would fail even though "CORS is configured" -- silently
    never matching any real request, exactly as the design notes describe.
  - "allow_methods=['GET', 'POST']... allow_headers=['Authorization',
    'Content-Type']... explicit allowlist, not '*'" -> TestMethodsAndHeadersAreExplicitAllowlists.
  - "allow_credentials=False by default" -> TestCredentialsDisabledByDefault.
  - "expose_headers=['Retry-After']" -> TestRetryAfterIsExposedToBrowserJs.

Since app.main.app and app.core.config.settings are both module-level
singletons constructed ONCE at first import in this pytest process (same
constraint documented throughout this project's subprocess-based Settings
tests), any scenario that needs a DIFFERENT BACKEND_CORS_ORIGINS value than
this suite's fixed conftest.py default cannot be exercised via the shared
`client` fixture -- those scenarios spin up a short-lived subprocess that
imports a FRESH app.main.app under a controlled environment and drives it
via httpx.ASGITransport in-process (inside that subprocess), printing
results back to this process over stdout. This mirrors the project's
established subprocess-per-case pattern (test_secret_key_startup.py etc.),
extended here from "does Settings() raise" to "what does a real ASGI
request through this app observe" -- still a single process boundary per
distinct config, for the same underlying reason.

Requires Postgres only for the default-origins class (it uses the shared
`client` fixture, which is DB-backed even though these particular requests
never touch a table) -- see tests/README.md. The subprocess-based classes
below do NOT require Postgres: app.main's lifespan (the only code path that
would touch a real DB connection) never runs under ASGITransport with no
explicit lifespan wrapper, confirmed already by tests/conftest.py's own
`client` fixture docstring, and reproduced deliberately in every subprocess
script below by never wrapping the transport with a lifespan manager.
"""

import json
import os
import subprocess
import sys
from pathlib import Path

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
    "ENVIRONMENT": "development",
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

        resp = await ac.get("/", headers={"Origin": "https://allowed.example.com"})
        results["allowed_origin_acao"] = resp.headers.get("access-control-allow-origin")
        results["allowed_origin_acac"] = resp.headers.get("access-control-allow-credentials")
        results["allowed_origin_expose"] = resp.headers.get("access-control-expose-headers")

        resp2 = await ac.get("/", headers={"Origin": "https://evil.example.com"})
        results["disallowed_origin_acao"] = resp2.headers.get("access-control-allow-origin")

        preflight = await ac.options(
            "/",
            headers={
                "Origin": "https://allowed.example.com",
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "authorization,content-type",
            },
        )
        results["preflight_status"] = preflight.status_code
        results["preflight_methods"] = preflight.headers.get("access-control-allow-methods")
        results["preflight_headers"] = preflight.headers.get("access-control-allow-headers")

        print("RESULT=" + json.dumps(results))

asyncio.run(main())
"""


def _run_asgi_probe(cors_origins_value: str) -> dict:
    env = dict(os.environ)
    env.update(BASE_ENV_FIELDS)
    env["BACKEND_CORS_ORIGINS"] = cors_origins_value
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
        f"subprocess ASGI probe produced no RESULT= line (app import/startup "
        f"likely failed).\nreturncode={result.returncode}\n"
        f"stdout={result.stdout!r}\nstderr={result.stderr!r}"
    )


class TestDefaultEmptyOriginsRestrictsCrossOrigin:
    """Uses the SUITE-WIDE `client` fixture, not a subprocess -- this is the
    one CORS scenario that doesn't need a different config than what
    tests/conftest.py already provides, because conftest.py deliberately
    does NOT set BACKEND_CORS_ORIGINS, so it resolves to its real default
    ([]) for the whole suite, same as any other unconfigured, defaulted
    field."""

    async def test_no_cors_header_for_any_origin_when_unconfigured(self, client):
        resp = await client.get("/", headers={"Origin": "https://anything.example.com"})
        assert resp.status_code == 200
        assert "access-control-allow-origin" not in {
            k.lower() for k in resp.headers.keys()
        }, (
            "with BACKEND_CORS_ORIGINS unset (empty-list default, Gate 1 "
            "Option A), NO Origin should ever receive an "
            "Access-Control-Allow-Origin header -- CORS must be closed by "
            "default, not open to everything absent explicit config"
        )


class TestConfiguredOriginAllowsMatchingRequest:
    def test_trailing_slash_bug_fix_matching_origin_gets_cors_header(self):
        """The load-bearing regression test for design notes section 1.1's
        found-and-fixed trailing-slash bug. BACKEND_CORS_ORIGINS is
        configured WITHOUT a trailing slash (the only shape a real Origin
        header is ever sent in); if the app naively used str(AnyHttpUrl)
        (which always has a trailing slash) as the CORSMiddleware
        allow_origins entry, this would NEVER match and this test would
        fail even though CORS IS configured for this exact origin."""
        results = _run_asgi_probe("https://allowed.example.com")
        assert results["allowed_origin_acao"] == "https://allowed.example.com", (
            f"a request with Origin: https://allowed.example.com (no "
            f"trailing slash) must receive a matching "
            f"Access-Control-Allow-Origin header when that exact origin is "
            f"configured -- got {results['allowed_origin_acao']!r}. If this "
            f"is None, the trailing-slash bug (design notes section 1.1) is "
            f"present: the origin was compared with an un-stripped trailing "
            f"slash and never matched."
        )

    def test_non_configured_origin_gets_no_cors_header(self):
        results = _run_asgi_probe("https://allowed.example.com")
        assert results["disallowed_origin_acao"] is None, (
            f"an Origin NOT in BACKEND_CORS_ORIGINS must never receive an "
            f"Access-Control-Allow-Origin header, even when OTHER origins "
            f"are configured -- got {results['disallowed_origin_acao']!r}"
        )


class TestCredentialsDisabledByDefault:
    def test_allow_credentials_is_not_true_for_configured_origin(self):
        """design notes section 1.3: 'allow_credentials=False... this
        template uses Authorization-header bearer tokens, not cookies.'"""
        results = _run_asgi_probe("https://allowed.example.com")
        assert results["allowed_origin_acac"] != "true", (
            f"Access-Control-Allow-Credentials must not be 'true' -- this "
            f"template issues bearer tokens, not cookies (design notes "
            f"section 1.3). got {results['allowed_origin_acac']!r}"
        )


class TestRetryAfterIsExposedToBrowserJs:
    def test_retry_after_is_in_expose_headers_for_allowed_origin(self):
        """design notes section 1.4: 'Retry-After... is NOT in [the
        CORS-safelisted set]... expose_headers=["Retry-After"]'."""
        results = _run_asgi_probe("https://allowed.example.com")
        expose = results["allowed_origin_expose"] or ""
        assert "retry-after" in expose.lower(), (
            f"Access-Control-Expose-Headers must include Retry-After so "
            f"browser JS can read a 429's backoff duration cross-origin "
            f"(design notes section 1.4) -- got {expose!r}"
        )


class TestMethodsAndHeadersAreExplicitAllowlists:
    def test_preflight_succeeds_for_allowed_origin(self):
        results = _run_asgi_probe("https://allowed.example.com")
        assert results["preflight_status"] in (200, 204), (
            f"a CORS preflight (OPTIONS) for an allowed origin requesting "
            f"POST + Authorization/Content-Type must succeed -- got "
            f"{results['preflight_status']}"
        )

    def test_preflight_allow_methods_is_not_a_bare_wildcard(self):
        """design notes section 1.2: 'allow_methods=["GET", "POST"],
        explicit -- least-privilege default... rather than inheriting a
        silent "*"'."""
        results = _run_asgi_probe("https://allowed.example.com")
        methods = (results["preflight_methods"] or "").upper()
        assert methods != "*", (
            "allow_methods must be an explicit allowlist (GET, POST), not "
            "a bare wildcard (design notes section 1.2)"
        )
        assert "POST" in methods, f"POST must be allowed, got {methods!r}"

    def test_preflight_allow_headers_includes_authorization_and_content_type(self):
        results = _run_asgi_probe("https://allowed.example.com")
        headers = (results["preflight_headers"] or "").lower()
        assert "authorization" in headers, f"got {headers!r}"
        assert "content-type" in headers, f"got {headers!r}"
