"""
OBJ-004 finding #9, part 2 -- SecurityHeadersMiddleware: HSTS,
X-Frame-Options, X-Content-Type-Options, and CSP present on every response,
with the Gate-1-approved scoped CSP exemption applying to /docs and /redoc
specifically and the strict CSP applying everywhere else (including
/openapi.json, per design notes section 2's explicit "/openapi.json is pure
JSON -- gets _API_CSP" note).

No Gherkin/AC doc exists for OBJ-004 -- see test_environment_settings.py's
docstring for the shared "derived from design notes" rationale. Scenario
derivation from obj-004-design-notes.md section 2:

  - "Strict-Transport-Security... max-age=63072000; includeSubDomains...
    unconditionally" -> TestHstsHeader.
  - "X-Frame-Options: DENY" -> TestXFrameOptionsHeader.
  - "X-Content-Type-Options: nosniff... Always set, no tradeoff" -> TestNosniffHeader.
  - "CSP: strict default-src 'none'... on real API JSON responses" +
    "a scoped, looser CSP on /docs/redoc" (Gate 1 APPROVED Option A,
    dependency_graph.md OBJ-004 Gate 1) -> TestContentSecurityPolicyHeader.
  - section 2's own code comment "/openapi.json is pure JSON -- gets
    _API_CSP" -> test_openapi_json_gets_strict_csp_not_docs_csp (this is
    the one easy-to-get-wrong case: it would be a natural but WRONG
    implementation to lump /openapi.json in with /docs and /redoc since all
    three are "docs-related" -- this test guards against that).

This file uses the shared `client` fixture (real Postgres-backed, per
tests/README.md) rather than a subprocess: unlike CORS-origin configuration
or ENVIRONMENT's docs-gating effect, none of these headers' VALUES depend on
which Settings config is active -- they are the same constants on every
response regardless of environment (HSTS/XFO/nosniff especially; the CSP
split is path-based, not config-based). The one config dependency this file
DOES have -- /docs and /redoc must be reachable to probe their CSP at all --
is already satisfied by tests/conftest.py's ENVIRONMENT=development default
(see that file's own comment), so no subprocess is needed here; the
separate "docs are actually gated off in production" behavior is
tests/api/test_docs_gating.py's concern, not this file's.
"""


def _header(resp, name: str):
    """Case-insensitive header lookup -- httpx normally handles this itself
    via resp.headers.get(), but spelled out explicitly here since header
    CASING is not the property under test and shouldn't be able to hide a
    failure."""
    return resp.headers.get(name)


class TestHstsHeader:
    async def test_hsts_present_on_json_api_response(self, client):
        resp = await client.get("/")
        assert resp.status_code == 200
        hsts = _header(resp, "strict-transport-security")
        assert hsts is not None, "Strict-Transport-Security header is missing"
        assert "max-age=63072000" in hsts, f"got {hsts!r}"
        assert "includesubdomains" in hsts.lower(), f"got {hsts!r}"

    async def test_hsts_does_not_include_preload(self, client):
        """design notes section 2.1: 'preload deliberately excluded --
        submitting a domain to browser HSTS preload lists is effectively
        irreversible.'"""
        resp = await client.get("/")
        hsts = _header(resp, "strict-transport-security") or ""
        assert "preload" not in hsts.lower(), (
            f"HSTS must NOT include 'preload' by default (design notes "
            f"section 2.1) -- got {hsts!r}"
        )

    async def test_hsts_present_on_an_auth_endpoint_response_too(self, client, api_prefix):
        """Not just the root route -- the middleware must apply globally."""
        resp = await client.post(f"{api_prefix}/auth/forgot-password", json={"email": "nobody@example.com"})
        assert _header(resp, "strict-transport-security") is not None


class TestXFrameOptionsHeader:
    async def test_x_frame_options_is_deny(self, client):
        resp = await client.get("/")
        assert _header(resp, "x-frame-options") == "DENY"


class TestNosniffHeader:
    async def test_x_content_type_options_is_nosniff(self, client):
        resp = await client.get("/")
        assert _header(resp, "x-content-type-options") == "nosniff"

    async def test_nosniff_present_on_error_response_too(self, client, api_prefix):
        """Security headers must apply even to error/4xx responses, not
        only the 'happy path' -- a login failure is a very common response
        shape to check this against."""
        resp = await client.post(
            f"{api_prefix}/auth/login",
            data={"username": "nobody@example.com", "password": "wrong"},
        )
        assert resp.status_code in (400, 401)
        assert _header(resp, "x-content-type-options") == "nosniff"
        assert _header(resp, "x-frame-options") == "DENY"


class TestContentSecurityPolicyHeader:
    async def test_api_json_response_gets_strict_csp(self, client):
        resp = await client.get("/")
        csp = _header(resp, "content-security-policy")
        assert csp is not None, "Content-Security-Policy header is missing"
        assert "default-src 'none'" in csp, (
            f"ordinary API responses must get the strict CSP (design notes "
            f"section 2.4) -- got {csp!r}"
        )

    async def test_docs_route_gets_the_scoped_looser_csp(self, client):
        """Gate 1 APPROVED Option A (dependency_graph.md, OBJ-004 Gate 1,
        2026-08-23): scoped CDN exemption for /docs specifically -- NOT the
        strict API CSP, which would break Swagger UI's default asset
        loading (design notes section 2.4/2.5)."""
        resp = await client.get("/docs")
        assert resp.status_code == 200, (
            "/docs must be reachable in the test suite's ENVIRONMENT=development "
            f"config -- got {resp.status_code}, check conftest.py's ENVIRONMENT default"
        )
        csp = _header(resp, "content-security-policy")
        assert csp is not None
        assert "default-src 'none'" not in csp, (
            f"/docs must NOT get the strict API CSP -- it would break "
            f"Swagger UI's default CDN asset loading. got {csp!r}"
        )
        assert "cdn.jsdelivr.net" in csp, (
            f"/docs' scoped CSP must allow the known Swagger UI CDN origin "
            f"per design notes section 2.4 -- got {csp!r}"
        )

    async def test_redoc_route_gets_the_scoped_looser_csp(self, client):
        resp = await client.get("/redoc")
        assert resp.status_code == 200
        csp = _header(resp, "content-security-policy")
        assert csp is not None
        assert "default-src 'none'" not in csp, f"got {csp!r}"
        assert "cdn.jsdelivr.net" in csp, f"got {csp!r}"

    async def test_openapi_json_gets_strict_csp_not_docs_csp(self, client):
        """design notes section 2's explicit note: '/openapi.json is pure
        JSON -- gets _API_CSP'. The easy bug here is lumping all three
        docs-adjacent paths together; this test specifically catches that,
        since /openapi.json returning application/json has no legitimate
        need for the CDN-permissive policy /docs/redoc need for their HTML
        UI."""
        resp = await client.get("/openapi.json")
        assert resp.status_code == 200
        csp = _header(resp, "content-security-policy")
        assert csp is not None
        assert "default-src 'none'" in csp, (
            f"/openapi.json must get the STRICT API CSP, not the docs "
            f"exemption (design notes section 2, explicit note) -- got {csp!r}"
        )

    async def test_docs_csp_still_restricts_frame_ancestors(self, client):
        """design notes section 2's _DOCS_CSP constant includes
        frame-ancestors 'none' even in the looser policy -- the CDN
        exemption is scoped to script/style/img/connect sources only, not a
        blanket loosening."""
        resp = await client.get("/docs")
        csp = _header(resp, "content-security-policy") or ""
        assert "frame-ancestors 'none'" in csp, f"got {csp!r}"
