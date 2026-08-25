"""SecurityHeadersMiddleware -- HSTS, X-Frame-Options, X-Content-Type-Options,
and Content-Security-Policy on every response (OBJ-004 finding #9, part 2,
obj-004-design-notes.md section 2).

CSP is the one header that's genuinely app-specific (design notes section
2.4): ordinary JSON API responses get a maximally restrictive policy, while
/docs and /redoc get a scoped exemption for the known Swagger UI/ReDoc CDN
origins (Gate 1 APPROVED Option A, section 2.5) -- /openapi.json is pure
JSON and deliberately does NOT get that exemption (section 2's own explicit
note).
"""

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

_HSTS_VALUE = "max-age=63072000; includeSubDomains"

_API_CSP = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'"
_DOCS_CSP = (
    "default-src 'self'; "
    "script-src 'self' https://cdn.jsdelivr.net; "
    "style-src 'self' https://cdn.jsdelivr.net 'unsafe-inline'; "
    "img-src 'self' data: https://fastapi.tiangolo.com; "
    "connect-src 'self'; "
    "frame-ancestors 'none'"
)
_DOCS_PATHS = {"/docs", "/redoc"}  # /openapi.json is pure JSON -- gets _API_CSP


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        response = await call_next(request)
        response.headers["Strict-Transport-Security"] = _HSTS_VALUE
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Content-Security-Policy"] = (
            _DOCS_CSP if request.url.path in _DOCS_PATHS else _API_CSP
        )
        return response
