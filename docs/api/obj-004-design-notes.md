# OBJ-004 — HTTP Security Baseline: API Design Notes

**Author:** solution-architect
**Input:** `docs/security/audit-report.md` findings #9, #10, #13, plus two backlog items folded in
from prior Gate 3 passes: `client_ip()`'s missing `X-Forwarded-For` support (security-specialist,
OBJ-001 Gate 3, "New MEDIUM") and `.env.example`'s incomplete `POSTGRES_SSL_MODE=require` wording
(security-specialist, OBJ-003 Gate 3, "[NUEVO — BAJO]"). No `business-analyst` pass for this
objective — infra/security hardening, no user-facing story, same convention as OBJ-003.
Companion artifacts read in full for this pass: `app/main.py`, `app/core/config.py`,
`app/core/rate_limit.py`, `app/api/v1/endpoints/auth.py`, `.env.example`.

No `openapi.yaml` schema/status-code/response-shape changes are needed for any of these findings —
CORS, security headers, docs-gating, and logging are all transport/framework-level concerns with no
HTTP body/status surface; the `client_ip()` fix changes *which* IP gets rate-limited, not the
response contract. `openapi.yaml` gets description-text updates only; see §8.

**Quick index:** finding numbers verified against `audit-report.md`, no transposition this time
(§0) · CORS via `BACKEND_CORS_ORIGINS: List[AnyHttpUrl]`, empty-list-safe default, structurally
rejects `"*"` (§1) · `SecurityHeadersMiddleware` — HSTS/nosniff/XFO always, CSP scoped looser for
`/docs`/`/redoc` only (§2) · new `ENVIRONMENT` field gates docs endpoints, dev+staging on,
production off (§3) · structured JSON audit-log event catalog, stdlib `logging` not `structlog`,
explicit never-log list for secrets (§4) · OTP debug `print` removed, replaced by an audit-log line
+ a temporary no-op `notifications.send_otp_notification` seam that OBJ-005 will later replace the
body of (§5) · `client_ip()` gains `TRUSTED_PROXY_COUNT`-based `X-Forwarded-For` trust, defaults to
0/untrusted (§6) · `.env.example` doc fix for `POSTGRES_SSL_MODE=require`'s MITM caveat (§7) · 4
genuine Gate-1 tradeoffs (§9). Jump to: "0. Finding-number verification", "1. CORS policy",
"2. Security headers middleware", "3. ENVIRONMENT-gated docs", "4. Structured auth-event logging",
"5. OTP debug print removal", "6. client_ip() X-Forwarded-For fix", "7. .env.example wording fix",
"8. openapi.yaml impact", "9. Open decisions".

---

## 0. Finding-number verification (unlike OBJ-003, no transposition found)

Per the task's explicit instruction to verify rather than trust `dependency_graph.md`'s citation
blindly (after OBJ-003's row was found transposed): read `docs/security/audit-report.md` directly.

| # in `audit-report.md` | Actual finding | Matches OBJ-004's shape? |
|---|---|---|
| **#9** | MEDIO — Sin CORS ni cabeceras de seguridad HTTP | Yes — CORS + HSTS/XFO/CSP/nosniff |
| **#10** | MEDIO — Sin logging/auditoría de eventos de autenticación (+ the OTP debug `print`) | Yes — structured auth-event logging + print removal |
| **#13** | BAJO — `/docs`, `/redoc`, `/openapi.json` expuestos sin gate de entorno | Yes — `ENVIRONMENT`-gated docs |

**Confirmed correct, no correction needed this time.** `dependency_graph.md`'s OBJ-004 row citation
matches `audit-report.md`'s real numbering exactly.

---

## 1. CORS policy (finding #9, part 1)

**Evidence:** `app/main.py:18-20` — `FastAPI(...)` with no `CORSMiddleware` registered at all
(confirmed by reading the full file, reproduced in §8 of this document's companion diff notes).

### 1.1 Origins: parametrized, empty-safe default, typed to reject `"*"` structurally

**Decision:** new `Settings` field `BACKEND_CORS_ORIGINS: List[AnyHttpUrl] = []`, populated from a
comma-separated env var (the common FastAPI-template convention), defaulting to an **empty list**
— not a hardcoded origin, and not a wildcard.

```python
BACKEND_CORS_ORIGINS: List[AnyHttpUrl] = []

@field_validator("BACKEND_CORS_ORIGINS", mode="before")
@classmethod
def assemble_cors_origins(cls, value):
    if isinstance(value, str) and not value.startswith("["):
        return [origin.strip() for origin in value.split(",") if origin.strip()]
    return value  # already a list, or JSON-array string -- let pydantic's
                   # native complex-type parsing handle it
```

**Why `List[AnyHttpUrl]`, not `List[str]` — a deliberate type-system choice, not a style
preference.** Audit finding #9's own stated risk is explicit: *"es probable que el siguiente
proyecto añada `allow_origins=["*"]` apresuradamente"* (evidence text, `audit-report.md` line 87).
`AnyHttpUrl` cannot parse the literal string `"*"` — it fails URL validation and blocks app startup
via the same `Settings()`-construction-time mechanism already established for `SECRET_KEY` and
`POSTGRES_SSL_MODE`. This closes the audit's exact named fear **at the type-validation level**, not
just by convention/documentation that a rushed fork could ignore — a meaningfully stronger
guarantee than "the docs say don't do this."

**Trailing-slash gotcha — found and fixed during this pass, not theoretical.** Pydantic v2's
`AnyHttpUrl` stringifies with a trailing slash (`http://localhost:3000` → `AnyHttpUrl` →
`str(...)` → `"http://localhost:3000/"`), but a browser's `Origin` header never carries a trailing
slash. `CORSMiddleware` does an exact string match against `allow_origins`, so passing
`str(origin)` directly would silently never match any real request. Fix: strip the trailing slash
when converting to the plain strings `CORSMiddleware` expects:

```python
app.add_middleware(
    CORSMiddleware,
    allow_origins=[str(origin).rstrip("/") for origin in settings.BACKEND_CORS_ORIGINS],
    ...
)
```

### 1.2 Methods and headers: explicit allowlist, not `["*"]`

Every current endpoint is `GET` or `POST` (confirmed: `register`/`login`/`forgot-password`/
`verify-otp`/`reset-password`/`refresh`/`logout` are all `POST`; `/me` is the only `GET`).
**Decision:** `allow_methods=["GET", "POST"]`, explicit — least-privilege default; a fork adding
`PUT`/`DELETE`/`PATCH` routes must consciously widen this, rather than inheriting a silent `"*"`.
`allow_headers=["Authorization", "Content-Type"]`, explicit — these are the only two headers any
current client needs to send.

### 1.3 Credentials: `False` by default — this service uses bearer tokens, not cookies

`allow_credentials` controls whether the browser sends/exposes cookies, HTTP auth, or TLS client
certs cross-origin — it does **not** gate custom headers like `Authorization`, which are governed
by `allow_headers` instead. Since this template issues JWTs delivered in the response body and sent
back via an `Authorization: Bearer` header (never a cookie), **`allow_credentials=False`** is the
correct default, not just a conservative one. **Flag for any fork that adopts cookie-based refresh
tokens later:** flipping this to `True` must never be paired with a wildcard origin — browsers
already reject that combination client-side, but it's worth noting here since it's exactly the kind
of thing that's easy to miss when only skimming this middleware call.

### 1.4 `expose_headers`: `Retry-After` needs to be explicit

Per the Fetch spec, only a small "CORS-safelisted" set of response headers (`Content-Type`,
`Content-Length`, etc.) is readable by browser JS by default on a cross-origin response —
`Retry-After` (already part of the `RateLimited` response contract, `openapi.yaml`
`components/responses/RateLimited`) is **not** in that set. Without `expose_headers=["Retry-After"]`,
a fork's frontend JS could see a `429` but never read *how long* to back off. **Decision:**
`expose_headers=["Retry-After"]`.

### 1.5 Addendum — `TrustedHostMiddleware` (also cited in finding #9's evidence, not itemized in
the task's own numbered list, included for completeness)

`audit-report.md`'s evidence line for #9 names three absent things: `CORSMiddleware`,
`TrustedHostMiddleware`, and security headers. The task's item breakdown covers the first and
third explicitly but doesn't name `TrustedHostMiddleware` — flagging it here since the underlying
finding does cite it, and it's cheap to close alongside CORS. `TrustedHostMiddleware` validates the
`Host` header against an allowlist, defending against Host-header-injection-based cache poisoning
or virtual-host confusion. **Decision:** `ALLOWED_HOSTS: List[str] = ["*"]` (same comma-parsing
validator shape as §1.1), registered via `TrustedHostMiddleware(app, allowed_hosts=...)`. Default
`["*"]` exactly preserves today's behavior (no host validation at all, since the middleware isn't
installed today) while giving every fork an explicit, documented knob to tighten — not a Gate-1
blocker, since the default changes nothing observable.

### 1.6 Open decision (Gate 1) — default origins policy

**This is the genuine product/deployment tradeoff, not decided here, per task instructions.**

| Option | Behavior | Pro | Con |
|---|---|---|---|
| **A — empty list, safe default (recommended)** | `BACKEND_CORS_ORIGINS` defaults to `[]`; CORS is effectively closed to all browser cross-origin calls until a fork explicitly configures it | Fails closed, matches `SECRET_KEY`/`POSTGRES_SSL_MODE`'s existing "no silent weak config" posture; the failure mode is immediately visible (a browser console CORS error) the moment a fork's frontend tries to call the API, forcing an explicit decision rather than an accidental wildcard | A fork's frontend genuinely does not work against this API until `BACKEND_CORS_ORIGINS` is set — friction on first integration, by design |
| **B — required, no default** | Same as `POSTGRES_SSL_MODE`: field has no default at all, every environment (including `.env.example`, `tests/conftest.py`) must set it explicitly, even to an empty value | Forces an explicit choice in every environment, no "it happened to work because the default was empty" ambiguity | An empty-list default is *already* maximally safe (fails closed) — making it required adds ceremony (one more line every `.env`/CI config must carry) without closing any actual gap the default-empty behavior leaves open |

**Recommendation: Option A.** Unlike `SECRET_KEY`/`POSTGRES_SSL_MODE` (where an unset/weak value is
actively dangerous), an empty `BACKEND_CORS_ORIGINS` list is already the maximally safe state — so
the "require an explicit choice" rationale that justifies B for those two fields doesn't carry the
same weight here. Flagged for Gate 1 confirmation per task instructions regardless, since this is
exactly the kind of "sane default a forking project's frontend can override" call the task named
explicitly.

---

## 2. Security headers middleware (finding #9, part 2)

**Decision:** a new `SecurityHeadersMiddleware` (`app/core/security_headers.py`), applied to every
response:

```python
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
```

### 2.1 HSTS — `max-age=63072000; includeSubDomains`, no `preload`

Two years (`63072000` seconds), matching the widely-used "HSTS-ready" baseline. `includeSubDomains`
is included since this is an auth service — a fork's subdomains (e.g. an API subdomain vs. a
frontend subdomain sharing the parent domain's cookies/session assumptions) should not be
downgradable to plain HTTP either. **`preload` deliberately excluded**: submitting a domain to
browser HSTS preload lists is effectively **irreversible** in practice (removal takes months and
requires the domain to have already dropped HTTPS support first) — not something a reusable
template should opt a fork's domain into by default. A fork that wants preload can add it to this
constant themselves once they've confirmed every subdomain is genuinely HTTPS-only, permanently.
**No gating needed on `ENVIRONMENT`/TLS status**: per RFC 6797, browsers only honor
`Strict-Transport-Security` when the response was itself received over HTTPS — sending it
unconditionally over plain HTTP in local dev is inert, not a compatibility risk.

### 2.2 `X-Frame-Options: DENY`

This is a pure JSON API — no response (except the ENVIRONMENT-gated `/docs`/`/redoc` HTML pages,
§3) has any legitimate reason to be framed by another site. `DENY` is stricter than
`SAMEORIGIN` and correct here since there's no same-origin page that legitimately frames this
service either.

### 2.3 `X-Content-Type-Options: nosniff`

Always set, no tradeoff — prevents a browser from MIME-sniffing a response into a different
content-type than declared (defense-in-depth against a hypothetical stored-content XSS if a
response's actual bytes were ever attacker-influenced).

### 2.4 CSP — the one header the task named as "notoriously app-specific," and it is

**API responses** (`_API_CSP`): `default-src 'none'; frame-ancestors 'none'; base-uri 'none'`. Safe
and uncontroversial — every real endpoint returns `application/json`, never renders anything a
browser would execute as script/style/image, so a maximally restrictive policy costs nothing
functionally. This is defense-in-depth on top of `nosniff`, not the primary control.

**Docs pages** (`_DOCS_CSP`, only reachable when `ENVIRONMENT` permits per §3): FastAPI's default
Swagger UI (`/docs`) and ReDoc (`/redoc`) load their JS/CSS bundles from `cdn.jsdelivr.net` and a
favicon from `fastapi.tiangolo.com`. A strict `default-src 'none'` here would silently break the
docs UI (blank page, console CSP violations) rather than just fail to protect anything additional —
worse than either alternative below.

### 2.5 Open decision (Gate 1) — CSP scope for `/docs`/`/redoc`

| Option | Behavior | Pro | Con |
|---|---|---|---|
| **A — scoped exemption for docs routes (recommended, shown above)** | Strict `_API_CSP` everywhere except `/docs`/`/redoc`, which get a permissive-but-still-restricted `_DOCS_CSP` allowing exactly the two known CDN origins FastAPI's default docs need | Docs stay usable out of the box; docs are already `ENVIRONMENT`-gated (§3), so the exposure window for this looser policy is dev/staging only, never production by default | Two CSP policies to maintain instead of one; if `developer` ever changes FastAPI's docs asset source, `_DOCS_CSP` needs a matching update |
| **B — strict CSP everywhere, including docs** | Same `_API_CSP` on every response, no exemption | One policy, simplest to reason about, no CDN trust at all | Breaks Swagger UI/ReDoc's default rendering unless `developer` also self-hosts the JS/CSS assets locally (`get_swagger_ui_html(swagger_js_url=..., swagger_css_url=...)`) — real, ongoing maintenance work for a template whose stated goal is staying lean to fork, to harden a surface (`/docs`) that's already access-gated by a separate, coarser control (§3) |

**Recommendation: Option A.** The docs pages are already environment-gated — CSP here is a second,
finer-grained layer on top of an already-narrow exposure window, so the marginal security value of
Option B is small relative to its ongoing cost. Flagged for Gate 1 per task instructions since this
is exactly the "genuinely app-specific" tradeoff named in the brief.

**Out of scope, noted for awareness only:** `Referrer-Policy` and `Permissions-Policy` are not part
of this objective's cited findings (task names HSTS/XFO/CSP/nosniff specifically) — not designed
here to stay disciplined to scope; a reasonable follow-up for a future pass if `security-specialist`
flags them.

---

## 3. `ENVIRONMENT`-gated docs endpoints (finding #13)

**Confirmed via direct read of `app/core/config.py`:** no `ENVIRONMENT` field exists anywhere in
`Settings` today (OBJ-001's Phase 1 notes flagged this as not-yet-existing as of that pass — still
true; this is the first objective to add it).

**Decision:** new required field, no default — matching the exact convention already established by
`POSTGRES_SSL_MODE` (§2.1 of `obj-003-design-notes.md`: "every environment must say what it wants"),
not a fresh Gate-1 tradeoff, since it directly follows precedent already approved for a
structurally identical field:

```python
_VALID_ENVIRONMENTS = {"development", "staging", "production"}

ENVIRONMENT: str

@field_validator("ENVIRONMENT")
@classmethod
def validate_environment(cls, value: str) -> str:
    if value not in _VALID_ENVIRONMENTS:
        raise ValueError(
            f"ENVIRONMENT must be one of {sorted(_VALID_ENVIRONMENTS)}, got {value!r}."
        )
    return value
```

Case-sensitivity matches `POSTGRES_SSL_MODE` (exact lowercase match, no case-insensitive handling)
rather than `SECRET_KEY`'s case-insensitive blocklist — this field is shape-identical to
`POSTGRES_SSL_MODE` (a small fixed enum of lowercase tokens), not to `SECRET_KEY`'s
free-text-with-a-blocklist shape.

**`app/main.py` wiring:**

```python
_DOCS_ENABLED_ENVIRONMENTS = {"development", "staging"}
_docs_enabled = settings.ENVIRONMENT in _DOCS_ENABLED_ENVIRONMENTS

app = FastAPI(
    title=settings.PROJECT_NAME,
    lifespan=lifespan,
    docs_url="/docs" if _docs_enabled else None,
    redoc_url="/redoc" if _docs_enabled else None,
    openapi_url="/openapi.json" if _docs_enabled else None,
)
```

Docs enabled for `development` **and** `staging`, disabled only for `production` — matches the
audit's literal fix text ("deshabilitar cuando `ENVIRONMENT=production`", `audit-report.md` line
125) exactly; staging is typically still an internal-facing environment where docs remain useful
for QA. Not routed to Gate 1 — a fork wanting docs disabled in staging too can narrow
`_DOCS_ENABLED_ENVIRONMENTS` to `{"development"}` trivially; this is a low-stakes default, not a
security-relevant fork in the road the way §1.6/§2.5/§6.3 are.

**Forward-looking note (per task instructions):** this field is deliberately general-purpose, not
docs-gating-specific — `OBJ-006` (CI/pip-audit branching, DB-role separation) and any future
objective needing environment-aware behavior can read `settings.ENVIRONMENT` directly. Not
over-designed here beyond what OBJ-004 itself needs.

---

## 4. Structured auth-event logging (finding #10, part 1)

**Evidence:** `audit-report.md` line 95 — "ningún uso de `logging`; solo un `print()` de debug del
OTP en claro." Confirmed via `grep`: no `import logging` anywhere in `app/`.

### 4.1 Mechanism: stdlib `logging` + a JSON formatter, no new dependency

**Decision:** stdlib `logging`, configured once at startup, emitting structured (JSON) lines to
stdout — no new runtime dependency (`structlog` was considered and rejected: this project's
established philosophy is minimal footprint for a template meant to be forked broadly, same
reasoning already applied to the rate limiter's "no Redis dependency added to the template" choice
in `obj-001-design-notes.md`). Output to **stdout**, not a file — 12-factor-app convention, letting
the deployment platform/log aggregator own retention/shipping. This is also the direct fix for
finding #10's own stated stdout concern ("riesgo adicional si stdout va a logs centralizados no
restringidos") — that risk was specifically about the *raw OTP* reaching stdout uncontrolled (§5);
once no raw secret ever reaches a log line, stdout becomes the correct sink, not a residual one.

**New module `app/core/audit_log.py`** — single owner of the auth-event log shape, same "one module
owns one concern" pattern as `security.py` (crypto), `rate_limit.py` (rate limiting):

```python
import json
import logging
from datetime import datetime, timezone
from typing import Any

_logger = logging.getLogger("app.audit")

def log_auth_event(event: str, *, level: int = logging.INFO, **fields: Any) -> None:
    """Structured auth-event log line. `fields` must never include a raw
    password, OTP code, or JWT token string -- see design notes section
    4.3. Callers pass only safe identifiers (email, ip, user_id, jti,
    family_id, outcome, reason)."""
    payload = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event": event,
        **fields,
    }
    _logger.log(level, json.dumps(payload))
```

### 4.2 Event catalog

Per finding #10's fix text ("login éxito/fallo, reset de password, intentos de OTP fallidos, uso
de refresh token") plus the OBJ-002 endpoints that didn't exist when the audit was written:

| Event | Level | Emitted from | Fields (beyond `timestamp`/`event`) |
|---|---|---|---|
| `auth.register` | INFO | `register` | `email`, `ip`, `outcome` (`success`\|`duplicate`) |
| `auth.login.success` | INFO | `login` | `email`, `ip`, `user_id` |
| `auth.login.failure` | INFO | `login` | `email`, `ip`, `reason` (`invalid_credentials`\|`inactive_user`) |
| `auth.otp.requested` | INFO | `forgot_password` | `email`, `ip`, `purpose` |
| `auth.otp.failed_attempt` | INFO | `_check_and_consume_otp` | `email`, `ip`, `purpose`, `attempts` |
| `auth.otp.lockout` | WARNING | `_check_and_consume_otp` | `email`, `ip`, `purpose` |
| `auth.password_reset.success` | INFO | `reset_password` | `email`, `ip`, `user_id` |
| `auth.refresh.success` | INFO | `refresh_token` | `user_id`, `family_id`, `old_jti`, `new_jti` |
| `auth.refresh.reuse_detected` | WARNING | `refresh_token` | `user_id`, `family_id`, `jti` |
| `auth.refresh.failure` | INFO | `refresh_token` | `ip`, `reason` (`no_session`\|`expired`\|`ver_mismatch`\|`user_inactive`) |
| `auth.logout` | INFO | `logout` | `jti` (nullable — the no-op branch has none), `ip` |
| `auth.rate_limit.exceeded` | WARNING | `enforce_rate_limit` | `scope`, `ip`, `email` |

`auth.register` is beyond the finding's literal list but a natural, low-risk audit-trail addition —
not routed to Gate 1 (unlike §1.6/§2.5/§6.3, there's no real tradeoff here, just "log one more
routine event").

`WARNING` is reserved for events that are themselves a security signal worth a human noticing
(rate-limit exhaustion, OTP lockout, refresh-token reuse — the last one specifically indicates
possible token theft, per OBJ-002's reuse-detection design). Ordinary auth failures (wrong
password, expired OTP) are `INFO` — expected, routine traffic, not incidents; logging them at
`WARNING` would create alert fatigue that trains operators to ignore the level entirely.

### 4.3 PII / token-leakage rule — explicit, non-negotiable

**Never logged, under any event, by any field:**
- Raw password (plaintext or hash)
- Raw OTP code (plaintext) — see §5, this is the specific thing finding #10 flags by name
- Raw JWT string (access or refresh token) — a token value in a log line is equivalent to a leaked
  credential (bearer token = ambient authority); only non-secret derived identifiers are logged
  (`jti`, `family_id` — knowing a session's id does not grant access to it without the actual
  signed token)
- `SECRET_KEY` / the derived OTP HMAC key

`email` **is** logged deliberately — it is the actor identity, standard and expected in an
authentication audit trail (distinct from a genuine secret like a password or token). This
distinction is stated explicitly here since the task called out the PII/leakage question directly.

### 4.4 `LOG_LEVEL` — new optional `Settings` field, safe default

```python
LOG_LEVEL: str = "INFO"
```

Unlike `ENVIRONMENT`/`SECRET_KEY`/`POSTGRES_SSL_MODE`, this field's failure mode if misconfigured is
"logs too much or too little," never a security posture regression — a safe default is genuinely
safe here, no Gate-1 flag needed. Configured once in `app/main.py`'s startup (`logging.basicConfig`
or an explicit handler setup) — not designed in further mechanical detail here, `developer`'s
Phase 3 concern.

---

## 5. OTP debug print removal (finding #10, part 2)

**Confirmed via direct read of `app/api/v1/endpoints/auth.py:263-266`** (per task instruction to
check for a remaining print statement before assuming OBJ-003 already removed it): **the print
still exists.** OBJ-003's `hash_otp` change (already landed) only changed what's *stored* in the DB
— the raw OTP still passes through `forgot_password`'s local `otp` variable and is still printed in
full to stdout:

```python
# app/api/v1/endpoints/auth.py:263-266 (current)
print(f"============================================")
print(f" [EMAIL MOCK] To: {payload.email} | OTP: {otp} ")
print(f"============================================")
```

### 5.1 Decision: remove the print, replace with a non-secret-leaking audit log line + a minimal
delivery seam

```python
# replaces the print block
audit_log.log_auth_event("auth.otp.requested", email=payload.email, purpose=RESET_PASSWORD_PURPOSE, ip=rate_limit.client_ip(http_request))
notifications.send_otp_notification(payload.email, otp, purpose=RESET_PASSWORD_PURPOSE)
```

`app/core/notifications.py` (new, minimal, deliberately **not** the full pluggable email-sender
abstraction — that is explicitly OBJ-005 scope per `dependency_graph.md`'s OBJ-005 row):

```python
def send_otp_notification(email: str, otp: str, *, purpose: str) -> None:
    """Placeholder OTP delivery channel. Temporary, pre-OBJ-005 -- a real
    pluggable email-sender abstraction lands in OBJ-005 and will replace
    this function's BODY (not its call site in auth.py) with actual email
    delivery. Deliberately a no-op today: no delivery channel exists yet.
    This is the ONLY function in the codebase that is allowed to receive a
    raw OTP value outside of generation (_generate_otp) and hashing
    (security.hash_otp) -- never print/log `otp` from anywhere else."""
    return None
```

### 5.2 Real, flagged consequence: this breaks an existing test's OTP-recovery mechanism

`obj-003-design-notes.md` §1.3 already noted the plaintext `otp` variable is "what's printed by the
(already-flagged-for-removal-in-OBJ-004) email mock" — and OBJ-003's own Phase 2 pass
(`dependency_graph.md`, `tests/api/test_otp_hashing_integration.py`) used exactly that print,
captured via `capsys`, as the **only** channel to recover a real OTP for its end-to-end
`/forgot-password` → `/verify-otp`/`/reset-password` flow (since no endpoint ever returns the OTP in
a response body, per `tests/README.md`'s own factory notes). Removing the print with no replacement
mechanism breaks that test file outright, not hypothetically — this was explicitly anticipated by
OBJ-003's qa-engineer pass as a known forward risk, not a surprise.

**Required, non-optional carry-over for `qa-engineer`'s OBJ-004 Phase 2 pass:**
`tests/api/test_otp_hashing_integration.py` must switch from `capsys`-based stdout capture to
`unittest.mock.patch("app.api.v1.endpoints.auth.notifications.send_otp_notification")` (or
equivalent), reading the real OTP from the mock's call arguments instead. Flagging prominently here
so it lands in Phase 2 planning, not discovered as a surprise regression during Phase 3.

### 5.3 Open decision (Gate 1) — is the minimal seam function in scope for OBJ-004, or blocked on
OBJ-005?

| Option | Behavior | Pro | Con |
|---|---|---|---|
| **A — add the minimal no-op seam now (recommended, shown above)** | `send_otp_notification` exists as a monkeypatchable single function boundary; body is a no-op until OBJ-005 | Directly satisfies finding #10's fix text ("eliminar el print antes de producción"); gives `qa-engineer` a clean, stable seam instead of stdout-scraping; OBJ-005 later replaces only the function body, not any call site | Technically a sliver of scope beyond "just remove the print" — introduces one new file |
| **B — remove the print with no replacement, accept the test breakage until OBJ-005** | `forgot_password` simply stops delivering the OTP anywhere | Zero new code | Leaves a known-broken test in the suite for an indefinite period (OBJ-005 is not next in the dependency graph's queue); violates this project's own established practice of not landing known regressions without a tracked, immediate fix |
| **C — leave the print in place, defer removal entirely to OBJ-005** | No change to `auth.py` | No test breakage | Directly contradicts finding #10's explicit remediation text and the task's explicit instruction to design this removal now |

**Recommendation: Option A.** This isn't a deep architecture decision (the "how" of testability
seams is normally left to `developer`'s discretion, per this project's established pattern for
OBJ-001's rate-limiter storage shape) — flagging it at Gate 1 anyway because it has a concrete,
required knock-on effect on `qa-engineer`'s OBJ-004 Phase 2 scope that shouldn't be decided
silently.

---

## 6. `client_ip()` `X-Forwarded-For` fix (OBJ-001 Gate 3 backlog, MEDIUM)

**Evidence:** `app/core/rate_limit.py:65-72` — `client_ip()` returns `request.client.host`
unconditionally, with no `X-Forwarded-For` awareness at all. security-specialist's OBJ-001 Gate 3
finding: *"behind any reverse proxy/LB (this template's actual target deployment shape), the IP
dimension of rate limiting collapses to a constant"* — every request appears to originate from the
proxy's own address, so the per-IP rate limit effectively becomes a *global* limit shared by every
real client behind that proxy (one abusive client can exhaust the budget for everyone else, and
per-attacker rate limiting stops working entirely).

### 6.1 Why blind trust of `X-Forwarded-For` is itself dangerous (the task's own framing)

`X-Forwarded-For` is a request header — if the app trusted it unconditionally with no reverse proxy
in front, any client could set `X-Forwarded-For: 1.2.3.4` directly and spoof an arbitrary IP,
defeating rate limiting in the *opposite* direction (unlimited requests, each claiming a different
fake source). The fix must trust *only* the hop(s) actually appended by infrastructure the operator
controls, never anything a client could have prepended.

### 6.2 Mechanism: `TRUSTED_PROXY_COUNT`-based hop selection

**Decision:** new `Settings` field `TRUSTED_PROXY_COUNT: int = 0`. `0` means "don't trust
`X-Forwarded-For` at all, use the direct socket peer" — the maximally safe default, and exactly
today's existing (unconfigured) behavior. A fork sitting behind exactly `N` trusted reverse
proxies/load balancers sets `TRUSTED_PROXY_COUNT=N`.

```python
def client_ip(request) -> str:
    trusted = settings.TRUSTED_PROXY_COUNT
    if trusted > 0:
        xff = request.headers.get("x-forwarded-for")
        if xff:
            hops = [h.strip() for h in xff.split(",") if h.strip()]
            if len(hops) >= trusted:
                # The N-th hop counting from the right is the address
                # appended by the OUTERMOST trusted proxy -- i.e. the
                # address it saw connecting to it. This is correct
                # regardless of anything a client prepends earlier in the
                # header, because each trusted proxy appends based on the
                # real TCP connection it observed, not on pre-existing
                # header content.
                return hops[-trusted]
    return request.client.host if request.client else "unknown"
```

**Why the N-th-from-the-right, not the leftmost entry:** each proxy in a forwarding chain appends
the address of whoever connected *to it* — it does not rewrite or validate anything already in the
header. So the entry appended by your own first-hop trusted proxy is trustworthy (it reflects a
real TCP connection your infrastructure observed), regardless of what an attacker prepended earlier
in the string before it ever reached that proxy. Counting from the right, skipping exactly
`TRUSTED_PROXY_COUNT` entries, always lands on that trustworthy value; counting from the left
(the naive approach) would return attacker-controlled content whenever more entries exist than
proxies actually in the chain.

**Bounds check, not a silent fallback to a wrong value:** if `len(hops) < trusted` (header has fewer
entries than the configured proxy count — a misconfiguration, or the header being stripped
somewhere upstream), the function falls back to `request.client.host` rather than indexing out of
range or trusting a too-short, ambiguous header.

**Known residual, flagged not solved (matches this project's established TOCTOU-tracking
convention):** a client sending **two** separate `X-Forwarded-For` headers (rather than one
comma-joined value) is a theoretical edge case depending on how the ASGI server/ Starlette's
`Headers.get()` merges duplicate header instances — not solved in this design, flagged as a minor
residual for a future hardening pass, same treatment as the already-tracked TOCTOU gaps from
OBJ-001/OBJ-002.

### 6.3 Open decision (Gate 1) — does this template assume it always sits behind a trusted proxy?

**This is the exact tradeoff the task instructed be routed to Gate 1, not decided unilaterally.**

| Option | Behavior | Pro | Con |
|---|---|---|---|
| **A — configurable, default 0/untrusted (recommended, shown above)** | `TRUSTED_PROXY_COUNT` defaults to `0`; a fork must explicitly opt in to trusting `X-Forwarded-For`, and says exactly how many hops | Correct and safe for every deployment topology (direct-to-app testing, bare VM with no proxy, N-deep proxy chains) — a template forked into an unknown number of future deployment shapes shouldn't assume any one of them | One more `Settings` field; a fork behind a proxy that forgets to set it gets today's already-known-collapsed-rate-limiting behavior (no worse than the status quo, but no better either, until configured) |
| **B — hardcode "always trust exactly 1 proxy hop"** | `client_ip()` unconditionally reads the first `X-Forwarded-For` entry, assuming exactly one LB/reverse proxy always sits in front | Matches security-specialist's own framing of "this template's actual target deployment shape"; zero config | **Actively dangerous for any deployment without a fronting proxy** (local dev, bare EC2, docker-compose without nginx, direct-to-app testing) — the client's own spoofed header would be blindly trusted in exactly those cases, turning today's "rate limiting collapses to a constant" MEDIUM finding into a strictly worse "rate limiting is fully attacker-controlled" outcome for any fork that doesn't happen to match the assumed topology |

**Recommendation: Option A.** Option B's convenience is real but narrow (correct only for one
specific, unstated deployment assumption); Option A costs one config line and is correct for every
topology, including the "no proxy at all" case this sandbox and most local dev environments
actually are. Flagged for Gate 1 confirmation per task instructions.

---

## 7. `.env.example` wording fix for `POSTGRES_SSL_MODE=require` (OBJ-003 Gate 3 LOW finding)

**Evidence:** security-specialist's OBJ-003 Gate 3 pass (`audit-report.md`, "Gate 3 — Verificación
OBJ-003", §"Hallazgo #8"): `.env.example` documents `verify-full` and `disable` with one sentence
each but **never mentions `require` at all**, despite it being one of three valid values. Concrete
exploitation scenario given: an operator copies `.env.example`, sees `require` "activates TLS" (a
name that invites assuming it's the strong default), deploys against a Postgres whose certificate
has been substituted by a network-position attacker (transparent proxy, DNS spoofing) — the
connection encrypts fine, the app never notices, and the attacker MITMs credentials/tokens in
transit.

**Decision — fix text, replacing the current 5-line comment block:**

```
# TLS to PostgreSQL (audit finding #8). One of: disable | require | verify-full.
# "verify-full" (encrypt + verify server cert + hostname) is recommended for
# anything beyond local dev -- the only mode that protects against a
# man-in-the-middle presenting an untrusted/self-signed certificate.
# "require" encrypts the connection but does NOT verify the server's
# certificate or hostname -- it stops passive eavesdropping but is VULNERABLE
# to an active MITM attacker presenting a forged/self-signed certificate on
# the wire (e.g. a rogue transparent proxy or DNS-spoofed endpoint). Only use
# "require" as a deliberate, informed trade-off (e.g. a private network you
# already trust) -- never treat it as equivalent to "verify-full" just
# because both "enable TLS". "disable" is the explicit local/test opt-out
# (e.g. this template's own throwaway test Postgres, or a same-host/Unix-
# socket deployment where TLS doesn't apply). Required -- no default.
POSTGRES_SSL_MODE=verify-full
```

No code change — this is a documentation-only fix, confirmed non-blocking by security-specialist's
own Gate 3 verdict ("no bloqueante... es un gap de documentación operador-facing, no un defecto de
implementación"). Not routed to Gate 1 — there is no tradeoff here, just accuracy.

---

## 8. `openapi.yaml` impact

No schema, status-code, or response-shape changes anywhere in this objective — CORS, security
headers, docs-gating, and logging are all transport/framework-level concerns with no HTTP body
surface; the `client_ip()` fix changes rate-limiting *behavior* (which IP bucket), not the `429`
response contract already documented in `components/responses/RateLimited`. Updated:

- **`info.version`** bumped to `0.5.0-obj-004`; **`info.description`** gains a short pointer to
  this document, covering CORS/security-headers/docs-gating/audit-logging/`X-Forwarded-For` as
  non-HTTP-surface, config/middleware-level concerns.
- **`/auth/forgot-password`** description gains a note that OTP delivery goes through a temporary
  placeholder seam (`app/core/notifications.py`, §5) pending OBJ-005's real email-sender
  abstraction — informational, no request/response shape change.
- **`/auth/logout`**, **`/auth/refresh`**, **`/auth/login`**: description gains a one-line note that
  these endpoints now emit structured audit-log events (§4) — informational only, not a contract
  change (nothing about the HTTP response changes; the audit log is a server-side side effect).
- No changes to any `components/schemas` — none of this objective's changes touch a request/response
  body shape.

---

## 9. Open decisions needing Gate 1 confirmation

1. **CORS default origins policy (§1.6)** — Option A (`BACKEND_CORS_ORIGINS` defaults to `[]`,
   safe-closed, recommended) vs. Option B (required, no default, matching `POSTGRES_SSL_MODE`'s
   ceremony without closing any gap the empty default doesn't already close).
2. **CSP scope for `/docs`/`/redoc` (§2.5)** — Option A (scoped exemption allowing the known
   Swagger/ReDoc CDN origins, recommended) vs. Option B (strict CSP everywhere, breaks default docs
   rendering unless assets are self-hosted).
3. **OTP delivery interim seam (§5.3)** — Option A (add a minimal monkeypatchable no-op
   `send_otp_notification` now, recommended, with a required `qa-engineer` test-file update) vs.
   Option B/C (no replacement / defer to OBJ-005, both rejected in this pass's analysis but
   included for completeness).
4. **`X-Forwarded-For` trust model (§6.3)** — Option A (`TRUSTED_PROXY_COUNT`, configurable, default
   `0`/untrusted, recommended) vs. Option B (hardcode "always trust exactly 1 proxy hop," dangerous
   for any fork without a fronting reverse proxy).

None of these block `qa-engineer`'s Phase 2 pass from starting on the *other* findings in this
objective — each open item affects which of two already-fully-specified mechanisms lands, not
whether a mechanism exists at all. Items 5 (`ENVIRONMENT` field shape) and 7 (`.env.example`
wording) are decided in this pass, following established precedent, not fresh tradeoffs.
