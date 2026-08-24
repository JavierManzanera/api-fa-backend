# OBJ-004 — Test Report (qa-engineer)

**Summary:** 79 new tests (9 files) covering all 6 task items (CORS, security headers,
`ENVIRONMENT`-gated docs, structured audit logging, OTP debug-print removal, `X-Forwarded-For`
client IP) against `docs/api/obj-004-design-notes.md` — no business-analyst Gherkin doc for this
infra/security objective, scenarios derived directly from design decisions per each file's own
docstring (same convention as OBJ-003). **Gate 2: awaiting user approval.**

**Environment blocker independently confirmed during this pass** (matches OBJ-006's identical
finding, cross-checked, not a regression from this pass): `import greenlet` fails with
`ImportError: DLL load failed... An Application Control policy has blocked this file` —
100% reproducible (4 fresh-process attempts, including after a forced reinstall, ruling out a
corrupted single file). Blocks every SQLAlchemy `AsyncSession`/`AsyncEngine` operation project-wide
— both 61 of the 118 pre-existing tests (`tests/api/**`) and 32 of this pass's own 79 new tests.
Not routed around (OS-level policy, not something to bypass from a session). **Whoever picks up
Phase 3 must confirm `import greenlet` works before claiming any DB-backed test green.**

## Phase 2 (red phase) — 2026-08-24

- `tests/unit/test_cors_settings.py` (8) + `tests/api/test_cors_middleware.py` (8) — item 1.
  Settings-parsing half (empty default, comma-separated parsing, wildcard/schemeless rejection) vs.
  HTTP-behavior half (default-closed; configured-origin/trailing-slash-fix/credentials/
  expose-headers/methods/headers, via a subprocess-spawned fresh app since `Settings`/`app.main.app`
  are import-time singletons).
- `tests/api/test_security_headers.py` (11) — item 2. HSTS/X-Frame-Options/nosniff, strict CSP on
  ordinary JSON responses, the Gate-1-approved scoped CSP exemption on `/docs`/`/redoc`, and that
  `/openapi.json` gets the strict CSP (not the exemption) — the design notes' own explicit
  easy-to-miss case.
- `tests/unit/test_environment_settings.py` (12) + `tests/api/test_docs_gating.py` (3) — item 3.
  Required-no-default + exact-lowercase enum (case-variants rejected) vs. `/docs`/`/redoc`/
  `/openapi.json` 200 in dev/staging, 404 in production (subprocess, same singleton constraint).
- `tests/api/test_audit_logging.py` (16) — item 4. One class per catalog event (all 12), asserting
  the event fires with correct documented fields, and the 3 WARNING-level events (lockout,
  reuse_detected, rate_limit_exceeded) are genuinely at WARNING. Plus
  `TestNoRawSecretsInAnyLogRecord` — drives a full register→login→forgot-password→verify-otp→
  reset-password→refresh→reuse→logout flow with REAL secret values and asserts none appear as a
  substring in any captured log record, any logger. Out of scope (noted in-file): only the
  `no_session` branch of `auth.refresh.failure`'s 4 `reason` values is independently tested.
- `tests/unit/test_otp_debug_print_removed.py` (5) — item 5. No `print(`/`[EMAIL MOCK]` banner
  anywhere in `auth.py`; `app.core.notifications.send_otp_notification` exists with the documented
  no-op signature; `/forgot-password` actually calls it with the real OTP.
- **Required carry-over**: `test_otp_hashing_integration.py` rewritten to recover the OTP via
  `mock.patch("app.api.v1.endpoints.auth.notifications.send_otp_notification")` instead of `capsys`
  (the print it relied on is now gone) — same 5 tests/assertions, only the recovery mechanism
  changed.
- `tests/unit/test_client_ip.py` (13) + `tests/api/test_rate_limit_ip_spoofing.py` (3) — item 6.
  Pure-function unit tests (`TRUSTED_PROXY_COUNT=0` ignores XFF entirely, correct N-th-from-right
  hop selection, bounds-check fallback, `request.client is None`) + HTTP-level anti-bypass proof
  that a spoofed XFF can't reset/split the `/forgot-password` rate-limit budget at
  `TRUSTED_PROXY_COUNT=0`.
- Required conftest fix: `ENVIRONMENT=development` added to the bootstrap. Proactive carry-overs
  (same convention as OBJ-003's `POSTGRES_SSL_MODE` fix): `test_secret_key_startup.py` and
  `test_postgres_ssl_mode_startup.py` both got `"ENVIRONMENT": "development"` added to
  `BASE_ENV_FIELDS`, to avoid masking their real assertions once the new required field lands.

### Verification and exact counts

Full suite: **37 failed, 67 passed, 93 errors** (197 total = 118 pre-existing + 79 new). All 93
errors carry the identical `greenlet` traceback (verified programmatically) — 61 pre-existing +
32 new, none a distinct code-level failure hiding behind the noise. **Not a regression**: none of
the 61 previously-green tests' code paths were touched by this pass (only conftest/env-bootstrap
and two `BASE_ENV_FIELDS` edits), and the identical traceback appears for both an old test
(`test_me_endpoint.py`) and a new one (`test_security_headers.py`).

**Of the 79 new tests (excluding the 32 blocked): 37 genuinely red** (spot-checked:
`AttributeError` for `Settings.TRUSTED_PROXY_COUNT`, `ImportError` for `app.core.notifications`,
plain assertion failures for missing headers, a `405` where a CORS preflight should succeed,
the print/banner still present). **10 pass vacuously**, flagged explicitly (same convention as
`test_postgres_ssl_mode_startup.py`'s forward-looking anchors): `TestValidEnvironmentsPermitStartup`
(3, `ENVIRONMENT` doesn't exist yet), `TestWildcardAndMalformedOriginsBlockStartup` (3, fails for
the wrong reason — an `AttributeError` on the missing field, not `AnyHttpUrl` correctly rejecting
`"*"`), `TestDocsReachableInDevelopmentAndStaging` (2, docs are unconditionally reachable today,
not because gating correctly permits them), two CORS-middleware tests that vacuously pass because
no `CORSMiddleware` is installed at all yet. **32 blocked** by the greenlet issue. 37+10+32=79 ✓.
Baseline: 118 pre-existing = 61 blocked (all DB-backed) + 57 unaffected, all 57 confirmed still
green, zero regressions (118−61=57, matches 67 passed − 10 vacuous = 57). 37+67+93=197=118+79 ✓.

### Out of scope
Direct execution of the 32 blocked new + 61 blocked baseline tests (environment-blocked, not a
scope decision — required before Gate 3 can be met, this pass's counts don't substitute for it);
`auth.refresh.failure`'s 3 untested `reason` values; `TrustedHostMiddleware`/`ALLOWED_HOSTS`/
`LOG_LEVEL` beyond the default-preserves-today's-behavior check (not in the task's 6 items).

### Risks flagged for developer
1. Confirm `import greenlet` works before starting Phase 3 — the single biggest risk to this Gate.
2. Patch-target coupling: `test_otp_hashing_integration.py`/`test_otp_debug_print_removed.py`/
   `test_audit_logging.py`'s no-raw-secrets test all patch
   `app.api.v1.endpoints.auth.notifications.send_otp_notification` — update if a different import
   style is used; not a behavioral regression on its own.
3. `client_ip()` testability assumption: `TRUSTED_PROXY_COUNT` must be read as a live
   `settings.TRUSTED_PROXY_COUNT` attribute at call time, not captured at import time.
4. Field-name coupling in `test_audit_logging.py` — every asserted field name is taken verbatim
   from design notes §4.2's catalog table.
5. CORS/docs-gating HTTP tests use a subprocess-spawned app, not the shared `client` fixture —
   necessary (import-time singletons), confirmed safe since none touch the database.
6. The 10 vacuous passes above are not proof the mechanism works yet — expected to flip to
   passing-for-the-right-reason once implemented, no test-file edits needed.

**Gate 2: awaiting user approval.**
