# OBJ-004 — Test Report (qa-engineer)

**Summary:** 79 new tests (9 files) covering all 6 task items (CORS, security headers,
`ENVIRONMENT`-gated docs, structured audit logging, OTP debug-print removal, `X-Forwarded-For`
client IP) against `docs/api/obj-004-design-notes.md` — no business-analyst Gherkin doc for this
infra/security objective, scenarios derived directly from design decisions per each file's own
docstring (same convention as OBJ-003). **Gate 3: PASS (2026-08-25)** — full suite independently
re-run: 40 failed / 204 passed / 244 total, exactly matching developer's self-report; the 40
failures are precisely the pre-existing OBJ-005 red-phase files (untouched); all previously-vacuous
OBJ-004 tests (CORS middleware, docs-gating, wildcard-blocks-startup) now pass for the right
reason; spot-checked assertions (HSTS/CSP, OTP-lockout WARNING level, CORS empty-default) are
meaningful, not rubber-stamped. No regressions. See "Phase 3 (Gate 3 verification)" below for
full detail.

### Jump-to-index
- "Phase 2 (red phase) — 2026-08-24" (line 18): original red-phase authoring, 79 new tests, 9
  files, environment blocker (greenlet) and its impact on counts at that time.
- "Phase 3 (Gate 3 verification) — 2026-08-25" (bottom): independent re-run confirming
  developer's self-report, spot-checks of test intent vs. design notes, CORS
  `NoDecode`/`Annotated` deviation check, final PASS verdict.

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

## Phase 3 (Gate 3 verification) — 2026-08-25

Independent verification of `developer`'s Phase 3 implementation, per this project's "confirm via
disk/execution, don't just trust the self-report" discipline. Environment: disposable PostgreSQL
16 at `localhost:5433` (test/test/api_fa_test), already running, reachable, untouched (shared with
the parallel `security-specialist` dispatch). `import greenlet` confirmed working (3.5.5) — the
Phase 2 blocker (Windows Application Control DLL block) is resolved as of today, not recurring.

### What changed (per `git diff --stat`)
Modified: `app/api/v1/endpoints/auth.py` (+104/-…), `app/core/config.py` (+65), `app/core/rate_limit.py`
(+33), `app/main.py` (+46). New: `app/core/security_headers.py`, `app/core/audit_log.py`,
`app/core/notifications.py`. Matches the file set named in the dispatch and the 6 task items in the
design notes (CORS, security headers, ENVIRONMENT-gated docs, audit logging, OTP print removal,
XFF client IP).

### Full-suite run (`python -m pytest -q`, foreground, from repo root)
**40 failed, 204 passed, 244 total in 90.81s.** Exactly matches developer's self-reported
109→40 failed / 135→204 passed. (Total rose from 197 in the Phase 2 partial run to 244 here because
the greenlet blocker that hid 93 tests behind a single traceback in Phase 2 is gone — every test now
actually executes instead of erroring at collection/fixture time.)

### Failure-set identity check
All 40 failures map 1:1 onto the 6 pre-existing OBJ-005 red-phase files named in the dispatch, and
nothing else:
- `tests/api/test_login_refresh_verification_enforcement.py` — 3
- `tests/api/test_register_email_verification.py` — 5
- `tests/api/test_resend_verification_email.py` — 8
- `tests/api/test_verification_purpose_isolation.py` — 3
- `tests/api/test_verify_email.py` — 9
- `tests/unit/test_email_sender.py` — 12

3+5+8+3+9+12 = 40. Every failure traces to OBJ-005 surface not yet implemented (`Settings` has no
`EMAIL_PROVIDER`/`EMAIL_FROM`, `app.core.email` module doesn't exist yet, etc.) — confirmed by
reading the tracebacks, not just the file names. **Zero failures outside this set** — no
regression introduced by the OBJ-004 implementation.

### Spot-checks: test intent vs. design notes (not just pass/fail)
1. **`tests/api/test_security_headers.py`** (`TestHstsHeader`, `TestContentSecurityPolicyHeader`)
   vs. design notes §2 — confirmed meaningful: `test_hsts_does_not_include_preload` locks in the
   deliberate no-`preload` decision (§2.1); `test_openapi_json_gets_strict_csp_not_docs_csp` guards
   the one easy-to-miss case the design notes call out by name (`/openapi.json` must NOT get the
   `/docs`/`/redoc` CDN-permissive CSP even though it's "docs-adjacent"); `test_docs_csp_still_restricts_frame_ancestors`
   confirms the CDN exemption is scoped, not a blanket loosening. All read as targeted, not
   tautological.
2. **`tests/api/test_audit_logging.py::TestOtpLockoutEvent`** vs. design notes §4.2 — genuinely
   non-trivial: `test_fifth_wrong_guess_logs_lockout_warning` first asserts the WARNING event does
   **not** fire on attempts 1-4 (`_audit_events(caplog, "auth.otp.lockout") == []`), then asserts it
   fires on exactly the 5th at `WARNING` level with the right `email` field. This is a real
   boundary-condition test, not a rubber stamp. `app/core/audit_log.py`'s actual implementation
   (`log_auth_event`, stdlib `logging` + JSON payload, `_logger.log(level, ...)`) matches the design
   notes' illustrative code verbatim.
3. **`tests/unit/test_cors_settings.py`** vs. design notes §1.1/§1.6 (Gate 1 Option A) — confirmed
   the empty-default-is-safe decision survived implementation: `TestDefaultIsEmptyList::test_unset_defaults_to_empty_list`
   passed in the full run (not in the 40 failures), independently proving `BACKEND_CORS_ORIGINS`
   is `[]` when unset. `TestWildcardAndMalformedOriginsBlockStartup` (previously flagged vacuous in
   Phase 2, since the field didn't exist) now also passes — re-ran this class plus
   `test_cors_middleware.py`/`test_docs_gating.py`/`test_environment_settings.py`/
   `test_client_ip.py`/`test_rate_limit_ip_spoofing.py` in isolation (63 tests) to confirm none are
   passing for a leftover-vacuous reason: **63/63 passed**, all previously-vacuous cases now exercise
   real behavior (a `CORSMiddleware` is actually installed, `/docs` is actually 404 in production,
   `"*"` actually fails `Settings()` construction).

### CORS `Annotated[List[AnyHttpUrl], NoDecode]` deviation — does NOT weaken Gate 1's safe-default
`developer` added `NoDecode` (from `pydantic_settings`) to `BACKEND_CORS_ORIGINS`, not present in
the design notes' illustrative snippet. Read `app/core/config.py`: the field is declared
`Annotated[List[AnyHttpUrl], NoDecode] = []` — default is still the empty list literal, and the
`@field_validator(..., mode="before")` comma-split logic is unchanged and still runs. `NoDecode`
only opts the field out of pydantic-settings' default behavior of JSON-decoding complex-typed env
values *before* the custom validator gets a chance to run — without it, a comma-separated
(non-JSON) string would raise `SettingsError` before `assemble_cors_origins` ever executes. This is
a mechanical fix for how pydantic-settings v2 parses `List[...]`-typed env vars, not a security
posture change. Independently confirmed via test, not just code-reading:
`test_unset_defaults_to_empty_list` (empty env → `[]`) and `TestWildcardAndMalformedOriginsBlockStartup`
(literal `"*"` and a schemeless host both still fail `Settings()` construction) both pass. Gate 1's
"empty list is a safe default, `*` cannot be expressed" decision is intact.

### Verdict
**PASS.** Counts match developer's self-report exactly, failure set is exactly the expected
pre-existing OBJ-005 scope with zero unexplained regressions, spot-checked assertions are
substantive, and the one implementation deviation from the design notes (`NoDecode`) is a
non-weakening technical necessity, confirmed by both reading and independent test execution.

### Out of scope for this pass
Did not re-derive or re-review the 40 failing OBJ-005 tests' own correctness (that's OBJ-005's own
red-phase report, `docs/testing/obj-005-test-report.md` if/when it exists) — only confirmed they are
the same byte-identical pre-existing set, unaffected by this objective's changes.

### Risks / flakiness notes
None observed. Full suite ran deterministically in 90.81s against the real Postgres instance; no
timing-sensitive or order-dependent failures seen. The subprocess-spawned tests (CORS/docs-gating/
environment settings) remain a known environment cost (~30s of the runtime) but are necessary per
Phase 2's singleton-config rationale, not a new risk.
