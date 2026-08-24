# OBJ-001 — Test Report (qa-engineer)

**Summary:** 39 red-phase tests (7 files, `tests/unit/` + `tests/api/`) covering all 21 Gherkin
scenarios in `docs/requirements/obj-001-critical-auth-hardening.md`, verified against
`docs/api/openapi.yaml`/`obj-001-design-notes.md`. Gate 3 verdict: **PASS** (independently
reproduced by qa-engineer, unanimous with security-specialist/database-architect). Final suite:
49/49 green, no regressions, no mocked shortcuts.

## Phase 2 (red phase) — 2026-08-21

Files: `tests/unit/test_security.py`, `test_secret_key_startup.py`, `test_otp_generation.py`,
`tests/api/test_token_type_enforcement.py`, `test_me_endpoint.py`, `test_otp_lockout.py`,
`test_rate_limit.py`, `test_otp_resend_cooldown.py`. Verified against a throwaway self-provisioned
Postgres 16 (`initdb`/`pg_ctl`, port 5433 — this project has no Docker; standard pattern reused by
every subsequent objective). **39 failed, 10 passed** — every failure traced to a specific missing
OBJ-001 piece (no `type` JWT claim, wrong `/auth/refresh` status codes, `/auth/me` 404, no OTP
lockout, no rate limiting, `random`-based OTP, no `SECRET_KEY` validation); the 10 passes are
regression guards for already-correct pre-OBJ-001 behavior. No broken-test failures (import/fixture
errors).

Out of scope (documented in `tests/README.md`): Scenario 2.6 (timing side-channel, BA marked
best-effort), Scenario 3.8 (SECRET_KEY rotation, mechanism undecided), true concurrent/TOCTOU
testing for Scenario 2.7 (exercised sequentially).

Risk flagged for developer (confirmed non-issue in Phase 3): `test_rate_limit.py` assumes the rate
limiter shares the app's overridable `deps.get_db` session — a separate engine would surface as a
raw DB error instead of a clean assertion.

**Gate 2: APPROVED 2026-08-21.**

## Gate 3 verification (qa-engineer, 2026-08-21) — Verdict: PASS

- Reproduced independently: two foreground runs, **49 passed, 0 failed** both times, ~35s each, no
  flakiness — matches developer's reported count.
- Read all 39 red-phase tests against the actual diff, not just green/red: confirmed real
  status-code-transition assertions (e.g. exact 5-attempt lockout boundary, shared attempts budget
  across `/verify-otp` + `/reset-password`), real JWTs built directly with `python-jose` (including
  wrong-secret and missing-`type`-claim cases) rather than only app-minted tokens,
  `test_secret_key_startup.py` genuinely spawns a subprocess per case (`sys.executable -c "import
  app.core.config"`) to prove the module-level Pydantic singleton raises at import time — none of
  the 39 mock the code path under test.
- Implementation vs. `openapi.yaml` read line by line: `/auth/refresh`/`/auth/me` 401 on any
  token-validity failure; `/auth/refresh`'s "valid token, inactive user" branch correctly stays 400
  (business-state, not credential validation); no rotation yet (correctly OBJ-002 scope); `429`
  responses carry `Retry-After`; rate limit is checked before `_check_and_consume_otp` so a
  rate-limited request never burns the OTP attempt budget; `forgot_password`'s rate limit fires
  before the user-existence check (no new enumeration oracle).
- Two design-deviation edge cases evaluated, no test gaps requiring new tests, but flagged as
  residual (non-blocking, tracked toward OBJ-006's concurrency-hardening backlog):
  1. OTP lockout (`expires_at = now()` on lockout, not delete) has no `SELECT ... FOR UPDATE` —
     `_check_and_consume_otp`'s plain SELECT-then-UPDATE (`auth.py:58-77`) could theoretically let a
     concurrent correct-code guess succeed on a stale pre-lockout read. Same TOCTOU class already
     out-of-scope per Scenario 2.7.
  2. Rate limiter's `SELECT COUNT(...)` then `INSERT` (`rate_limit.py:42-62`) is not atomic —
     concurrent requests at the boundary could both pass, producing a bounded one-request overshoot
     per burst. Not a fixed-window edge case (the sliding-window design is actually immune to that
     class of bypass) — this is a different, lower-severity TOCTOU shape. `rate_limit_hits`
     unbounded growth (no cleanup) confirmed via grep — tracked into OBJ-006.
- Regression check: full 49/49 confirms all 10 pre-existing passes hold; `register`/`login`
  untouched by the diff, no behavior change visible.

**Conclusion:** PASS. Two flagged concurrency edge cases + unbounded `rate_limit_hits` growth are
real but non-blocking — tracked, not reopened.
