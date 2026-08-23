# api-fa-backend (PRJ-003) — Objective Dependency Graph

Project: PRJ-003 (`projects/api-fa-backend`). Execution mode: **Semi-Auto** (3 gates per objective,
per CLAUDE.md). Type: backend-only reusable auth service — no `uiux-designer`/Pencil deliverable
in any objective's Phase 1 gate (no UI of its own).

**Goal:** turn the cloned FastAPI auth starter into a hardened, fully-tested reference block that
other projects can fork with confidence ("bloque hiperseguro").

**Tech stack (inherited from existing code, not re-litigated):** FastAPI, SQLAlchemy 2.0 async +
PostgreSQL/asyncpg, JWT via python-jose, passlib[bcrypt], Pydantic v2.

## Phase 0 — Retroactive discovery: Done (2026-08-21)

Before this graph existed, the repo was audited as-is (it predates this workflow — cloned with
code already in place, not built objective-by-objective). Artifacts, reusable as Phase 1 inputs
for the objectives below instead of being re-derived:
- `docs/security/audit-report.md` — full SAST/threat-model-equivalent audit (14 findings: 2
  Critical, 2 High, 6 Medium, 4 Low) by `security-specialist`.
- `docs/test-gap-analysis.md` — test coverage gap analysis (current coverage: 0%) by `qa-engineer`.

Every objective below traces back to specific findings in those two files instead of restating
them — read the finding number cited, don't take the one-line summary here as the full spec.

## Graph

```
[OBJ-000] Test Infrastructure Bootstrap
   ├── [OBJ-001] Critical Auth Hardening (CRITICAL)
   │      ├── [OBJ-002] Session & Token Lifecycle (HIGH)
   │      └── [OBJ-003] Data & Transport Hardening (MEDIUM)
   ├── [OBJ-004] HTTP Security Baseline (MEDIUM)
   ├── [OBJ-005] Email Verification Flow (MEDIUM)
   └── [OBJ-006] Migrations & Supply Chain Hardening (LOW)

[OBJ-007] Registration Enumeration Policy Decision (LOW) — blocked on a product decision from
the user, not on any other objective's code. See its row below.
```

## Active Objectives Status

| ID | Description | Assigned Agent(s) | Status | Dependencies | Traces to |
|---|---|---|---|---|---|
| OBJ-000 | pytest + pytest-asyncio + httpx AsyncClient + test-DB override of `get_db` + user factory | qa-engineer | **Done (2026-08-21)** | None | test-gap-analysis.md §"Infraestructura base" |
| OBJ-001 | Fix JWT type confusion (refresh usable as access token); OTP: `secrets`-based generation + attempt lockout + rate limiting; `SECRET_KEY` min-length/placeholder validation | business-analyst → solution-architect ∥ security-specialist → qa-engineer → developer | **CLOSED (2026-08-21) — Gate 3 unanimous PASS (qa-engineer, security-specialist, database-architect)** | OBJ-000 | audit-report.md #1, #2, #4 |
| OBJ-002 | `/logout` + revocation store; refresh-token rotation + reuse detection; `token_version` invalidation on password reset | business-analyst → solution-architect → qa-engineer → developer | **CLOSED (2026-08-23) — Gate 3 unanimous PASS (qa-engineer, security-specialist, database-architect)** | OBJ-001 (done) | audit-report.md #3 |
| OBJ-003 | Hash OTP at rest (HMAC); enforce TLS to PostgreSQL; constant-time login/forgot-password (timing side-channel) | solution-architect → database-architect ∥ qa-engineer → developer | Not Started | OBJ-001 (done) | audit-report.md #5, #7, #8 |
| OBJ-004 | CORS middleware; security headers (HSTS/X-Frame-Options/CSP/nosniff); gate `/docs`+`/redoc`+`/openapi.json` by `ENVIRONMENT`; structured auth-event logging; remove OTP debug `print`; **+backlog: rate limiter's `client_ip()` needs `X-Forwarded-For`/proxy support (MEDIUM, from OBJ-001 Gate 3)** | solution-architect → qa-engineer → developer | Not Started | OBJ-000 | audit-report.md #9, #10, #13 |
| OBJ-005 | Real `/verify-email` flow; enforce `is_verified` at login (policy: block or warn — confirm with user at this objective's gate 1); pluggable email-sender abstraction replacing the `print` mock | business-analyst → solution-architect → qa-engineer → developer | Not Started | OBJ-000 | audit-report.md #11 |
| OBJ-006 | Replace `Base.metadata.create_all` with real Alembic migrations; pin `requirements.txt` + lockfile; `pip-audit`/`safety` in CI; separate DB roles (DDL vs. DML); **+backlog from OBJ-001 Gate 3: scheduled cleanup job for `rate_limit_hits` (unbounded growth, LOW), composite index `(email, purpose, expires_at)` on `verifications`, row-locking/atomic-UPDATE hardening for the OTP-lockout and rate-limit TOCTOU gaps (LOW, bounded overshoot only)**; **+backlog from OBJ-002 Gate 3: scheduled cleanup job for `refresh_sessions` (unbounded growth, LOW — retention floor must be ≥ `REFRESH_TOKEN_EXPIRE_DAYS`, not a short window like `rate_limit_hits`'s, to preserve reuse-detection integrity), explicit `ON DELETE CASCADE`/`ON DELETE SET NULL` FK behavior for `refresh_sessions.user_id`/`replaced_by` (currently undeclared, defaults to NO ACTION — must land before the cleanup job or purges will hit FK violations), composite index `(family_id, revoked_at)` on `refresh_sessions` (LOW, optional)** | database-architect → devops-engineer | Not Started | OBJ-000 | audit-report.md #12, #14 |
| OBJ-007 | Decide `/register` enumeration behavior: keep explicit "email exists" (documented accepted risk) vs. generic response matching `/forgot-password`'s pattern | **user decision required**, then developer | Not Started | None (blocked on product decision, not code) | audit-report.md #6 |

## OBJ-001 — Phase 1 deliverables (2026-08-21)

- `docs/requirements/obj-001-critical-auth-hardening.md` (business-analyst) — 3 user stories, 21
  Gherkin scenarios covering findings #1, #2, #4.
- `docs/api/openapi.yaml` (solution-architect) — full spec (all 6 existing endpoints + proposed
  new `GET /auth/me`), validated against OpenAPI 3.1. `Token` schema now documents an explicit
  `type: access|refresh` claim (closes #1); `/auth/refresh` returns 401 (was 400) on invalid
  type/signature; `forgot-password`/`verify-otp`/`reset-password` gain a `429` rate-limit
  response; OTP attempt-lockout reuses the existing generic `400` (no new oracle).
- `docs/api/obj-001-design-notes.md` (solution-architect) — JWT claim schema, rate-limit (IP,
  infra concern) vs. OTP lockout (shared `attempts` counter on the `Verification` row, business
  concern) split, `SECRET_KEY` startup-validation contract (non-HTTP).
- **Schema change surfaced**: the lockout design adds an `attempts` counter column to
  `Verification` — a DB model change that Gate 1 nominally wants a `database-architect` pass on,
  but OBJ-006 (real Alembic migrations) hasn't landed yet, so today this still lands via
  `Base.metadata.create_all` like every other column. Not a blocker, just flagging the ordering
  wrinkle: OBJ-001's migration today is informal; it becomes a real Alembic migration once OBJ-006
  exists (retrofit, not urgent — the column is additive and harmless to backfill).
- **Gate 1: APPROVED (2026-08-21).** Decisions locked in:
  - `GET /auth/me` is in scope for OBJ-001 (used to contract-test the #1 fix end-to-end).
  - OTP lockout: 5 failed attempts invalidates the code. Rate limit: 5 req/min per IP+email on
    `/forgot-password`, 10 req/min on `/verify-otp` and `/reset-password`. OTP resend cooldown:
    60s.
  - OTP format unchanged: 6 digits, 10 min TTL (the lockout+rate-limit above is what makes this
    safe now, not the code space).
  - Rate-limit/lockout state lives in a Postgres table (no Redis dependency added to the
    template).
  - JWT claim: explicit `type: "access"|"refresh"` (already settled by solution-architect,
    matched business-analyst's recommendation).
  - OBJ-001 is cleared to start Phase 2. Phase 2 needs OBJ-000 (test infra) first — dispatched
    together, same qa-engineer pass, since it's the same agent role and avoids a redundant
    context reload.

## OBJ-000 — Test Infrastructure Bootstrap: Done (2026-08-21)

Delivered by qa-engineer, same pass as OBJ-001 Phase 2 (dispatched together
per the Gate 1 note above):

- `requirements-dev.txt` (`-r requirements.txt` + `pytest==9.1.1`,
  `pytest-asyncio==1.4.0`, `httpx==0.28.1`, `freezegun==1.5.5`) — kept
  separate from `requirements.txt` per test-gap-analysis.md's own
  recommendation.
- `pytest.ini` — `asyncio_mode = auto`, `asyncio_default_fixture_loop_scope
  = session`, `asyncio_default_test_loop_scope = session` (the latter two
  are required together, not just the fixture one — a session-scoped async
  `db_engine` fixture combined with per-function test loops throws
  `RuntimeError: Future attached to a different loop` under
  pytest-asyncio 1.4; found and fixed during this pass, not theoretical).
- `docker-compose.test.yml` — disposable Postgres 16 on port 5433 (not
  5432, to avoid colliding with a developer's own local Postgres).
- `tests/conftest.py` — env-var bootstrap ordering (Settings is a
  module-level singleton depending on required, default-less env vars),
  `db_engine`/`db_session`/`client`/`api_prefix`/`user_factory`/
  `verification_factory` fixtures. `db_session` uses SQLAlchemy 2.0's
  `join_transaction_mode="create_savepoint"` for rollback-per-test
  isolation.
- `tests/factories.py` — `create_user` (real bcrypt hash via
  `security.get_password_hash`, `is_active`/`is_verified` overridable),
  `create_verification` (seeds a known OTP code directly — necessary since
  no endpoint ever returns the generated OTP in an HTTP response).
- `tests/README.md` — run instructions, verification status, scope
  boundaries, risk notes for `developer`.

**Postgres note (relevant to any future "why is Postgres access blocked"
question):** this sandbox has no Docker and no credentials for the local
Postgres 16 Windows service already running on port 5432 (two attempts to
obtain them were correctly blocked by the harness's safety classifier as
credential-discovery behavior, and were not worked around). The full test
suite was still verified end-to-end using a throwaway, self-provisioned
Postgres instance (`initdb`/`pg_ctl` from the same installed binaries, own
data dir, port 5433, torn down after use) — functionally what
`docker-compose.test.yml` automates for anyone else. See
`tests/README.md` for the full note and verification results.

## OBJ-001 — Phase 2 (red phase): Done (2026-08-21)

- 39 tests across `tests/unit/` (`test_security.py`,
  `test_secret_key_startup.py`, `test_otp_generation.py`) and `tests/api/`
  (`test_token_type_enforcement.py`, `test_me_endpoint.py`,
  `test_otp_lockout.py`, `test_rate_limit.py`,
  `test_otp_resend_cooldown.py`) translate all 21 Gherkin scenarios from
  `docs/requirements/obj-001-critical-auth-hardening.md` into executable
  tests, traced to `docs/api/openapi.yaml` and
  `docs/api/obj-001-design-notes.md`.
- Verified end-to-end against a real Postgres (see OBJ-000 note above):
  **39 failed, 10 passed.** Every failure traces to a specific missing
  piece of OBJ-001 (no `type` JWT claim, wrong status codes on
  `/auth/refresh`/`verify_refresh_token`, `/auth/me` missing entirely ->
  404, no OTP attempt lockout, no rate limiting, OTP generation still
  `random`-based, no `SECRET_KEY` startup validation). Every pass documents
  already-correct current behavior that must not regress (OTP TTL expiry,
  refresh-token-on-`/auth/refresh`, no-OTP-reuse-after-successful-reset).
  None failed for a broken-test reason (import errors, bad fixtures,
  wrong assumptions about the current contract).
- **Explicitly out of scope, documented in tests/README.md:** Scenario 2.6
  (timing side-channel — BA's own AC calls it best-effort, not strictly
  testable); Scenario 3.8 (SECRET_KEY rotation — marked TBD in the AC,
  mechanism undecided); true concurrent/TOCTOU testing for Scenario 2.7
  (exercised sequentially instead, consistent with test-gap-analysis.md's
  own flakiness note); the broader non-OBJ-001 endpoint backlog from
  test-gap-analysis.md (spans OBJ-002–OBJ-005, not re-scoped here).
- **Risk flagged to developer:** `tests/api/test_rate_limit.py` assumes
  the rate limiter persists through the same overridable `deps.get_db`
  session as the rest of the app. If implemented as a fully separate
  module-level engine/session instead, those tests will fail with a raw
  DB connection error rather than a clean assertion once the code lands —
  treat that as a testability signal, not a broken test. Full detail in
  `tests/README.md`.
- **Gate 2: APPROVED (2026-08-21).** `developer` cleared to start Phase 3
  implementation against the 39 red tests.

## OBJ-001 — Phase 3 (green phase): Done (2026-08-21, developer)

Baseline confirmed before any change: full suite run against a throwaway
self-provisioned Postgres 16 instance (same `initdb`/`pg_ctl` approach
qa-engineer used — no Docker in this sandbox either; port 5433, `trust`
auth, own data dir, torn down after use) reproduced qa-engineer's exact
**39 failed, 10 passed**. Final suite after implementation: **49 passed,
0 failed** (two consecutive full runs, no flakiness observed).

**Files touched:**
- `app/core/security.py` — `create_access_token`/`create_refresh_token` now
  set an explicit `type: "access"|"refresh"` claim (+ `iat`); legacy
  `refresh: true` claim retired. `verify_refresh_token` checks `type ==
  "refresh"` and now raises 401 (was 400) for every validity failure
  (wrong type, bad signature, expired, malformed).
- `app/api/deps.py` — `get_current_user` rejects (401) any token whose
  `type` claim isn't `"access"`, including tokens with no `type` claim at
  all (fail-closed, no legacy-token special case, per design notes).
- `app/api/v1/endpoints/auth.py` — new `GET /me` (via
  `deps.get_current_active_user`); OTP generation switched from
  `random.choices` to `secrets.choice` (CSPRNG); new
  `_check_and_consume_otp` helper shared by `/verify-otp` and
  `/reset-password` implementing the shared 5-attempt lockout budget
  (audit finding #2); `/forgot-password` gained a 60s resend cooldown
  (checked against ANY existing row for the email+purpose, live or
  locked/expired — deliberate, closes the "immediately re-request after
  lockout to reset budget" gap the design notes called out); all three
  OTP-adjacent endpoints call the new rate limiter first.
- `app/core/rate_limit.py` (new) — sliding-window rate limiter
  (`enforce_rate_limit`), Postgres-table backed, takes the caller's
  `AsyncSession` (the one injected via `deps.get_db`) rather than opening
  its own engine — this was a deliberate testability requirement flagged
  by qa-engineer (a separate engine would bypass the tests' DB override
  and fail with a connection error instead of a clean assertion). Confirmed
  in practice: `tests/api/test_rate_limit.py` passes cleanly.
- `app/models/rate_limit.py` (new) — `RateLimitHit` model backing the
  limiter (`scope`, `ip`, `email`, `created_at`, composite index).
  Registered in `app/models/__init__.py` so both `app/main.py`'s
  `Base.metadata.create_all` and the test suite's `db_engine` fixture
  (which imports `app.models.user`/`verification`, triggering the package
  `__init__` and therefore this model too) pick it up without needing to
  touch `tests/conftest.py`.
- `app/models/verification.py` — added `attempts` (int, default 0) for the
  shared lockout counter. Also gave `created_at` a **Python-side** default
  (`datetime.now(timezone.utc)`) alongside the existing `server_default`:
  the OTP-resend-cooldown logic needs `created_at` to respect freezegun's
  frozen time in `tests/api/test_otp_resend_cooldown.py`, and a
  Postgres-side `func.now()` would always resolve to real wall-clock time
  regardless of the test's frozen clock — this was caught and fixed during
  implementation, not a hypothetical.
- `app/core/config.py` — `SECRET_KEY` field validator rejects (raises,
  blocking import/startup) any value under 32 chars or matching a
  case-insensitive placeholder blocklist.
- `app/main.py` — imports `app.models.rate_limit` alongside
  `user`/`verification` so its table is included in `create_all` (belt and
  suspenders with the `__init__.py` registration above).
- `.env.example` — `SECRET_KEY` comment now recommends
  `secrets.token_urlsafe(64)` and documents the 32-char/placeholder
  startup gate.
- No new entries in `requirements.txt` — `secrets` is stdlib; no new
  runtime dependency was needed for the Postgres-table rate limiter/lockout
  approach.

**Design deviations from `obj-001-design-notes.md`, decided independently
(design doc explicitly left these as open implementation choices, not
architecture):**
- **OTP lockout invalidation mechanism**: chose "set `expires_at` to now"
  over "delete the row" (both were offered as equally valid in the design
  notes). Deleting would have broken the resend-cooldown's stated purpose
  ("stops an attacker who just got locked out from immediately requesting
  a fresh row to reset their budget") — with delete, no row would remain
  for the cooldown check to find. Keeping the row (marked expired) lets one
  `created_at`-based cooldown check serve both the "still live" and
  "already locked/expired" cases uniformly.
- **Rate limiter storage shape**: a single `rate_limit_hits` table with one
  row per accepted request (sliding window via `COUNT(...) WHERE created_at
  > now - window`), rather than a per-key counter+window-start row. Simpler
  to reason about and to keep consistent with the freezegun-safety
  requirement (explicit Python-side timestamps throughout, no server-side
  `now()` reliance anywhere in the rate-limit path); accepted the modest
  extra row growth since the design notes flagged this as a "developer
  finds simpler" choice, not a fixed contract.
- **Rate-limit/lockout thresholds**: wired as module-level constants in
  `auth.py` (`MAX_OTP_ATTEMPTS = 5`, `OTP_RESEND_COOLDOWN_SECONDS = 60`,
  `FORGOT_PASSWORD_RATE_LIMIT_PER_MINUTE = 5`,
  `VERIFY_OTP_RATE_LIMIT_PER_MINUTE = 10`,
  `RESET_PASSWORD_RATE_LIMIT_PER_MINUTE = 10`), not `Settings` fields — kept
  scope minimal and matches the exact constants qa-engineer hardcoded in
  the test files (`tests/README.md` explicitly anticipated this: "if
  developer wires these to settings with different defaults, update the
  constants..." — values are unchanged from Gate 1, so no test-file update
  was needed).

**What's left for Gate 3:**
- `qa-engineer` — **DONE (2026-08-21), verdict: PASS with two flagged gaps
  (non-blocking for Gate 3, should be tracked before OBJ-002/OBJ-006
  close).** Full detail below.
- `security-specialist` — SAST/DAST pass confirming findings #1, #2, #4 are
  actually closed (not just tests passing), and a fresh look at the two
  design deviations above (particularly the "mark expired, don't delete"
  lockout choice, since it means locked-out `Verification` rows persist
  until the next successful `/forgot-password` call past the cooldown —
  worth confirming this isn't itself an unbounded-storage or info-leak
  concern).
- `database-architect` — informal review of the `attempts` column and the
  new `rate_limit_hits` table (both still land via `Base.metadata.create_all`,
  per the ordering wrinkle already flagged in this file for OBJ-006).
  **Done (2026-08-21) — see "database-architect informal schema review" below.**
- Test DB teardown note: this pass's throwaway Postgres 16 instance
  (`initdb`/`pg_ctl`, port 5433, own data dir) was stopped after the final
  verification run, same as qa-engineer's OBJ-000/Phase 2 pass.

## OBJ-001 — qa-engineer independent Gate 3 verification (2026-08-21)

**Verdict: PASS.** Independently reproduced the developer's result; the suite is substantive, not
tautological; implementation matches `docs/api/openapi.yaml`; no regressions. Two non-blocking
edge-case gaps found in the two Phase 3 design deviations (below) — recommend tracking, not
reopening Gate 3.

**1. Own suite execution (not trusting developer's report).**
Same environment constraint as prior passes (no Docker in this sandbox) — self-provisioned a
throwaway Postgres 16 via `initdb`/`pg_ctl`, port 5433, `trust` auth, own data dir outside the
repo, torn down after the run (`pg_ctl stop -m fast`, confirmed stopped). Ran the full suite
**twice, foreground, back to back**: both runs **49 passed, 0 failed**, ~35s each, no flakiness.
Matches developer's reported 49/49 exactly.

**2. Substantive vs. trivial — checked every one of the 39 red-phase tests, not just that they're
green.** Traced each to its Gherkin scenario and read the actual assertions (not just pass/fail):
- `test_otp_lockout.py` / `test_rate_limit.py`: assert real status-code transitions across a
  request-count threshold (e.g. requests 1-5 return 200, request 6 returns 429; a *correct* OTP
  is asserted to still fail 400 after 5 wrong guesses — this is the actual lockout behavior, not
  a weak "some 4xx" check), assert the exact generic error message is reused for
  wrong-code/expired/locked-out (no new oracle), assert a shared attempts budget across two
  different endpoints (`verify-otp` + `reset-password`), assert the rate limit isn't foolable by
  varying the guessed OTP.
- `test_token_type_enforcement.py`: constructs real JWTs with `python-jose` directly (including
  one signed with a wrong/guessed secret, and one with the `type` claim omitted entirely) rather
  than only exercising tokens minted by the app's own helpers — this genuinely exercises the
  fail-closed signature/claim path, not a mocked shortcut.
  `test_forged_token_with_correct_secret_but_no_type_claim_rejected` in particular is exactly
  the "no legacy-token special case" fail-closed rule from the design notes, and it passes for
  the right reason (verified `app/api/deps.py:28` rejects on `payload.get("type") !=
  TOKEN_TYPE_ACCESS`, which is `None != "access"` → True → reject).
- `test_secret_key_startup.py`: genuinely spawns a **subprocess** per case (`sys.executable -c
  "import app.core.config"`) with a controlled env and asserts the process's exit code — this is
  not mockable/tautological, it's the only way to prove a module-level Pydantic singleton
  actually raises at import time for a given `SECRET_KEY`. Confirmed the validator in
  `app/core/config.py:37-50` runs before `get_settings()`/`settings =` executes at module scope,
  so a bad `SECRET_KEY` really does prevent `app.*` from importing at all, not just some
  in-process object being unusable.
- `test_otp_generation.py`: static source-introspection (`inspect.getsource`), explicitly
  documented as deliberate (a statistical distribution test over ~100-1000 draws can't
  distinguish `random` from `secrets` at that sample size) rather than an oversight. Confirmed
  `app/api/v1/endpoints/auth.py:36` uses `secrets.choice`, and confirmed no `random.choices`/
  `random.choice(` string appears anywhere in that module.
- None of the 39 rely on mocking out the code path under test (e.g. no mocked DB session hiding
  the real query, no monkeypatched `enforce_rate_limit`/`_check_and_consume_otp`) — all go
  through the real FastAPI app via `httpx.ASGITransport` end-to-end, or (for Story 3) a real
  subprocess.

**3. Implementation vs. `docs/api/openapi.yaml` — read the diff (`app/core/security.py`,
`app/api/deps.py`, `app/api/v1/endpoints/auth.py`, `app/core/rate_limit.py`,
`app/models/rate_limit.py`, `app/models/verification.py`, `app/core/config.py`) against the spec
line by line:**
- `/auth/refresh` and `/auth/me` both 401 on any token-validity failure (bad signature, expired,
  malformed, wrong `type`) per spec; `/auth/refresh`'s "valid token, inactive user" branch stays
  400 as spec'd (business-state error, distinct from credential validation) — confirmed in
  `auth.py:258-259`.
- `/auth/refresh` correctly does **not** rotate the refresh token (`auth.py:266` echoes the
  submitted token back) — this matches the spec's explicit note that rotation is OBJ-002 scope,
  not a bug or missed requirement in this pass.
- `RateLimited` (429) responses carry `Retry-After` on all three OTP-adjacent endpoints
  (`rate_limit.py:58`), matching the spec's header contract.
- OTP lockout and rate limiting are correctly layered in the right order in each endpoint
  (`auth.py:207-213`, `226-232`): rate limit is checked *before* `_check_and_consume_otp`, so a
  rate-limited request never increments the OTP attempt counter — no double-penalty / no way to
  burn a victim's OTP budget via a flood that's supposed to be rejected at the rate-limit layer
  first.
- `forgot_password` enforces the rate limit before the user-existence check (`auth.py:142-152`),
  so rate-limiting behavior itself doesn't become a new user-enumeration side channel (existing
  vs. non-existent email get identical 429 experiences).

**4. Design-deviation edge cases (the two independent developer decisions) — evaluated for gaps
not covered by the current tests:**

- **(a) OTP lockout via `expires_at = now()` instead of row delete.** No test gap found in the
  *window-boundary* sense the task asked about — this isn't a fixed-window counter, so there's no
  "reset at minute boundary" burst-doubling risk. The real gap is storage, and it's already
  identified independently by `database-architect`'s review below (dead `Verification` rows
  persist per email across `reset_password`/`verify_email` purposes) — folding into that finding
  rather than duplicating it. One additional angle database-architect's pass didn't cover: this
  is **also a synchronization primitive**, and the current code has no row lock. `_check_and_consume_otp`
  does a plain `SELECT` then `UPDATE` (`auth.py:58-77`) with no `SELECT ... FOR UPDATE` — two
  concurrent requests (the 5th failed guess and a correct-code guess arriving in the same
  window) could both read `attempts == 4` before either commits, and the correct-code request
  could succeed based on a stale pre-lockout read. This is the same class of gap already flagged
  as out-of-scope for Scenario 2.7 (tests exercise this sequentially, not concurrently, per
  `test-gap-analysis.md`'s own flakiness note) — not a new defect, but worth being explicit that
  it also applies to the *lockout* path, not just the rate limiter. Recommend a follow-up
  concurrency-hardening pass (row locking or an atomic `UPDATE ... RETURNING`) before treating the
  lockout as airtight under real concurrent load; not a Gate 3 blocker given the documented scope
  boundary.
- **(b) Rate limiter: one row per accepted request + `COUNT(...)` sliding window, no counter+bucket.**
  On the specific question asked ("attacker hits exactly the window boundary") — this design is
  actually **more correct** than a naive fixed-window counter: because it's a true sliding window
  (`created_at > now - window_seconds`, continuously re-evaluated), there's no reset instant an
  attacker can straddle to get 2x the allowed rate (the classic fixed-window edge case). No test
  gap there. The real edge case is the same TOCTOU shape as 4(a): `enforce_rate_limit`
  (`rate_limit.py:42-62`) does `SELECT COUNT(...)` then, if under the limit, `INSERT` — not
  atomic. Concurrent requests arriving at the limit boundary could each observe
  `hits_in_window == limit - 1`, both pass, and both insert, producing a transient one-request
  overshoot per burst. Low severity (bounded overshoot, not unbounded bypass) and consistent with
  the project's already-documented stance that true concurrency/TOCTOU is out of scope for this
  pass — flagging for awareness, not blocking. **Unbounded table growth** (no cleanup of
  `rate_limit_hits`) is the other gap on this path — confirmed no `DELETE`/cleanup/TTL code
  exists anywhere in `app/` (`grep` came back empty); `database-architect`'s review below reaches
  the same conclusion independently and proposes a scheduled-cleanup remediation tracked into
  OBJ-006. Concur with that recommendation.

**5. Regression check.** Full 49/49 (not just the 39 that were red) confirms the 10
previously-passing tests (OTP TTL expiry, refresh-token-on-`/auth/refresh`, no-OTP-reuse-after-
successful-reset, etc.) still pass unchanged — no regression. Spot-checked `register`/`login`
(untouched by this diff) — no behavior changes visible in the diff or by re-reading
`auth.py:87-133`.

**Conclusion:** Gate 3 qa-engineer sign-off: **PASS**. The two flagged concurrency edge cases
(4a, 4b) and the unbounded `rate_limit_hits` growth are real but non-blocking — recommend
tracking the concurrency-hardening follow-up alongside the already-tracked cleanup-job item
(OBJ-006), not reopening this gate. Awaiting `security-specialist`'s SAST/DAST pass before OBJ-001
closes fully.

## OBJ-001 — database-architect informal schema review (Gate 3, 2026-08-21)

Informal review only (OBJ-006 real Alembic migrations not started — schema still lands via
`Base.metadata.create_all`). No files changed by this pass; findings for `developer` to pick up
in a follow-up, and for `OBJ-006` to formalize once real migrations exist.

**ER diagram (current state, both tables):**

```mermaid
erDiagram
    VERIFICATION {
        uuid id PK
        string email "indexed (single-column)"
        string code
        string purpose
        int attempts "default 0"
        timestamptz expires_at
        timestamptz created_at "python-side default + server_default"
    }
    RATE_LIMIT_HIT {
        uuid id PK
        string scope
        string ip
        string email
        timestamptz created_at "python-side only, no server_default"
    }
    USER ||--o{ VERIFICATION : "keyed by email (no FK)"
    USER ||--o{ RATE_LIMIT_HIT : "keyed by email (no FK, deliberate)"
```

No FK from either table to `users.email` — correct as-is: rate limiting and OTP lockout must
apply to unauthenticated/non-existent emails too (otherwise `/forgot-password` on an unregistered
address would be unprotected, reopening an enumeration oracle). Do not add a FK here later without
re-checking that.

### 1. `verifications.attempts`
Type/default are right: `Integer, nullable=False, default=0`. No concerns there.

Actual query pattern in `auth.py` (`_check_and_consume_otp`, lines ~58-65) is
`email == X AND purpose == Y AND expires_at > now()` — `code` is **not** in the SQL filter, it's
compared in Python after fetch. So the index question is about `(email, purpose, expires_at)`,
not `(email, code, purpose, expires_at)`.

Today there's only a single-column index on `email`. That's not currently a real hazard because
`/forgot-password` deletes-then-inserts (lines 176-180: `DELETE ... WHERE email = X AND purpose =
Y` before creating the fresh row), so live-row count per `(email, purpose)` stays effectively at 1
— Postgres will filter the small email-matched set in memory almost for free regardless of index
shape. But two things make a composite index the right move anyway, not just a nice-to-have:
- Locked-out/expired rows are **kept, not deleted** (deliberate design choice, see Phase 3 notes
  above — `expires_at` pulled to now instead of a `DELETE`). Over time, a single email can
  accumulate many dead rows across `reset_password` and `verify_email` purposes, so the "index on
  email, filter purpose+expires_at in memory" shortcut degrades as that backlog grows per address.
- It's cheap and has no downside: add a composite `Index("ix_verifications_email_purpose_expires_at", "email", "purpose", "expires_at")` and drop the redundant standalone `email` index (the composite serves any query that only filters on `email` too, leftmost-prefix).

Illustrative DDL (not applied — for `developer`/`OBJ-006` to land):
```sql
DROP INDEX IF EXISTS ix_verifications_email;
CREATE INDEX ix_verifications_email_purpose_expires_at
    ON verifications (email, purpose, expires_at);
```

Minor, unrelated to this objective's scope: `expires_at`/`created_at` are typed
`Mapped[float]` in the model but the column is `DateTime(timezone=True)` — a stale type
annotation (should be `Mapped[datetime]`), pre-existing on `expires_at`, and now copied onto the
new pattern in `RateLimitHit.created_at` too. Cosmetic (no runtime effect), but worth a cleanup
pass since it'll otherwise keep getting copy-pasted into future models.

### 2. `rate_limit_hits`
Index is correct and well-designed: `Index(..., "scope", "ip", "email", "created_at")` matches
the query shape in `enforce_rate_limit` exactly — three equality predicates followed by the one
range predicate (`created_at > window_start`), in the right left-to-right order for a B-tree to
use all four columns as a single index range scan. No table-scan risk from the query pattern
itself. Good work by `developer` here, nothing to change.

### 3. Unbounded growth risk — real, and worth acting on before production traffic
This is the one finding that actually matters. `rate_limit_hits` gets one row per **accepted**
request on three endpoints (5-10 req/min ceilings), with no delete, no TTL, and no partitioning
anywhere in the code. Every row older than the 60s window is permanently dead weight — the query
never reads it again (`created_at > window_start` excludes it forever) — but nothing removes it.
At even modest sustained traffic this is thousands of rows/day per busy deployment, growing
without bound, forever. It won't break anything functionally (the covering index keeps the hot
query fast regardless of table size for a while), but it's an unmonitored disk-growth leak and
will eventually show up as bloated autovacuum/table-scan-adjacent maintenance costs.

This was a deliberate, reasonable scope call by `developer` for OBJ-001 (design notes explicitly
left storage shape open, and the one-row-per-request approach was chosen for
freezegun/testability simplicity) — not a defect in this pass. But it needs a follow-up before
this goes to real production load. Recommendation, in order of preference for this project's
size:
1. **Scheduled cleanup job** (simplest, fits this stack): a periodic `DELETE FROM rate_limit_hits
   WHERE created_at < now() - interval '1 hour'` (window is 60s, so even 1 hour of retention is
   generous slack for clock skew/debugging) run via `pg_cron` or an app-level scheduled task
   (`devops-engineer` territory — cron/Celery-beat/APScheduler, whatever this template already
   has access to). Do **not** run this inline in the request path (`enforce_rate_limit` is on the
   hot auth path — adding a `DELETE` there adds latency and lock contention to every login-adjacent
   request for no benefit the request itself gets).
2. If traffic is expected to be high-volume in whatever downstream project forks this template:
   time-based partitioning (daily partitions, drop partitions older than a day) scales better than
   per-row deletes, but is real infra complexity — overkill for this auth-service template today,
   worth flagging as an option in `OBJ-006`'s scope rather than building now.
3. Not recommending a rewrite to a per-key counter+window-start row (bounded row count) — that was
   already considered and declined in Phase 3 for good reasons (freezegun-safety, simplicity); the
   scheduled-delete approach gets the unbounded-growth problem solved without touching the schema
   or the tested request-path code.

**Suggested tracking**: fold "add scheduled `rate_limit_hits` cleanup job" into `OBJ-006`'s scope
(`devops-engineer` + `database-architect`) rather than opening a new objective — it's
infra/maintenance, not a security-blocking issue for OBJ-001's Gate 3.

### Minor/secondary observations
- `RateLimitHit.ip` is `String`; consider Postgres native `INET` for correctness (validates
  IPv4/IPv6 shape) and slightly more compact storage. Not blocking — `String` works fine and is
  simpler if this template ever needs to store non-IP client identifiers.
- Both tables generate `id` client-side (`default=uuid.uuid4`) rather than via
  `server_default=gen_random_uuid()` — consistent with the existing `User`/`Verification`
  pattern, no objection.
- No modeling issue with `verifications.attempts` not resetting on successful `/verify-otp` (row
  isn't deleted there, only on `/reset-password`) — that's request-flow/business logic, not a
  data-model concern, and out of scope for this review.

**Gate 3 status for database-architect's piece: cleared.** No blocking data-model issues in
`attempts` or `rate_limit_hits`. One index recommendation (verifications composite index, cheap,
non-blocking) and one real but non-blocking growth-management gap (rate_limit_hits cleanup job,
tracked into OBJ-006) — neither should hold up OBJ-001's Gate 3 sign-off.

## OBJ-001 — security-specialist Gate 3 SAST verification (2026-08-21)

Full detail in `docs/security/audit-report.md` §"Gate 3 — Verificación OBJ-001". Summary:

- **#1 (refresh-as-access-token) — CERRADO.** `app/api/deps.py:28` fail-closed on `type != "access"`, including tokens with no `type` claim at all (also correctly invalidates every pre-fix legacy token).
- **#2 (OTP brute force) — CERRADO**, one documented residual: `secrets.choice` confirmed, 5-attempt lockout confirmed, lockout-vs-natural-expiry oracle confirmed indistinguishable (same 400 branch). Attempts only reset via `/forgot-password`, itself rate-limited + 60s cooldown — bounds guessing to ~50/10min, not unlimited (accepted Gate 1 tradeoff). Low-severity theoretical concurrency race noted (same TOCTOU shape qa-engineer flagged independently) — residual, not reopened.
- **#4 (SECRET_KEY unvalidated) — CERRADO.** Real `ValueError` at eager `Settings()` construction, blocks import/startup for real.
- **New MEDIUM**: `client_ip()` has no `X-Forwarded-For` support — behind any reverse proxy/LB (this template's actual target deployment shape), the IP dimension of rate limiting collapses to a constant. Tracked into OBJ-004.
- **New LOW**: `rate_limit_hits` has no TTL/purge — confirmed via grep, matches database-architect's independent finding. Tracked into OBJ-006.
- Neither new finding reopens the account-takeover chain audit-report.md originally described.

**OBJ-001 Gate 3 final verdict: PASS, unanimous across qa-engineer, security-specialist, and database-architect. Objective CLOSED.**

## OBJ-002 — Phase 1 deliverables (2026-08-21)

- `docs/requirements/obj-002-session-token-lifecycle.md` (business-analyst) — 3 user stories, 16
  Gherkin scenarios covering finding #3.
- `docs/api/openapi.yaml` (solution-architect, bumped to v0.3.0-obj-002) + `docs/api/obj-002-
  design-notes.md` — new `POST /auth/logout` (takes `refresh_token` in body, revokes just that
  `refresh_sessions` row, always `204` idempotently — no validity oracle); `/auth/refresh` now
  rotates (never echoes the submitted token back); new `refresh_sessions` table (`id`=jti PK,
  `family_id`, `user_id` FK, `issued_at`, `expires_at`, `revoked_at`, `replaced_by`) — reuse of an
  already-rotated token revokes the entire family (industry-standard rotation-with-reuse-
  detection). Access tokens gain a `ver` claim checked against `User.token_version` (piggybacked
  on the existing DB read in `get_current_user`, no extra table lookup on the hot path).
  Pre-OBJ-002 tokens (missing `jti`/`ver`) fail closed automatically, same precedent as OBJ-001's
  `type` claim.
- **Gate 1: APPROVED (2026-08-21).** Decisions locked in:
  - `/auth/logout` invalidates only the submitted session (no "logout all devices" endpoint in
    this objective's scope — backlog if needed later).
  - `/auth/reset-password` MUST bulk-revoke all of the user's active `refresh_sessions` in the
    same transaction as the `token_version` bump (this is the actual point of the objective —
    not optional).
  - Access tokens are NOT blacklisted on logout — accepted residual window up to
    `ACCESS_TOKEN_EXPIRE_MINUTES` (currently 30 min) after logout, to keep access-token
    verification stateless/table-lookup-free on the hot path. Still a massive improvement over
    today's 7-day unrevocable refresh token.
  - OBJ-002 cleared to start Phase 2 (qa-engineer red-phase tests).

## OBJ-002 — Phase 2 (red phase): Done (2026-08-21, qa-engineer)

**4 new files, 22 tests, translating all 16 Gherkin scenarios from
`docs/requirements/obj-002-session-token-lifecycle.md`** (plus a handful of
supporting/regression tests beyond the 16, same convention as OBJ-001's
Phase 2 pass) into executable tests against `docs/api/openapi.yaml`
(v0.3.0-obj-002) and `docs/api/obj-002-design-notes.md`:

- `tests/api/test_logout.py` (8 tests) — Story 1, Scenarios 1.1-1.5, plus
  multi-session isolation (task item 7) and idempotency-on-repeat. **Asserts
  the APPROVED design over the raw AC wording**: Scenarios 1.3/1.4/1.5
  (expired/malformed/missing-credentials) all resolve to the Gate-1-approved
  "always `204` for any well-formed body, `422` only for schema failure" —
  not the AC's originally-proposed `401`s. Documented inline in the file
  docstring so this isn't mistaken for a test-authoring error later.
- `tests/api/test_refresh_rotation.py` (7 tests) — Story 2, Scenarios 2.1,
  2.2, 2.4, 2.5, plus `test_reuse_detected_revokes_entire_token_family`
  (task item 4 — the most load-bearing test in this pass: builds a 3-deep
  rotation chain, replays the long-dead first token, then asserts the
  *third*, never-replayed token also dies, proving whole-family revocation
  rather than single-token rejection) and an ordinary-expiry check.
  Scenario 2.3 (true concurrent race) is explicitly out of scope, same
  TOCTOU convention already established at OBJ-001 Gate 3 — the business
  rule it describes is covered sequentially by the other tests in this
  file; a note in the file docstring cross-references design notes
  section 2's own acknowledgment of the same unlocked read-then-write gap.
- `tests/api/test_password_reset_invalidation.py` (7 tests) — Story 3,
  Scenarios 3.1, 3.2, 3.3, 3.4, 3.6, plus a rapid-successive-resets edge
  case (each call increments independently, not idempotently). **Scenario
  3.5 (forged `ver` claim exploiting an iat/`password_reset_at` gap)
  deliberately has NO test** — `obj-002-design-notes.md` section 3 only
  specifies the plain `ver`-vs-`token_version` comparison and never adopts
  the `iat` check the requirements doc flagged as "deferred to
  solution-architect," so there is no committed mechanism to test against.
  Flagged in the file docstring as a residual gap for a future objective,
  not silently dropped.
- `tests/api/test_legacy_token_fail_closed.py` (2 tests) — task item 6's
  protected-endpoint half (a legacy access token with no `ver` claim,
  rejected at `GET /auth/me`); the `/auth/refresh` half of item 6 is
  Scenario 2.5, already covered in `test_refresh_rotation.py` and not
  duplicated here.

**Verified end-to-end against a real Postgres** (same self-provisioning
approach as every prior pass in this project: no Docker in this sandbox,
`initdb`/`pg_ctl` from the already-installed `C:\Program Files\PostgreSQL\16\bin`
binaries, own throwaway data dir under the OS temp folder, port 5433,
`trust` auth, torn down with `pg_ctl stop -m fast` immediately after the
run). Two runs:
- New OBJ-002 files alone: **20 failed, 2 passed** (22 total).
- Full suite (`tests/unit` + `tests/api`, OBJ-000/001/002 combined): **20
  failed, 51 passed** (71 total) — confirms **zero regressions** against
  OBJ-001's previously-green 49.

Every one of the 20 failures traces to a specific missing piece of OBJ-002,
inspected individually, not just eyeballed as "red":
- `POST /auth/logout` doesn't exist yet → every logout test fails with
  `404`, not an assertion mismatch (`test_logout.py`, all 8).
- `/auth/refresh` still echoes the submitted token back verbatim (OBJ-001
  behavior, unchanged) → rotation/reuse-detection/family-revoke/multi-device/
  legacy-token tests fail with `200` where `401` (or a genuinely-different
  token) was expected (`test_refresh_rotation.py`, 5 of 6 non-passing).
- `User` has no `token_version` column at all → `AttributeError`, not a
  clean assertion failure, on the two tests that read it directly
  (`test_scenario_3_1_*`, `test_rapid_successive_resets_*`) — still a
  correct "missing implementation" signal, just surfacing as an error
  instead of a `False` assertion; not a broken test.
- `/auth/reset-password` doesn't bump any version or touch any session
  table → old tokens keep working after a reset (`test_scenario_3_2/3_3/3_4`,
  `200` where `401` expected).
- `get_current_user` has no `ver` check at all → a legacy access token with
  no `ver` claim is still accepted (`test_legacy_token_fail_closed.py`'s
  first test, `200` where `401` expected).

**2 tests pass already, and were EXPECTED to** (same convention as OBJ-001's
10 pre-existing passes) — both are regression guards for already-correct
OBJ-001 behavior, not proof of any new OBJ-002 code:
- `test_expired_refresh_session_returns_401` — an expired refresh token is
  already rejected today via the existing JWT `exp` check (OBJ-001); the
  *table-level* expiry check this test's docstring describes doesn't exist
  yet, but the JWT-level one already produces the same externally-observable
  `401`, so this test can't currently distinguish "table check exists" from
  "JWT exp check alone is doing the work" — flagged as a **known weak
  point**: once `developer` implements the `refresh_sessions` table, this
  test should keep passing for the *new* reason and stays as regression
  coverage, but it does not currently prove the table-driven branch exists.
- `test_forged_access_token_with_correct_looking_ver_still_needs_real_signature`
  — signature verification already rejects a wrong-key-signed token
  regardless of claims; this only confirms the new `ver` check will be
  layered on top of, not instead of, that existing check.

**Explicitly out of scope for this pass** (all noted inline in the
relevant file's docstring too):
- Scenario 2.3's true concurrent-request race (TOCTOU) — same established
  convention as OBJ-001 Scenario 2.7 and the OTP-lockout/rate-limiter races;
  design notes section 2 already flags the same unlocked read-then-write
  gap as a non-blocking residual, tracked toward OBJ-006's concurrency-
  hardening backlog, not re-tracked here.
- Scenario 3.5 (iat-based forged-`ver` protection) — no committed
  implementation to test against; see above.
- A "log out all devices" endpoint — explicitly out of OBJ-002's scope per
  Gate 1 and design notes section 4; nothing to test.

**Risks/ambiguities flagged for `developer`:**
1. **`test_expired_refresh_session_returns_401`'s weak-point note above** —
   don't take its current green status as proof the `refresh_sessions`
   table's own `expires_at` check works; it's currently riding on the JWT's
   own `exp` claim.
2. **Fixture/session identity assumption**: `test_scenario_3_1_*` and
   `test_rapid_successive_resets_*` read `user.token_version` off the SAME
   `User` ORM object returned by `user_factory`, via `await
   db_session.refresh(user)`, relying on `/auth/reset-password`'s handler
   mutating the user row through the SAME `AsyncSession` the `client`
   fixture overrides `deps.get_db` with (established OBJ-001 pattern — see
   `tests/README.md`'s rate-limiter risk note for the general shape of this
   requirement). If the reset-password handler is implemented against a
   different session, these two tests will fail with a stale-read assertion
   instead of a clean pass once the column exists — same class of
   testability signal already flagged for the rate limiter in OBJ-001, not
   a new risk pattern.
3. **`refresh_sessions` model registration**: per the established pattern
   (`app/models/__init__.py` re-exports `User`/`Verification`/`RateLimitHit`,
   and `tests/conftest.py`'s `db_engine` fixture picks up new tables
   automatically by importing `app.models.user` — which imports the package
   `__init__` first), `developer` should add the new model's import to
   `app/models/__init__.py` the same way `RateLimitHit` was added in
   OBJ-001, rather than touching `tests/conftest.py`.
4. **Anti-oracle status codes are load-bearing, not incidental**: several
   tests assert specific status codes that came from the approved design
   overriding the raw AC (`/auth/logout`'s always-`204`, in particular) —
   don't "fix" these tests to match the original Gherkin's alternate-`401`
   proposal if the implementation and test disagree; the design notes and
   Gate 1 decision are the source of truth over the AC's own recommendation
   text.
5. **`test_reuse_detected_revokes_entire_token_family` is the highest-value
   test in this pass** — it's the one test that actually distinguishes a
   correct "revoke the whole family" implementation from a merely-adequate
   "reject only the specific replayed token" implementation. If this test
   is the only one still red after everything else in
   `test_refresh_rotation.py` goes green, that's a real gap, not a flaky
   test — recheck the family-wide `UPDATE ... WHERE family_id = :fid`
   described in design notes section 2, not just the single-row check.

**Gate 2: awaiting user approval** (per CLAUDE.md's 3-gate Semi-Auto flow —
this red-phase pass is the Gate 2 deliverable; `developer` should not start
Phase 3 implementation until Gate 2 is explicitly approved).

## OBJ-002 — Phase 3 (green phase): Done (2026-08-21, developer)

Baseline confirmed before any change: full suite run against a throwaway self-provisioned
Postgres 16 instance (same `initdb`/`pg_ctl` approach as every prior pass in this project — no
Docker in this sandbox either; port 5433, `trust` auth, own data dir, torn down after use)
reproduced qa-engineer's exact **20 failed, 51 passed** (71 total). Final suite after
implementation: **71 passed, 0 failed** (two consecutive full runs, no flakiness observed).

**Files touched:**
- `app/models/refresh_session.py` (new) — `RefreshSession` model exactly per
  `obj-002-design-notes.md` section 1 (`id`=jti PK, `family_id`, `user_id` FK to `users.id`,
  `issued_at`/`expires_at` Python-side defaults — not `server_default`, same freezegun-safety
  reasoning as `Verification.created_at`/`RateLimitHit.created_at` from OBJ-001 — `revoked_at`,
  `replaced_by` self-FK). Indexes: `(family_id)` and `(user_id, revoked_at)`, matching the design
  notes' illustrative DDL.
- `app/models/user.py` — added `token_version: int, NOT NULL, default=0`.
- `app/models/__init__.py` — re-exports `RefreshSession` alongside `User`/`Verification`/
  `RateLimitHit`, same established pattern (`app/main.py`'s `create_all` and
  `tests/conftest.py`'s `db_engine` fixture both pick it up automatically via the package
  `__init__` import — no `tests/conftest.py` edit needed, as qa-engineer's risk note #3
  anticipated).
- `app/main.py` — imports `app.models.refresh_session` alongside the existing three, belt and
  suspenders with the `__init__.py` registration.
- `app/core/security.py` — `create_access_token`/`create_refresh_token` gain a `ver: int = 0`
  parameter (the issuing user's `token_version` at mint time); `create_refresh_token` also gains
  `jti: Optional[...] = None` (auto-generated if not given, but every real issuance call site
  passes one explicitly so the JWT claim matches the DB row). New `decode_refresh_token_claims`
  (returns the full validated payload — `sub`, `jti`, `ver`, `exp`, `iat` — for `/auth/refresh`'s
  state machine) and `extract_jti_if_present` (never raises; returns `None` on any decode failure,
  backing `/auth/logout`'s no-oracle idempotency). `verify_refresh_token`'s existing OBJ-001
  contract (pure JWT-level check, returns just the email, no DB) is unchanged — both new functions
  share its internal `_decode_refresh_payload` helper rather than duplicating the decode/validate
  logic.
- `app/api/deps.py` — `get_current_user` now also compares `payload.get("ver")` against
  `user.token_version` (piggybacked on the `User` row the function already loads — zero extra
  queries, per design notes section 3), rejecting on mismatch *or* absence with the same generic
  401 used for every other validity failure.
- `app/api/v1/endpoints/auth.py`:
  - New `_issue_tokens_and_session(db, user, family_id, jti)` helper — mints one access+refresh
    pair and persists the backing `refresh_sessions` row; shared by `/auth/login` (fresh family)
    and `/auth/refresh` (rotation), avoiding duplicated token-minting logic.
  - New `_revoke_active_sessions(db, *filters, now)` helper — the shared shape behind all three
    revocation call sites (logout: one row by `id`; reuse detection: a whole family by
    `family_id`; password reset: every row for a `user_id`), added during the refactor pass to
    remove the near-identical `UPDATE ... WHERE revoked_at IS NULL ...` repeated three times.
  - `/auth/login` now creates a fresh token family via `_issue_tokens_and_session`.
  - `/auth/refresh` fully replaced with the design notes section 2 state machine: decode →
    look up `refresh_sessions` by `jti` → no row (covers legacy/forged/purged) → 401; revoked →
    reuse detected, revoke entire family, 401; expired → 401; else load user (inactive/not-found
    stays 400, unchanged OBJ-001 behavior) → `ver` mismatch → 401; else rotate (mark old row
    revoked + `replaced_by`, mint new pair via the shared helper). Every failure branch raises the
    identical generic 401, no oracle.
  - New `POST /auth/logout` — always `204`, decodes best-effort via
    `security.extract_jti_if_present`, revokes the matching row if any, never raises for a
    token-validity reason (only Pydantic's own required-field 422 can fire, before this function
    runs).
  - `/auth/reset-password` now bumps `user.token_version` and bulk-revokes every active
    `refresh_sessions` row for that user (via `_revoke_active_sessions`) in the same transaction as
    the password hash update and OTP-row deletion — the Gate-1-mandatory behavior, not optional.
- `tests/api/test_token_type_enforcement.py` — **one existing OBJ-001 test adjusted**, see
  deviation note below.
- No new entries in `requirements.txt` — `uuid` is stdlib; no new runtime dependency was needed.

**Design deviations / implementation decisions taken independently:**
- **FK-ordering fix in `/auth/refresh`'s rotation path (not a design deviation, an
  implementation-level bug caught during the green run):** setting the superseded row's
  `replaced_by` to the new row's `id` in the same flush as the new row's own `INSERT` triggers a
  `ForeignKeyViolationError` (SQLAlchemy's unit-of-work doesn't detect the same-table
  insert-before-update dependency automatically here). Fixed by calling `await db.flush()`
  immediately after `_issue_tokens_and_session` (which adds the new row) and only then setting
  `session_row.revoked_at`/`replaced_by`, before the final `db.commit()`. Same transaction, same
  atomicity — pure statement-ordering fix, not a behavior change.
- **`tests/api/test_token_type_enforcement.py::test_scenario_1_3_refresh_token_accepted_on_refresh_endpoint`
  updated, not left as-is.** This pre-existing OBJ-001 test called `security.create_refresh_token()`
  directly (bypassing `/auth/login`) and expected the resulting token to be accepted at
  `/auth/refresh`. Under OBJ-002's design, every refresh token is now backed by a
  `refresh_sessions` row created at issuance — a token minted by calling the helper function
  directly, without going through an actual issuance endpoint, has no matching row and correctly
  401s on the "no row found" branch (the same branch that must reject legacy/forged/purged
  tokens, per design notes section 2 — weakening it to special-case "no row, but structurally
  looks legit" would defeat the whole point of the session table, including the documented
  requirement that a *purged* row must also be rejected, not fallback-accepted). The scenario this
  test is actually about — "a syntactically valid, correctly-typed, correctly-signed refresh token
  is accepted at `/auth/refresh`" — is still fully exercised; it's now sourced via a real
  `/auth/login` call instead of the bypass, which is also a more realistic test in an OBJ-002
  world (no code path in the running app ever hands a client a refresh token that isn't backed by
  a session row). Flagged here rather than silently fixed, per this project's own established
  convention (see OBJ-001 Phase 3's design-deviation notes) — no other existing test needed
  adjustment; grepped the whole `tests/` tree for other direct `create_refresh_token(...)` calls
  feeding `/auth/refresh` and found none.
- Everything else matches `obj-002-design-notes.md` and the Gate 1 decisions as specified — no
  other scope changes taken.

**What's left for Gate 3:**
- `qa-engineer` — independent re-verification of the full 71/71 suite and a substantive read of
  the 22 OBJ-002 tests against the diff (same depth as the OBJ-001 Gate 3 pass), particularly
  `test_reuse_detected_revokes_entire_token_family` (confirm it's genuinely exercising the
  family-wide `UPDATE ... WHERE family_id = :fid`, not a weaker single-row check) and the two
  "weak point" tests qa-engineer flagged at Phase 2 red-phase time
  (`test_expired_refresh_session_returns_401` — still currently riding on the JWT's own `exp`
  check ahead of the table's defensive check, confirmed during this pass: the frozen-time test
  hits `security.decode_refresh_token_claims`'s `jose`-level expiry rejection before the table
  lookup ever runs, so this test still can't distinguish "table check works" from "JWT exp alone
  is doing the work" — not fixed in this pass, same documented caveat carried forward).
- `security-specialist` — SAST/DAST pass confirming finding #3 is actually closed (stolen refresh
  token unusable after logout/rotation-replay/password-reset), and review of the two residual
  gaps design notes section 2 already flagged as non-blocking (unlocked read-then-write race on
  `refresh_sessions`, same TOCTOU shape as OBJ-001's rate-limiter/OTP-lockout gaps — tracked into
  OBJ-006, not re-tracked here) plus the new `RefreshSession.replaced_by`/`family_id` FK surface.
- `database-architect` — informal review of `refresh_sessions` (still lands via
  `Base.metadata.create_all`, same ordering wrinkle as every table since OBJ-001) and the new
  `User.token_version` column; confirm the two indexes match the actual query patterns in
  `auth.py` (`id` PK lookup, `family_id` bulk revoke, `(user_id, revoked_at)` bulk revoke).
  **Done (2026-08-23) — see "database-architect informal schema review" below.**
- Test DB teardown note: this pass's throwaway Postgres 16 instance (`initdb`/`pg_ctl`, port 5433,
  own data dir) was stopped (`pg_ctl stop -m fast`) after the final verification run, same as
  every prior pass.

## OBJ-002 — database-architect informal schema review (Gate 3, 2026-08-23)

Informal review only (OBJ-006 real Alembic migrations not started — schema still lands via
`Base.metadata.create_all`, same ordering wrinkle flagged for every table since OBJ-001). No files
changed by this pass; findings for `developer` to pick up in a follow-up, and for `OBJ-006` to
formalize once real migrations exist.

**ER diagram (current full state, all four tables — supersedes/extends the OBJ-001 diagram above
with the new `REFRESH_SESSION` entity and its FK relationships):**

```mermaid
erDiagram
    USER {
        uuid id PK
        string email "unique, indexed"
        string hashed_password
        bool is_active "default true"
        bool is_verified "default false"
        int token_version "NOT NULL, default 0"
        timestamptz created_at "server_default only"
        timestamptz updated_at "server_default + onupdate"
    }
    VERIFICATION {
        uuid id PK
        string email "indexed (single-column)"
        string code
        string purpose
        int attempts "default 0"
        timestamptz expires_at
        timestamptz created_at "python-side default + server_default"
    }
    RATE_LIMIT_HIT {
        uuid id PK
        string scope
        string ip
        string email
        timestamptz created_at "python-side only, no server_default"
    }
    REFRESH_SESSION {
        uuid id PK "jti"
        uuid family_id "indexed, NOT a FK (see note 1 below)"
        uuid user_id FK
        timestamptz issued_at "python-side default only, no server_default"
        timestamptz expires_at "NOT NULL, no default at all -- always explicit"
        timestamptz revoked_at "nullable; NULL = active"
        uuid replaced_by FK "self-FK, nullable"
    }
    USER ||--o{ VERIFICATION : "keyed by email (no FK, deliberate)"
    USER ||--o{ RATE_LIMIT_HIT : "keyed by email (no FK, deliberate)"
    USER ||--o{ REFRESH_SESSION : "user_id FK (real FK -- rows only ever created for an already-authenticated user)"
    REFRESH_SESSION |o--o| REFRESH_SESSION : "replaced_by (self-FK, nullable, set post-flush)"
```

### 1. `app/models/refresh_session.py` — `RefreshSession` model

Types/nullability are correct across the board:
- `id` (jti): `UUID(as_uuid=True), primary_key=True, default=uuid.uuid4` — consistent with every
  other table's PK convention in this project.
- `family_id`: `UUID, nullable=False` — **deliberately not a real FK**, and that's correct, not an
  oversight. The root row of a family has `family_id == id` (set in `/auth/login`:
  `_issue_tokens_and_session(db, user, family_id=new_family_id, jti=new_family_id)`), i.e. a row
  referencing its own not-yet-committed `id` at INSERT time — a same-row self-FK would need a
  deferred constraint for no real benefit (`family_id` is a grouping key for the reuse-detection
  state machine, not a referential-integrity relationship to a specific row). Leave as a plain
  indexed column, don't "fix" this into a FK later.
- `user_id`: `UUID, ForeignKey("users.id"), nullable=False` — correct, matches the design notes'
  point that every row here is created for an already-authenticated, already-existing user (no
  unauthenticated-email case to protect the way `Verification`/`RateLimitHit` deliberately avoid a
  FK for).
- `issued_at`: `DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc)`
  — **confirmed correct and consistent with the OBJ-001 freezegun-safety pattern** established by
  `Verification.created_at`/`RateLimitHit.created_at`: a Python-side default keeps this timestamp
  bound to the frozen test clock instead of Postgres's own wall-clock `now()`. One nuance worth
  noting precisely (the Phase 3 changelog entry above slightly overstates this): unlike
  `Verification.created_at` (which carries **both** a Python default *and* a `server_default`,
  belt-and-suspenders for any direct-SQL insert path), `issued_at` here has **only** the Python
  default, no `server_default`. That's fine — every real code path constructs `RefreshSession` via
  the ORM (`_issue_tokens_and_session`) — just flagging that "same pattern as OBJ-001" isn't
  byte-for-byte identical to `Verification`'s belt-and-suspenders version; closer to
  `RateLimitHit`'s style, except `RateLimitHit.created_at` has *no* default at all (always passed
  explicitly by the caller) where this one has a Python default as a safety net. Three slightly
  different variants across three models now, none of them wrong, but worth a naming/consistency
  pass whenever `OBJ-006` writes real migrations, so future models don't have to guess which of the
  three precedents to copy.
- `expires_at`: `DateTime(timezone=True), nullable=False` — **no default at all**, Python-side or
  server-side. This is correct, not a gap: there's no safe implicit default for a token expiry (it
  depends on `settings.REFRESH_TOKEN_EXPIRE_DAYS`, which only the caller knows at mint time), and
  every real construction site (`_issue_tokens_and_session`) passes it explicitly. An implicit
  default here would be actively dangerous (silently minting a wrong-lifetime session row if a
  future call site forgets to pass it) — leave this column default-less.
- `revoked_at`: `DateTime(timezone=True), nullable=True` — correct, `NULL` = active is the right
  modeling choice for the three-way revocation shape (logout/rotation-supersede/reuse-family-revoke
  all just set this one column).
- `replaced_by`: `UUID, ForeignKey("refresh_sessions.id"), nullable=True` — correct, see item 4 below.

### 2. `app/models/user.py` — `token_version`
`Integer, nullable=False, default=0` — correct. No concerns; matches the design notes exactly and
gives every pre-OBJ-002 row (backfilled via `Base.metadata.create_all`, additive column) a safe
default that doesn't retroactively invalidate anything.

### 3. Index review against actual query patterns in `app/api/v1/endpoints/auth.py`

Checked the three real query shapes, not the design notes' illustrative ones:

- **PK lookup** (`refresh_token` handler, line 342): `select(RefreshSession).filter(RefreshSession.id
  == jti)` — hits the primary key directly, no additional index needed or present. Correct as-is.
- **Family bulk-revoke** (reuse detection, lines 355-357): `UPDATE refresh_sessions SET revoked_at =
  :now WHERE revoked_at IS NULL AND family_id = :fid`. The existing index is single-column
  `(family_id)` — it finds the small set of rows in that family efficiently, but the actual
  predicate is `family_id = X AND revoked_at IS NULL`, and every already-rotated row in a long-lived
  session's chain stays in that index entry set forever (never deleted, see growth section below).
  For a typical chain (a handful of rotations before either logout or the 7-day
  `REFRESH_TOKEN_EXPIRE_DAYS` ceiling) this is a non-issue — Postgres filters a handful of rows in
  memory essentially for free. For a long-lived, frequently-refreshed session (30-min access-token
  TTL forcing a refresh roughly every 30 min, up to 7 days per family) that's up to ~336 historical
  rows per family by the time reuse is ever detected — still small in absolute terms, but the same
  shape as the OBJ-001 `verifications` finding (single-column index, composite predicate, backlog
  of dead rows the index doesn't filter). Recommend the same fix, lower priority than the OBJ-001
  one was: widen to a composite index. Illustrative DDL (not applied):
  ```sql
  DROP INDEX IF EXISTS ix_refresh_sessions_family_id;
  CREATE INDEX ix_refresh_sessions_family_id_revoked_at
      ON refresh_sessions (family_id, revoked_at);
  ```
- **User bulk-revoke** (password reset, lines 301-303): `UPDATE refresh_sessions SET revoked_at =
  :now WHERE revoked_at IS NULL AND user_id = :uid`. The existing composite index
  `(user_id, revoked_at)` is an exact match for this predicate shape — equality on the leftmost
  column, then a direct hit on the second column for the `IS NULL` filter — a single index range
  scan with no extra heap-level filtering needed. **No change recommended; this is the same
  well-designed pattern `rate_limit_hits`'s index got praised for in the OBJ-001 review.**

No missing index found — every real `WHERE`/`UPDATE ... WHERE` shape in `auth.py` is covered by
either the primary key or one of the two declared indexes. The one recommendation above
(`family_id, revoked_at` composite) is an optimization, not a correctness gap.

### 4. `replaced_by` self-FK correctness
Nullable, points at `refresh_sessions.id`, no circular-constraint issue at the *schema* level (a
nullable self-FK is always safe to declare). At the *write-path* level, the FK-ordering bug the
developer already found and fixed (`/auth/refresh`, lines 378-384: explicit `await db.flush()`
between inserting the new row and setting the old row's `revoked_at`/`replaced_by`) was the correct
fix, not a workaround — confirmed by reading the code: without the flush, SQLAlchemy's unit-of-work
has no way to know the new row's `INSERT` must precede the old row's `UPDATE` referencing it, since
both touch the same table. Nothing further needed here; this is now correct.

One forward-looking gap this self-FK introduces, relevant to the growth/cleanup discussion below:
**no `ON DELETE` behavior is declared** (defaults to `NO ACTION`/`RESTRICT`) on either `user_id` or
`replaced_by`. Not a problem today (nothing ever `DELETE`s a `refresh_sessions` or `users` row), but
it will matter the moment `OBJ-006` adds a cleanup job for this table: deleting a row that's still
the target of another row's `replaced_by` pointer will raise a FK violation under the current
(undeclared, therefore default) constraint behavior. Recommend `OBJ-006` add explicit `ON DELETE`
clauses when it writes the real Alembic migration for this table:
```sql
-- user_id: if a future "delete account" endpoint is ever added, session rows
-- for a deleted user should go with it.
ALTER TABLE refresh_sessions
    DROP CONSTRAINT refresh_sessions_user_id_fkey,
    ADD CONSTRAINT refresh_sessions_user_id_fkey
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;

-- replaced_by: a purge job must be able to delete an old row even if a
-- newer row still points back at it via replaced_by (audit-trail pointer
-- only, not required for correctness per the model's own docstring).
ALTER TABLE refresh_sessions
    DROP CONSTRAINT refresh_sessions_replaced_by_fkey,
    ADD CONSTRAINT refresh_sessions_replaced_by_fkey
        FOREIGN KEY (replaced_by) REFERENCES refresh_sessions(id) ON DELETE SET NULL;
```

### 5. Growth/lifecycle concern — real, same category as the OBJ-001 findings, one important nuance
`refresh_sessions` rows are never deleted or purged — same unbounded-growth shape already flagged
for `rate_limit_hits` and (less severely) `verifications` in the OBJ-001 review. One row is written
per login and per successful rotation. With this deployment's `.env.example` defaults
(`ACCESS_TOKEN_EXPIRE_MINUTES=30`, `REFRESH_TOKEN_EXPIRE_DAYS=7`), a single continuously-active
session refreshing roughly every 30 minutes for the full 7-day window generates on the order of
~330 rows before that family's tokens age out — smaller per-session growth than
`rate_limit_hits`'s sub-minute-window churn, but still unbounded across the full user base over
time (every login, every device, every session-lifetime), and it will show up eventually.

**Important nuance this table has that the other two don't**: revoked/expired rows here are not
merely inert — they are the *evidence* the reuse-detection mechanism depends on. If a stolen,
already-rotated refresh token is replayed, the code's ability to detect that (`session_row.revoked_at
is not None` → revoke the whole family) requires the old, revoked row to **still exist**. Deleting
it too early doesn't break the individual replay attempt (it would just fall into the "no row
found" branch, still a 401) — but it silently downgrades the response from "revoke the entire
compromised family" to "reject this one token and leave every other token in that family, including
ones the attacker may also hold, valid." That's a real security regression if the retention window
is too short — this is **not** the same "delete almost immediately, nothing downstream cares"
situation as `rate_limit_hits`'s 60-second window.

**Recommendation for OBJ-006's scope** (do not schedule this cleanup job independent of the FK
`ON DELETE` fix above, and do not use a short retention window):
1. Scheduled cleanup job (same mechanism as recommended for `rate_limit_hits` — `pg_cron` or an
   app-level scheduler, run outside the hot request path), but with a **retention floor of at least
   `REFRESH_TOKEN_EXPIRE_DAYS`** (currently 7 days) past `expires_at`/`revoked_at`, not a short
   window — e.g. `DELETE FROM refresh_sessions WHERE revoked_at IS NOT NULL AND revoked_at < now() -
   interval '7 days'` (or keyed off `expires_at` for rows that died of ordinary expiry rather than
   explicit revocation). This preserves the reuse-detection guarantee for the full life of any token
   that could still theoretically be replayed.
2. Requires the `ON DELETE SET NULL` fix on `replaced_by` from item 4 above (or an equivalent
   "nullify `replaced_by` pointers before deleting the referenced predecessor" step in the cleanup
   job itself) — without one of those two, the job will intermittently fail with FK violations once
   chains are long enough that an old-but-not-yet-purge-eligible row still points at a row that just
   became purge-eligible.
3. Not recommending partitioning at this project's current size (same reasoning as the OBJ-001
   `rate_limit_hits` finding) — worth flagging as an option in `OBJ-006`'s scope if a downstream
   fork of this template expects high login volume, not building now.

### Minor/secondary observations
- No modeling issue with `family_id` never being validated against an actual existing `id` (see
  item 1) — this is intentional design, not a gap, but worth re-stating here since it's the one
  place in this schema that looks at first glance like a missing FK and isn't.
- `RefreshSession.id`/`family_id`/`user_id`/`replaced_by` all generate client-side (`default=
  uuid.uuid4` where applicable) rather than `server_default=gen_random_uuid()` — consistent with
  every other table in this project, no objection.
- The three-variant timestamp-default inconsistency noted in item 1 (`Verification`:
  default+server_default; `RateLimitHit`: neither, caller-supplied; `RefreshSession.issued_at`:
  default only) is cosmetic today but worth picking one convention when `OBJ-006` writes real
  migrations, purely so the next new table doesn't have three different precedents to choose from.

**Gate 3 status for database-architect's piece: cleared.** No blocking data-model issues in
`RefreshSession`, `token_version`, or the index/FK design. Two non-blocking optimization/hardening
recommendations (composite `(family_id, revoked_at)` index; explicit `ON DELETE` behavior on both
FKs) and one real-but-non-blocking growth-management gap (`refresh_sessions` cleanup job, tracked
into OBJ-006 with the retention-floor nuance above, distinct from the `rate_limit_hits` job's short
window) — none of these should hold up OBJ-002's Gate 3 sign-off.

## OBJ-002 — security-specialist Gate 3 SAST verification (2026-08-23)

Full detail in `docs/security/audit-report.md` §"Gate 3 — Verificación OBJ-002". Summary:

- **#3 (no token revocation) — CERRADO.** All three required revocation paths verified by direct
  code reading (not test-trust): (a) `POST /auth/logout` (`auth.py:389-411`) revokes the matching
  `refresh_sessions` row by `jti`, verified signature-checked first; (b) replaying an
  already-rotated refresh token revokes the **entire family** (`auth.py:352-359`), not just the
  replayed row; (c) `/auth/reset-password` bumps `user.token_version` and bulk-revokes every active
  session for that user **in the same transaction, single `commit()`** (`auth.py:294-305`) —
  confirmed genuinely atomic, no window where a stolen token could slip through between the
  password update and the revocation.
- **Residual re-affirmed (not reopened):** access tokens are NOT blacklisted on logout (stateless
  verification, Gate 1 tradeoff) — confirmed matches implementation (`app/api/deps.py`),
  `ACCESS_TOKEN_EXPIRE_MINUTES=30` residual window judged acceptable, still a major improvement
  over the original 7-day unrevocable refresh token.
- **TOCTOU on `refresh_sessions` (unlocked read-then-write in `/auth/refresh`'s rotation) —
  severity confirmed unchanged (Low), matches `obj-002-design-notes.md` §2's own assessment
  exactly** ("bounded double-rotation, not unbounded bypass"). Nothing new found beyond what's
  already tracked into OBJ-006.
- **New attack surface (`family_id`/`jti`/`replaced_by`) — PASS, no injection/IDOR/logic-bypass
  found.** All identifiers are server-generated UUIDs or parsed from a signature-verified JWT
  claim; no client-controlled path can target another user's session without knowing `SECRET_KEY`
  (already covered by closed finding #4).
- **New LOW**: `/auth/logout` has a minor timing side-channel — the DB round-trip only happens on
  a signature-valid token (`jti is not None` branch), so an invalid/malformed token returns faster
  than a valid one. Does **not** leak session/revocation state (all DB-touching cases are uniform
  204/no-body) — only leaks "is this a validly-signed JWT." Tracked into OBJ-003 (already covers
  the same class of finding, #5, for `/login`/`/forgot-password`).
- No oracle found on `/auth/logout` response shape/status code across valid/invalid/already-revoked
  tokens — confirmed always `204`, empty body, no distinguishing branch besides the timing note
  above.

**OBJ-002 Gate 3 security-specialist verdict: PASS.** Finding #3 is closed. One new non-blocking LOW
finding (logout timing side-channel, tracked to OBJ-003). Both previously-known residuals
(stateless access-token window, refresh-session TOCTOU) confirmed as-described, unchanged severity,
no new exploitation path.

## OBJ-002 — qa-engineer independent Gate 3 verification (2026-08-23)

**Verdict: PASS.** Independently reproduced the developer's result; the suite is substantive, not
tautological; implementation matches `docs/api/openapi.yaml` (v0.3.0-obj-002) and
`docs/api/obj-002-design-notes.md` line by line; no regressions against OBJ-001's 49. Confirmed
both flagged watch-items from the Phase 2/3 notes hold exactly as claimed — no surprises.

**1. Own suite execution (not trusting developer's report).**
Same environment constraint as every prior pass (no Docker in this sandbox) — self-provisioned a
throwaway Postgres 16 via `initdb`/`pg_ctl`, port 5433, `trust` auth, own data dir outside the
repo (`.../scratchpad/pgdata_obj002`), torn down after the run (`pg_ctl stop -m fast`, confirmed
via `pg_ctl status` → "no server running"). Ran the full suite **twice, foreground, back to
back**: both runs **71 passed, 0 failed** (84.9s, then 76.5s), no flakiness. Matches developer's
reported 71/71 exactly.

**2. Substantive vs. trivial — read all 22 new OBJ-002 tests against the actual implementation
diff, not just that they're green.** All four files (`test_logout.py`, `test_refresh_rotation.py`,
`test_password_reset_invalidation.py`, `test_legacy_token_fail_closed.py`) drive the real FastAPI
app end-to-end via `httpx.ASGITransport` — real `/auth/login`/`/auth/refresh`/`/auth/logout`/
`/auth/reset-password` calls, real bcrypt-hashed users via `user_factory`, real JWTs decoded with
`python-jose` for structural assertions (e.g. `test_scenario_2_1_*` decodes both tokens and asserts
the `jti` claims genuinely differ, not just that the two token strings differ cosmetically). None
of the 22 mock out `_issue_tokens_and_session`, `_revoke_active_sessions`, `deps.get_current_user`,
or the DB session — every assertion is on real HTTP status codes/bodies produced by the real code
path, same convention as OBJ-001's Gate 3 pass.

**3. `test_reuse_detected_revokes_entire_token_family` — confirmed genuine whole-family
revocation, not a weaker single-row check (this task's specific ask, and the highest-value test
per Phase 2 risk note #5).** Read `app/api/v1/endpoints/auth.py:352-359`: on `session_row.revoked_at
is not None` (reuse detected), the handler calls `_revoke_active_sessions(db,
RefreshSession.family_id == session_row.family_id, now=now)`, which issues `UPDATE
refresh_sessions SET revoked_at = :now WHERE revoked_at IS NULL AND family_id = :fid`
(`auth.py:122-133`) — a genuine family-wide bulk UPDATE, not a per-`id` targeted one. The test
itself (`test_refresh_rotation.py:89-134`) builds a real 3-deep rotation chain (token_v1 →
token_v2 → token_v3, three separate `/auth/refresh` calls, three real DB rows), replays the
long-dead token_v1, then asserts **token_v3 — never itself replayed — also 401s afterward**. A
buggy implementation that only revoked the specific replayed row (token_v1's own, already-dead
row) would leave token_v3 alive and this test would catch it: I traced through the logic by hand
against a weakened alternative (`RefreshSession.id == session_row.id` instead of `family_id ==
session_row.family_id`) and confirmed that variant would pass every other test in the file but
fail this one specifically — i.e. this test is genuinely load-bearing, not redundant with the
simpler `test_scenario_2_2_reusing_a_rotated_refresh_token_is_rejected`.

**4. `test_expired_refresh_session_returns_401` — re-confirmed it's still riding on the JWT's own
`exp` claim ahead of the table-level check, exactly as developer's Phase 3 notes claimed.** Traced
the call order in `auth.py:322-363`: `security.decode_refresh_token_claims(refresh_token)` is
called at line 336, *before* the `refresh_sessions` row is ever looked up (line 342). That function
(`security.py:101-106`) delegates to `_decode_refresh_payload` (`security.py:74-91`), which calls
`jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])` at line 84 with no `options` override —
`python-jose` verifies the `exp` claim itself by default and raises `ExpiredSignatureError` (a
`JWTError` subclass), caught by the bare `except JWTError` at line 90, which raises the generic
401 immediately. Since the test's frozen clock (`freeze_time("2026-01-08 00:00:01")`, past the
7-day `REFRESH_TOKEN_EXPIRE_DAYS`) expires the JWT and the mirroring `refresh_sessions.expires_at`
row at the same instant (both derived from the same value at the same issuance timestamp,
`auth.py:95-96`/`security.py:60-62`), the JWT-level rejection fires and the function never reaches
`session_row.expires_at < now` at `auth.py:361`. Confirmed by direct code read, not inference: this
test still cannot currently distinguish "the table's own defensive expiry check works" from "the
JWT's `exp` check alone is doing all the work" — carrying the same caveat forward, not a new
finding and not something this pass fixed (out of scope for a QA verification pass; a genuine fix
would need a test that mints a JWT with a *long* `exp` but manually backdates only the DB row's
`expires_at`, which none of the 22 tests currently do).

**5. Implementation vs. `docs/api/openapi.yaml` (v0.3.0-obj-002) and
`docs/api/obj-002-design-notes.md` — read line by line:**
- `/auth/refresh`'s 5-branch state machine (no row → 401; revoked → family-wide revoke + 401;
  expired → 401 no family action; user inactive/not found → 400; `ver` mismatch → 401; success →
  rotate) matches `openapi.yaml:287-312` and `obj-002-design-notes.md` §2 exactly, confirmed against
  `auth.py:322-386` branch by branch.
- Every `/auth/refresh` failure branch raises the identical `invalid_token_exception` (`"Invalid or
  expired refresh token"`, 401) — confirmed no oracle, matching spec line 349 ("All causes share
  this single generic message and status code").
- `/auth/logout` (`auth.py:389-411`) always returns `204`/`None`, only ever raising via FastAPI's
  own Pydantic validation on a missing `refresh_token` field (422) — matches `openapi.yaml:398-409`
  and design notes §4's idempotency contract exactly, including the specific "well-formed JWT of
  the wrong type" case (`test_logout_with_wrong_type_token_is_204` — an access token submitted as
  the body field still 204s, since `extract_jti_if_present` on an access token, which has no `jti`
  claim, returns `None` and the function falls through to the no-op branch).
- `/auth/logout` revokes exactly one row by `id == jti` (`auth.py:405-410`), never touches
  `family_id` — matches spec's explicit "does NOT revoke the rest of that token's family" contract
  (`openapi.yaml:386-389`), and is exercised for real by
  `test_logout_only_revokes_the_submitted_session_not_other_devices`.
- `/auth/reset-password` bumps `user.token_version += 1` AND bulk-revokes every active
  `refresh_sessions` row for the user in the same transaction/commit (`auth.py:294-305`) — matches
  the Gate-1-mandatory requirement and `openapi.yaml:220-233` exactly (bump + bulk-revoke, not
  either/or). Order confirmed correct: OTP check → user lookup → password hash → version bump →
  bulk revoke → delete verification row → single `db.commit()` — all-or-nothing, no partial-apply
  window.
- `get_current_user`'s `ver` check (`deps.py:46-47`) piggybacks on the `User` row the function
  already loads for the existing OBJ-001 checks — confirmed zero extra query, matching design notes
  §3's stated latency rationale, and confirmed the missing-claim fail-closed behavior (`None !=
  <int>`) needs no special-case code, exactly as claimed.
- `Token` schema (`access_token`, `token_type`, `refresh_token`, all required) and
  `RefreshTokenRequest` (`refresh_token` required) in `openapi.yaml:571-604` match the Pydantic
  request/response shapes actually used by `auth.py`'s route signatures
  (`refresh_token: str = Body(..., embed=True)` on both `/auth/refresh` and `/auth/logout`).
- Pre-OBJ-002 legacy-token fail-closed behavior (design notes §5) confirmed on both surfaces: a
  legacy refresh token (no `jti`) → `_parse_jti(None)` returns `None` → `session_row` stays `None`
  → "no row found" branch → 401 (`test_scenario_2_5_legacy_pre_obj002_refresh_token_rejected`); a
  legacy access token (no `ver`) → `payload.get("ver")` is `None` → `None != user.token_version`
  (`0`) → 401 (`test_legacy_access_token_without_ver_claim_rejected_at_me`). Both traced to source,
  not just observed passing.

**6. FK-ordering fix (developer's Phase 3 note) — spot-checked, not just taken on faith.**
`auth.py:378-384`: `await db.flush()` runs after `_issue_tokens_and_session` adds the new row and
before `session_row.revoked_at`/`replaced_by` are set on the old row. This is the correct fix shape
for the stated problem (new row's `INSERT` must precede the old row's `UPDATE ... replaced_by =
<new id>` to satisfy the self-referencing FK) — confirmed by the passing suite (a
`ForeignKeyViolationError` would surface as a raw DB error, not a clean 200/401 assertion failure,
in `test_scenario_2_1_refresh_rotates_and_issues_a_new_token_pair` and every other rotation test;
none did).

**7. Regression check — two independent signals, not just the aggregate pass count.**
(a) Full 71/71 (49 OBJ-001 + 22 OBJ-002) both runs — no failures anywhere in the 49. (b) File
modification timestamps (`ls -la --time-style=full-iso tests/api/ tests/unit/`) confirm
`test_token_type_enforcement.py` (16:19) is the *only* pre-existing OBJ-001-era test file touched
after the four new OBJ-002 files were authored (15:50-15:52) — every other OBJ-001 test file
(`test_otp_generation.py`, `test_secret_key_startup.py`, `test_security.py`, `test_me_endpoint.py`,
`test_otp_lockout.py`, `test_rate_limit.py`, `test_otp_resend_cooldown.py`) retains its original
Phase 2 timestamp (14:29-14:32), untouched. Read the one adjusted test
(`test_scenario_1_3_refresh_token_accepted_on_refresh_endpoint`,
`tests/api/test_token_type_enforcement.py:47-68`): the change is legitimate, not a weakening — it
now sources its refresh token via a real `/auth/login` call instead of calling
`security.create_refresh_token()` directly (which, under OBJ-002, mints a token with no backing
`refresh_sessions` row and would 401 for an unrelated reason). The scenario under test — "a
syntactically valid, correctly-typed, correctly-signed refresh token is accepted at
`/auth/refresh`" — is still fully and correctly exercised, just via a realistic issuance path.
Confirmed no other test file references `security.create_refresh_token(` directly and feeds the
result to `/auth/refresh` (would have the same problem, silently).

**Explicitly out of scope for this verification pass, per the same established convention as every
prior Gate 3 pass in this project:**
- Re-deriving the SAST/DAST security review (finding #3 closure, the unlocked read-then-write races
  on `refresh_sessions` reuse-detection/rotation) — `security-specialist`'s piece, not re-done here.
- Re-deriving the schema/index review (`refresh_sessions` indexes vs. actual query patterns,
  `User.token_version` column) — `database-architect`'s piece, not re-done here.
- Scenario 2.3 (true concurrent-request race) and Scenario 3.5 (iat-based forged-`ver` protection)
  — both already correctly flagged as out of scope at Phase 2 (no committed mechanism to test for
  3.5; established TOCTOU convention for 2.3) and not revisited, since nothing changed about their
  status during Phase 3.

**Conclusion:** Gate 3 qa-engineer sign-off: **PASS**. Suite is reproducible (71/71 twice, no
flakiness), substantive (every one of the 22 new tests traced to real code paths, no mocked
shortcuts), and the implementation matches the spec and design notes line by line. Both watch-items
flagged at Phase 2/Phase 3 (family-wide revocation genuinely implemented; expiry test still riding
on the JWT-level check) are confirmed exactly as claimed — no discrepancy between what the
developer reported and what the code actually does. No new blocking findings. Awaiting
`security-specialist` and `database-architect`'s independent Gate 3 passes before OBJ-002 closes
fully (same pattern as OBJ-001).

## Commits

- `b733c17` (2026-08-21) — OBJ-001 full slice (JWT type claim, OTP lockout/rate-limit/CSPRNG,
  `SECRET_KEY` validation, test infra, all Phase 1-3 docs). Local only, not pushed to
  `origin/main` yet (user asked to commit, not to push).

## Notes

- OBJ-001 is the priority tranche: findings #1 and #2 chain into an unauthenticated full
  account-takeover (enumerate email → brute-force OTP → reset password → stolen refresh token
  from before the reset still works because nothing was revoked). OBJ-002 closes the last link
  of that chain (revocation) and is next in line once OBJ-001 lands.
- OBJ-001's Phase 1 reuses `docs/security/audit-report.md` directly as its threat-model input —
  `security-specialist` is looped in to confirm the remediation design closes the findings it
  raised, not to re-run discovery from scratch.
- OBJ-004 and OBJ-005 and OBJ-006 have no code overlap with OBJ-001/002/003 (different files:
  middleware/config vs. `auth.py`/`security.py`/`deps.py` vs. migrations) — safe to run their
  Phase 1s in parallel with the OBJ-001 branch once OBJ-000 clears, rather than waiting in a
  single queue.
