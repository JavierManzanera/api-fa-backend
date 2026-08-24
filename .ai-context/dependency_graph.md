# api-fa-backend (PRJ-003) — Objective Dependency Graph

Project: PRJ-003 (`projects/api-fa-backend`). Execution mode: **Semi-Auto** (3 gates per objective,
per CLAUDE.md). Type: backend-only reusable auth service — no `uiux-designer`/Pencil deliverable in
any objective's Phase 1 gate (no UI of its own).

**Goal:** turn the cloned FastAPI auth starter into a hardened, fully-tested reference block that
other projects can fork with confidence ("bloque hiperseguro").

**Tech stack (inherited, not re-litigated):** FastAPI, SQLAlchemy 2.0 async + PostgreSQL/asyncpg,
JWT via python-jose, passlib[bcrypt], Pydantic v2.

**Format note (2026-08-24):** this file is a lean index only — status + pointers. Full
reasoning/findings live in each role's own owned doc (`docs/requirements/`, `docs/api/`,
`docs/testing/`, `docs/database/`, `docs/security/`). See `CLAUDE.md` → "Dependency graph format"
for the full convention. Only the orchestrating Claude session edits this file.

## Phase 0 — Retroactive discovery: Done (2026-08-21)

Repo predates this workflow (cloned with code already in place). Reused as Phase 1 input instead of
re-derived: `docs/security/audit-report.md` (14 findings: 2 Critical, 2 High, 6 Medium, 4 Low) and
`docs/test-gap-analysis.md` (coverage gap analysis, 0% at the time). Every objective traces back to
a specific finding number — read the cited finding, don't trust a one-line paraphrase.

## Graph

```
[OBJ-000] Test Infrastructure Bootstrap
   ├── [OBJ-001] Critical Auth Hardening (CRITICAL)
   │      ├── [OBJ-002] Session & Token Lifecycle (HIGH)
   │      └── [OBJ-003] Data & Transport Hardening (MEDIUM)
   ├── [OBJ-004] HTTP Security Baseline (MEDIUM)
   ├── [OBJ-005] Email Verification Flow (MEDIUM)
   └── [OBJ-006] Migrations & Supply Chain Hardening (LOW)

[OBJ-007] Registration Enumeration Policy Decision (LOW) — blocked on a product decision from the
user, not on any other objective's code.
```

## Active Objectives Status

| ID | Description | Agent chain | Status | Traces to |
|---|---|---|---|---|
| OBJ-000 | Test infra bootstrap (pytest/pytest-asyncio/httpx/factories) | qa-engineer | CLOSED | test-gap-analysis.md §"Infraestructura base" |
| OBJ-001 | JWT type confusion fix; OTP CSPRNG+lockout+rate-limit; `SECRET_KEY` validation | business-analyst → solution-architect ∥ security-specialist → qa-engineer → developer | **CLOSED** (commit `b733c17`) | audit-report.md #1, #2, #4 |
| OBJ-002 | `/logout`+revocation; refresh rotation+reuse detection; `token_version` invalidation | business-analyst → solution-architect → qa-engineer → developer | **CLOSED** (commit `33b7aa0`) | audit-report.md #3 |
| OBJ-003 | OTP HMAC-at-rest; TLS to Postgres; timing side-channel mitigation | solution-architect → database-architect ∥ qa-engineer → developer | **CLOSED** (commit `5ce5e2c`) | audit-report.md #5, #7, #8 |
| OBJ-004 | CORS; security headers; `ENVIRONMENT`-gated docs; audit logging; remove OTP debug print; XFF-aware `client_ip()` | solution-architect → qa-engineer → developer | Phase 2 done, **Gate 2 awaiting approval** | audit-report.md #9, #10, #13 |
| OBJ-005 | Real `/verify-email` flow; `is_verified` enforcement at login/refresh; `EmailSender` abstraction | business-analyst → solution-architect → qa-engineer → developer | Phase 2 done, **Gate 2 awaiting approval** | audit-report.md #11 |
| OBJ-006 | Real Alembic migrations; DDL/DML role separation; dependency pinning/CI audit; scheduled cleanup jobs | database-architect → devops-engineer | database-architect piece DONE; devops-engineer piece **not started** | audit-report.md #12, #14 |
| OBJ-007 | Decide `/register` enumeration behavior (explicit vs. generic) | **user decision required**, then developer | Not Started (blocked on product decision) | audit-report.md #6 |

## OBJ-000 — Test Infrastructure Bootstrap

Status: CLOSED (commit `b733c17`, delivered alongside OBJ-001) | Agent: qa-engineer
Docs: `tests/README.md` (run instructions, scope, risk notes)

## OBJ-001 — Critical Auth Hardening

Status: CLOSED (commit `b733c17`) | Agent chain: business-analyst → solution-architect ∥
security-specialist → qa-engineer → developer
Docs: requirements=`docs/requirements/obj-001-critical-auth-hardening.md` ·
design=`docs/api/obj-001-design-notes.md` · tests=`docs/testing/obj-001-test-report.md` ·
security=`audit-report.md` §"Gate 3 — Verificación OBJ-001" ·
db=`docs/database/obj-001-schema-review.md`
Gate 1 decisions: `GET /auth/me` in scope · OTP lockout 5 attempts, rate limits 5-10/min per
IP+email, 60s resend cooldown · OTP stays 6-digit/10min TTL (lockout+rate-limit is what makes this
safe) · rate-limit/lockout state in Postgres (no Redis) · JWT explicit `type` claim.
Gate 3: unanimous PASS (qa-engineer, security-specialist, database-architect).

## OBJ-002 — Session & Token Lifecycle

Status: CLOSED (commit `33b7aa0`) | Agent chain: business-analyst → solution-architect →
qa-engineer → developer
Docs: requirements=`docs/requirements/obj-002-session-token-lifecycle.md` ·
design=`docs/api/obj-002-design-notes.md` · tests=`docs/testing/obj-002-test-report.md` ·
security=`audit-report.md` §"Gate 3 — Verificación OBJ-002" ·
db=`docs/database/obj-002-schema-review.md`
Gate 1 decisions: `/auth/logout` invalidates only the submitted session, no "all devices" endpoint
· `/auth/reset-password` MUST bulk-revoke all active sessions + bump `token_version` atomically ·
access tokens NOT blacklisted on logout (stateless, accepted residual window up to
`ACCESS_TOKEN_EXPIRE_MINUTES`).
Gate 3: unanimous PASS. New LOW found (`/auth/logout` timing side-channel) — folded into OBJ-003.

## OBJ-003 — Data & Transport Hardening

Status: CLOSED (commit `5ce5e2c`) | Agent chain: solution-architect → database-architect ∥
qa-engineer → developer
Docs: design=`docs/api/obj-003-design-notes.md` · tests=`docs/testing/obj-003-test-report.md` ·
security=`audit-report.md` §"Gate 3 — Verificación OBJ-003" ·
db=`docs/database/obj-003-schema-review.md`
Gate 1 decisions: TLS enforcement = configurable `POSTGRES_SSL_MODE` with safe default + operator
escape hatch (not hard-fail-closed like `SECRET_KEY`) · `/forgot-password` dummy-work = unconditional
bcrypt-dummy tax on every call (accepted ~100-300ms latency cost for the stronger guarantee).
Gate 3: unanimous PASS. Residual, non-blocking: no real TLS-terminated-Postgres wire-level DAST
check has been done in any pass (sandbox has no TLS certs) — worth a real check before production
deploys relying on `require`/`verify-full`.

## OBJ-004 — HTTP Security Baseline

Status: Phase 2 done (2026-08-24) | **Gate 2: awaiting user approval** | Agent chain:
solution-architect → qa-engineer → developer
Docs: design=`docs/api/obj-004-design-notes.md` · tests=`docs/testing/obj-004-test-report.md`
Gate 1 decisions (APPROVED 2026-08-23): CORS default origins = empty list (safe default) · CSP
scope for `/docs`/`/redoc` = scoped CDN exemption (adopted, no genuine tradeoff — alternative
breaks default Swagger UI) · OTP delivery interim seam = add the minimal monkeypatchable no-op now
(adopted, low-stakes/reversible) · `X-Forwarded-For` trust = configurable `TRUSTED_PROXY_COUNT`,
default `0`/untrusted (adopted).
Open items: **environment blocker** — `greenlet` blocked by Windows Application Control, blocks 32
of 79 new tests + 61 pre-existing DB-backed tests project-wide (see Notes below, same root cause as
OBJ-006's identical finding). Must be resolved before Phase 3 verification can complete.

## OBJ-005 — Email Verification Flow

Status: Phase 2 done (2026-08-24) | **Gate 2: awaiting user approval** | Agent chain:
business-analyst → solution-architect → qa-engineer → developer
Docs: requirements=`docs/requirements/obj-005-email-verification-flow.md` ·
design=`docs/api/obj-005-design-notes.md` · tests=`docs/testing/obj-005-test-report.md`
Gate 1 decisions (APPROVED 2026-08-23): login enforcement = block unverified users (Option A) ·
token mechanism = reuse existing 6-digit OTP infra (`Verification.purpose="email_verification"`),
chosen **over** business-analyst's own recommendation of a long random link-token, to minimize new
surface area · email send failure = fail the registration (rollback, `503`) · resend endpoint =
reuse existing rate-limit/cooldown infra · login/refresh `is_verified` enforcement mechanics =
distinguishable `400 "Email not verified"`, adopted 2026-08-24 without a separate ask (extends the
already-Gate-3-reviewed `is_active` precedent by one predicate, doesn't reopen finding #5).
Open items: **CRITICAL cross-cutting test risk** — `tests/factories.py`'s `create_user` defaults to
`is_verified=False`; zero existing tests across OBJ-001–004 override it, so once login enforcement
lands, ~13 pre-existing test files will regress unless `developer` also flips the default to
`is_verified=True` in the same Phase 3 pass (full detail in
`docs/testing/obj-005-test-report.md`). Same `greenlet` environment blocker as OBJ-004/006.

## OBJ-006 — Migrations & Supply Chain Hardening

Status: database-architect piece DONE (2026-08-24, 8 Alembic migrations authored+verified);
devops-engineer piece (CI/pip-audit/lockfile/role-creation/cleanup-scheduling) **not started** |
Agent chain: database-architect → devops-engineer
Docs: plan+migrations+handoff=`docs/database/obj-006-migration-plan.md` (includes the Gate 1
approval and migration-authorship sections)
Gate 1 decisions (APPROVED 2026-08-23): `rate_limit_hits` retention 1hr · `refresh_sessions`
retention floor = 7 days (`REFRESH_TOKEN_EXPIRE_DAYS`, hard floor, not adjustable downward) ·
cleanup scheduler = APScheduler over `pg_cron` · migration 0005 (timestamp convergence) kept ·
**migration 0006 (`RateLimitHit.ip`→`INET`) INCLUDED** — user explicitly accepted the data-cast
risk rather than deferring it · CI role-separation enforcement adopted · optional partial-unique-
index defense (migration 0008) adopted.
**CRITICAL, blocking further deployment**: migration `0008` (partial unique index on
`refresh_sessions.family_id`) is confirmed **deterministically incompatible** with the current
`/auth/refresh` rotation handler's insert-then-revoke ordering — breaks every single-threaded
rotation once migrated to head. Validated fix (reorder to revoke→insert→link) documented in the
migration plan doc. **Do not run `alembic upgrade head` — stop at `0007` — until `developer`
reorders that handler.**
Same `greenlet` environment blocker as OBJ-004/005 (see Notes) — full pytest suite against a
migrated schema not yet directly verified.

## OBJ-007 — Registration Enumeration Policy Decision

Status: Not Started, blocked on a product decision (not code) | Traces to: audit-report.md #6
Decide: keep `/register`'s explicit "email already exists" `400` (documented accepted risk) vs.
switch to a generic response matching `/forgot-password`'s anti-enumeration pattern. Not yet raised
with the user.

## Commits

- `b733c17` (2026-08-21) — OBJ-000+OBJ-001 full slice.
- `33b7aa0` (2026-08-21) — OBJ-002 full slice.
- `5ce5e2c` (2026-08-23) — OBJ-003 full slice.
- All three pushed to `origin/main` (verified 2026-08-23, see `CLAUDE.md` commit+push discipline).

## Notes

- OBJ-001 is the priority tranche: findings #1+#2 chain into an unauthenticated full
  account-takeover (enumerate email → brute-force OTP → reset password → stolen refresh token from
  before the reset still works). OBJ-002 closes the revocation gap.
- OBJ-004/005/006 have no code overlap with OBJ-001/002/003 (different files: middleware/config vs.
  `auth.py`/`security.py`/`deps.py` vs. migrations) — safe to run their Phase 1s in parallel.
- **Active cross-cutting blocker (2026-08-24): `greenlet` blocked by Windows Application Control.**
  Independently discovered and confirmed by three separate agent passes (OBJ-004 qa-engineer, OBJ-005
  qa-engineer, OBJ-006 database-architect) — `import greenlet` fails with `DLL load failed... An
  Application Control policy has blocked this file`, 100% reproducible, not fixed by reinstalling the
  package. Blocks every SQLAlchemy `AsyncSession`/`AsyncEngine` operation, i.e. the entire
  `tests/api/**` suite and any async-DB code path, for every objective — not caused by any of the
  three passes that found it. Plain sync SQLAlchemy (what Alembic itself uses) is unaffected.
  **Must be resolved through a sanctioned channel before Phase 3/Gate 3 verification can complete
  for OBJ-004, OBJ-005, or OBJ-006.** Tracked as the next thing to fix after the dependency-graph/
  context-management cleanup (per user instruction, 2026-08-24).
