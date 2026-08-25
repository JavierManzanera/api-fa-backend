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
| OBJ-004 | CORS; security headers; `ENVIRONMENT`-gated docs; audit logging; remove OTP debug print; XFF-aware `client_ip()` | solution-architect → qa-engineer → developer | **CLOSED** (commit `bcd058f`) | audit-report.md #9, #10, #13 |
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

Status: CLOSED (commit `bcd058f`) | Agent chain: solution-architect → qa-engineer → developer →
qa-engineer ∥ security-specialist
Docs: design=`docs/api/obj-004-design-notes.md` · tests=`docs/testing/obj-004-test-report.md` ·
security=`audit-report.md` §"Gate 3 — Verificación OBJ-004"
OTP seam for OBJ-005: `app.core.notifications.send_otp_notification(email, otp, *, purpose)` in
`app/core/notifications.py`, imported module-level in `auth.py`.

## OBJ-005 — Email Verification Flow

Status: Gate 2 approved (2026-08-25) | Phase 3 implementation done (developer, 2026-08-25) |
**Gate 3 verification in progress** (qa-engineer ∥ security-specialist dispatched) | Agent chain:
business-analyst → solution-architect → qa-engineer → developer → qa-engineer ∥ security-specialist
Docs: requirements=`docs/requirements/obj-005-email-verification-flow.md` ·
design=`docs/api/obj-005-design-notes.md` · tests=`docs/testing/obj-005-test-report.md`
Gate 1 decisions (APPROVED 2026-08-23): login enforcement = block unverified users (Option A) ·
token mechanism = reuse existing 6-digit OTP infra (`Verification.purpose="email_verification"`),
chosen **over** business-analyst's own recommendation of a long random link-token, to minimize new
surface area · email send failure = fail the registration (rollback, `503`) · resend endpoint =
reuse existing rate-limit/cooldown infra · login/refresh `is_verified` enforcement mechanics =
distinguishable `400 "Email not verified"`, adopted 2026-08-24 without a separate ask (extends the
already-Gate-3-reviewed `is_active` precedent by one predicate, doesn't reopen finding #5).
Phase 3 (developer, 2026-08-25): new `app/core/email/` package (`EmailSender` ABC + `EmailSendError`
in `base.py`, `ConsoleEmailSender` in `console.py`, template renderers in `templates.py`) wired via
`Depends(deps.get_email_sender)`; `POST /auth/verify-email` + `POST /auth/resend-verification-email`
added; `/auth/register` creates an `email_verification` row and sends via `EmailSender`, rolling
back + `503` on `EmailSendError`; `/auth/login` + `/auth/refresh` gain the `is_verified` check.
`tests/factories.py`'s `create_user` default flipped `is_verified` False→True (the flagged
cross-cutting fix, landed in this pass). Full suite: 40 failed/204 passed → **244/244 passed**,
zero regressions. Deviation from design §4.1: `app/core/notifications.py` (OBJ-004's seam) was
kept, NOT retired/routed through `EmailSender` — three pre-existing green tests patch it directly
by name; retiring it would have broken them. `/forgot-password` still uses the old seam;
`EmailSender` is wired into `/register` + `/resend-verification-email` only, per what OBJ-005's own
tests actually require.
Open items: Gate 3: qa-engineer PASS (244/244, independently re-executed, `is_verified` default
flip confirmed safe by reading not just green) + security-specialist PASS on finding #11 (genuinely
closed, not bypassable) but **2 new MEDIUM findings from this objective's own additions** (neither
reopens a closed finding, security-specialist says neither blocks Gate 3 sign-off): (1)
`EMAIL_PROVIDER` has no fail-closed startup validation — a fork reaching `ENVIRONMENT=production`
without configuring a real provider silently logs OTPs in plaintext via `ConsoleEmailSender`,
reintroducing #10's exposure class; (2) `POST /auth/resend-verification-email` lacks the
`verify_password_or_dummy` timing-parity call `/forgot-password` uses for finding #5, reopening a
bounded email-existence/verification-status enumeration channel via response latency. **User
decision (2026-08-25): fix both now in this same pass** — done: `developer` added
`Settings.validate_email_provider_not_console_in_production` (`app/core/config.py`, fails startup
on `ENVIRONMENT=="production"` + `EMAIL_PROVIDER=="console"`) and an unconditional
`verify_password_or_dummy` call in `resend_verification_email` mirroring `/forgot-password`'s
pattern, plus 11 new tests (`tests/unit/test_email_provider_startup.py` ×7,
`TestResendVerificationEmailConstantTimeGuarantee` ×4 in `test_timing_side_channel.py`). Both
findings confirmed genuinely red before the fix (temporarily reverted, reran, restored). Full
suite: 244 → **255/255 passed**, zero regressions. Gate 3 round 2: qa-engineer PASS (255/255,
independently re-run, both new test groups confirmed substantive) + security-specialist CLOSED on
both findings (empirically confirmed via subprocess `Settings()` cases, symmetric — no
over-blocking of legitimate configs). **OBJ-005 clear to close.**

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
- `bcd058f` (2026-08-25) — OBJ-004 full slice (Gate 3: qa-engineer + security-specialist both PASS).
- All four pushed to `origin/main` (verified 2026-08-25, see `CLAUDE.md` commit+push discipline).

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
