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

[OBJ-007] Registration Enumeration Policy Decision (LOW) — decision made 2026-08-25, now in Phase 2.
```

## Active Objectives Status

| ID | Description | Agent chain | Status | Traces to |
|---|---|---|---|---|
| OBJ-000 | Test infra bootstrap (pytest/pytest-asyncio/httpx/factories) | qa-engineer | CLOSED | test-gap-analysis.md §"Infraestructura base" |
| OBJ-001 | JWT type confusion fix; OTP CSPRNG+lockout+rate-limit; `SECRET_KEY` validation | business-analyst → solution-architect ∥ security-specialist → qa-engineer → developer | **CLOSED** (commit `b733c17`) | audit-report.md #1, #2, #4 |
| OBJ-002 | `/logout`+revocation; refresh rotation+reuse detection; `token_version` invalidation | business-analyst → solution-architect → qa-engineer → developer | **CLOSED** (commit `33b7aa0`) | audit-report.md #3 |
| OBJ-003 | OTP HMAC-at-rest; TLS to Postgres; timing side-channel mitigation | solution-architect → database-architect ∥ qa-engineer → developer | **CLOSED** (commit `5ce5e2c`) | audit-report.md #5, #7, #8 |
| OBJ-004 | CORS; security headers; `ENVIRONMENT`-gated docs; audit logging; remove OTP debug print; XFF-aware `client_ip()` | solution-architect → qa-engineer → developer | **CLOSED** (commit `bcd058f`) | audit-report.md #9, #10, #13 |
| OBJ-005 | Real `/verify-email` flow; `is_verified` enforcement at login/refresh; `EmailSender` abstraction | business-analyst → solution-architect → qa-engineer → developer | **CLOSED** (commit `8ea1294`) | audit-report.md #11 |
| OBJ-006 | Real Alembic migrations; DDL/DML role separation; dependency pinning/CI audit; scheduled cleanup jobs | database-architect → devops-engineer | **CLOSED** (`c4c518b` + PR #1 merge `2bc6eb6`) | audit-report.md #12, #14 |
| OBJ-007 | `/register` switches to generic anti-enumeration response (matches `/forgot-password`) | qa-engineer → developer → qa-engineer ∥ security-specialist | Phase 2 (red tests in progress) | audit-report.md #6 |

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

Status: CLOSED (commit `8ea1294`) | Agent chain: business-analyst → solution-architect →
qa-engineer → developer → qa-engineer ∥ security-specialist → developer (2 MEDIUM fixes) →
qa-engineer ∥ security-specialist (re-verify)
Docs: requirements=`docs/requirements/obj-005-email-verification-flow.md` ·
design=`docs/api/obj-005-design-notes.md` · tests=`docs/testing/obj-005-test-report.md` ·
security=`audit-report.md` §"Gate 3 — Verificación OBJ-005"
`EmailSender` abstraction (`app/core/email/`) wired into `/register` + `/resend-verification-email`;
OBJ-004's `notifications.py` seam deliberately kept for `/forgot-password` (3 pre-existing tests
patch it by name). Gate 3 round 1 surfaced 2 new MEDIUM findings (own additions, not regressions);
fixed same pass, both independently re-confirmed CLOSED.

## OBJ-006 — Migrations & Supply Chain Hardening

Status: CLOSED (`c4c518b` + PR #1 merge `2bc6eb6`; follow-ups `bae2915` RateLimitHit.ip fix,
`f930513` CI YAML quoting fix, `25d5792`/PR #3 alembic-gate made required)
Docs: plan+migrations+handoff=`docs/database/obj-006-migration-plan.md` · security=`audit-report.md`
#12, #14
Residual, not yet actioned: migration `0008` (partial unique index on `refresh_sessions.family_id`)
still confirmed incompatible with `/auth/refresh`'s current handler ordering — CI stays pinned to
`0007` until `developer` reorders it (see migration-plan doc, "CRITICAL finding"). Also
`docs/database/sql/provision_db_roles.sql`'s DML-grant block assumes tables already exist — doesn't
hold for a genuine greenfield DB, worth a `database-architect` look before a real prod cutover.

## OBJ-007 — Registration Enumeration Policy Decision

Status: Gate 2 PASSED (red-phase tests written + live-confirmed genuinely red) — awaiting user
approval to proceed to developer implementation | Agent chain: solution-architect → qa-engineer →
developer → qa-engineer ∥ security-specialist | Blocked by: none | Traces to: audit-report.md #6
Docs: design=`docs/api/obj-007-design-notes.md` · spec=`docs/api/openapi.yaml` (`/auth/register`
path) · tests=`docs/testing/obj-007-test-report.md`
Gate 2 (qa-engineer, commits `8418e00`+`87d783d`): 17 tests across
`test_register_email_verification.py` / `test_timing_side_channel.py` /
`test_audit_logging.py`, live-run against real Postgres 2026-08-25 — 14 failed / 3 passed (the 3
green ones are pre-existing regression anchors untouched by this objective). All 14 failures
confirmed as clean contract mismatches (`201`/`400` vs. the new `200`/`503` contract), none from
typos/fixtures/imports. One test-authoring bug found+fixed during the live pass (a post-rollback
ORM-attribute read causing a crash instead of a clean assertion failure).
Gate 1 decision (2026-08-25, user): switch `/register` to a generic anti-enumeration response
matching `/forgot-password`'s pattern.
Gate 1 design (solution-architect): new contract is `200` + `MessageResponse` (same body whether
new or duplicate email) replacing the old `201`+`UserResponse` / `400` split — `UserResponse`
dropped from this endpoint entirely rather than faked on the duplicate branch, since that would
itself be the enumeration signal. Duplicate branch must pay an equivalent bcrypt-hash cost
(`security.get_password_hash()`, not the verify-dummy used elsewhere) for timing parity, still
sends a "you already have an account" notification via `EmailSender`, creates zero new
`User`/`Verification` rows, and its send-failure also yields `503` (closes a residual oracle).
Flagged for Gate 3, not blocking now: `/register` still has no rate limiting (existing gap, out of
this objective's scope).
Open items: user Gate 2 approval, then developer implementation, then Gate 3.
Commit: `8418e00`, `87d783d` (branch `obj-007-register-anti-enumeration`, not yet merged)

## Commits

- `b733c17` (2026-08-21) — OBJ-000+OBJ-001 full slice.
- `33b7aa0` (2026-08-21) — OBJ-002 full slice.
- `5ce5e2c` (2026-08-23) — OBJ-003 full slice.
- `bcd058f` (2026-08-25) — OBJ-004 full slice (Gate 3: qa-engineer + security-specialist both PASS).
- `8ea1294` (2026-08-25) — OBJ-005 full slice (Gate 3, 2 rounds: 2 MEDIUM findings raised + fixed +
  re-verified same pass, both closed).
- `c4c518b` (2026-08-25) — OBJ-006 devops-engineer slice (CI, lockfiles, pip-audit, cleanup jobs) —
  last commit pushed direct-to-`main` under the old policy.
- `2bc6eb6` (2026-08-25) — merge of PR #1 (`RateLimitHit.ip` fix + CI YAML quoting fix) — first
  objective closed under the new branch+PR-to-main policy (see `CLAUDE.md` directive #4).
- All pushed/merged to `origin/main` (verified 2026-08-25, see `CLAUDE.md` commit+push discipline).
  `main` now has GitHub branch protection: PR required, direct push blocked (tested), 3 required
  CI status checks, `enforce_admins: true`.

## Notes

- OBJ-001 is the priority tranche: findings #1+#2 chain into an unauthenticated full
  account-takeover (enumerate email → brute-force OTP → reset password → stolen refresh token from
  before the reset still works). OBJ-002 closes the revocation gap.
- OBJ-004/005/006 have no code overlap with OBJ-001/002/003 (different files: middleware/config vs.
  `auth.py`/`security.py`/`deps.py` vs. migrations) — safe to run their Phase 1s in parallel.
- **RESOLVED (2026-08-25): `greenlet`/Windows Application Control blocker from 2026-08-24.** User
  rebooted the machine; `import greenlet` and the actual `greenlet_spawn` trampoline both confirmed
  working again. No longer blocks async SQLAlchemy for any objective. `docker` is still not
  installed/on PATH in this environment — Postgres for test runs is provisioned as a disposable
  instance via the already-installed `C:\Program Files\PostgreSQL\16\bin` (`initdb`+`pg_ctl`, port
  5433, `test`/`test`/`api_fa_test`), same pattern documented in `tests/README.md`'s original
  environment note. Per `CLAUDE.md` directive #6, provisioning/tearing down this instance and
  running the verification suite is `devops-engineer`/`qa-engineer`'s domain going forward, not the
  orchestrator's — OBJ-004/005's Gate 3 passes both did this correctly.
