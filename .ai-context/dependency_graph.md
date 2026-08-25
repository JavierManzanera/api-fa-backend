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

[OBJ-008] Replace python-jose with PyJWT[cryptography] (LOW, backlog) — removes the ecdsa
dependency (and its suppressed CVE) from the tree entirely, not urgent.
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
| OBJ-007 | Decide `/register` enumeration behavior (explicit vs. generic) | **user decision required**, then developer | Not Started (blocked on product decision) | audit-report.md #6 |
| — | `ALGORITHM` config guardrail (finding #15) | security-specialist → developer → qa-engineer | In progress (developer next) | audit-report.md #15 |
| OBJ-008 | Replace `python-jose` with `PyJWT[cryptography]` (drops `ecdsa`/PYSEC-2026-1325 entirely) | developer → qa-engineer ∥ security-specialist | Not Started (backlog, LOW, no deadline) | audit-report.md #15 |

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

Status: CLOSED (`c4c518b` direct-to-main under the old policy + PR #1 / merge `2bc6eb6` under the
new one) | Agent chain: database-architect → devops-engineer → developer (RateLimitHit.ip fix) →
devops-engineer (CI YAML fix)
Docs: plan+migrations+handoff=`docs/database/obj-006-migration-plan.md` (includes the Gate 1
approval, migration-authorship, and devops addendum sections)
devops-engineer delivered: `.github/workflows/ci.yml` (4 jobs, all now correctly named — a job
`name:` containing an unquoted ` #` was silently truncated by YAML comment parsing, caught when it
broke a required branch-protection status check, fixed in `f930513`) · pinned
`requirements(-dev).txt` + `requirements(-dev).lock.txt` (finding #12) · `pip-audit` wired ·
`app/core/scheduler.py` (APScheduler cleanup jobs) · CI role-separation smoke test (finding #14).
Every CI migration step targets `0007` explicitly, never `head`/`0008`.
`RateLimitHit.ip` ORM/migration-drift fix (model was `String`, migration 0006 casts DB column to
`INET`) — closed, both modes 255/255 green, confirmed on real CI too.
**Commit+push policy change (2026-08-25, mid-objective) — this is the objective where it happened:**
`c4c518b` (CI pipeline etc.) landed direct-to-`main` under the *old* policy; the
`RateLimitHit.ip`/YAML fixes that followed went through the *new* one (branch
`obj-006-migrations-supply-chain` → PR #1 → user-reviewed-and-merged on GitHub, `2bc6eb6`) — see
`CLAUDE.md` directive #4 for the full policy and reasoning. GitHub branch protection on `main` is
now live and verified (direct push tested and rejected with `GH006`).
Secondary, lower-urgency, not yet actioned: `docs/database/sql/provision_db_roles.sql`'s DML
grants assume the 4 tables already exist, doesn't hold for a genuine greenfield DB — CI works
around it with a narrower bootstrap subset; real operator script may need the same split for an
actual staging/production cutover.
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
`greenlet` blocker (see Notes) confirmed resolved 2026-08-25 — full suite now verified in both
modes: create_all = 255/255 green; `TEST_DB_SCHEMA_SOURCE=alembic` (stopping at 0007) = 60 failing,
all traced to the single `RateLimitHit.ip` type-mismatch finding above, not a migration-authorship
defect. Awaiting user decision on the finding above before OBJ-006 fully closes.

## OBJ-007 — Registration Enumeration Policy Decision

Status: Not Started, blocked on a product decision (not code) | Traces to: audit-report.md #6
Decide: keep `/register`'s explicit "email already exists" `400` (documented accepted risk) vs.
switch to a generic response matching `/forgot-password`'s anti-enumeration pattern. Not yet raised
with the user.

## Finding #15 remediation — `ALGORITHM` config guardrail

Status: CLOSED (commit `b97f9a5`, live-verified 267/267 green on `tests/unit`+`tests/api` 2026-08-25
— not yet merged, awaiting PR review) | Agent chain: security-specialist → developer → qa-engineer
Docs: security=`audit-report.md` §"Auditoría puntual — PYSEC-2026-1325 / python-ecdsa / ALGORITHM
sin validar (2026-08-25)" (finding #15, MEDIUM)
Fail-closed `field_validator` on `Settings.ALGORITHM` restricting it to `{"HS256"}`, same pattern as
`POSTGRES_SSL_MODE`/`ENVIRONMENT`. User approved doing this now (2026-08-25); durable fix (dropping
`python-jose` entirely) tracked separately as OBJ-008 backlog.

## OBJ-008 — Replace `python-jose` with `PyJWT[cryptography]` (backlog)

Status: Not Started, backlog (LOW, no deadline) | Traces to: audit-report.md #15
Rationale: removes `ecdsa` (and the suppressed `PYSEC-2026-1325` CVE) from the dependency tree
entirely instead of reasoning about reachability indefinitely. security-specialist scoped it as
~2 app files + 8 test files, near-identical API — user approved opening this as a tracked backlog
item (2026-08-25), not urgent.

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
