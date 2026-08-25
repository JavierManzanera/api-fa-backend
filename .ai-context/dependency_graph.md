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

[OBJ-007] Registration Enumeration Policy Decision (LOW) — CLOSED 2026-08-25 (Gate 3 unanimous
PASS, PR pending merge).

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
| OBJ-007 | `/register` switches to generic anti-enumeration response (matches `/forgot-password`) | solution-architect → qa-engineer → developer → qa-engineer ∥ security-specialist | **CLOSED** (PR pending) | audit-report.md #6 |
| — | `/register` DoS amplification via missing rate limit (finding #16) | security-specialist found it | Not Started (backlog) | audit-report.md §Gate 3 OBJ-007 |
| — | `ALGORITHM` config guardrail (finding #15) | security-specialist → developer → qa-engineer | **CLOSED** (PR #4 merged) | audit-report.md #15 |
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

Status: CLOSED — Gate 3 unanimous PASS (qa-engineer 262/262 live, security-specialist finding #6
confirmed closed by code reading not self-report) — commits `4182d8b`..`7f718c8` on branch
`obj-007-register-anti-enumeration`, not yet merged (PR pending)
Docs: design=`docs/api/obj-007-design-notes.md` · spec=`docs/api/openapi.yaml` (`/auth/register`) ·
tests=`docs/testing/obj-007-test-report.md` · security=`audit-report.md` §"Gate 3 — Verificación
OBJ-007"
`POST /register` now returns identical `200`+`MessageResponse` whether the email is new or already
registered — no `User`/`Verification` row, no distinguishable timing (unconditional
`get_password_hash()`), symmetric `503` on send-failure, on the duplicate-email branch.

## Finding #16 (new, MEDIUM, non-blocking) — `/register` DoS amplification via missing rate limit

Status: Not started, backlog | Traces to: audit-report.md §"Gate 3 — Verificación OBJ-007"
Found by security-specialist during OBJ-007 Gate 3: `/register` still has no `enforce_rate_limit`
call (pre-existing gap), and OBJ-007's own timing-parity fix now makes the duplicate-email branch
pay a real bcrypt cost too (previously near-free) — the one remaining unauthenticated auth endpoint
with no rate limiting just got a genuine CPU-exhaustion amplification vector. Not urgent enough to
block OBJ-007's Gate 3, but real. Candidate for a dedicated small objective or folding into
whichever next touches `/register`.

## Finding #15 remediation — `ALGORITHM` config guardrail

Status: CLOSED (commit `b97f9a5`, live-verified 267/267 green on `tests/unit`+`tests/api` 2026-08-25
— PR #4 merged) | Agent chain: security-specialist → developer → qa-engineer
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
