# OBJ-005 — Test Report (qa-engineer)

**Summary:** 47 new tests (6 files) covering Stories 1-3 of
`docs/requirements/obj-005-email-verification-flow.md` against `obj-005-design-notes.md` and
`openapi.yaml` (0.6.0-obj-005). **Could not be executed live** — two independent environment
blockers hit during this pass (below); correctness verified instead by direct line-by-line reading
of current `app/` code. **Gate 2: awaiting user approval.**

**CRITICAL cross-cutting risk found during this pass, for `developer`'s Phase 3 (not fixed here,
kept additive-only per task scope):** `tests/factories.py`'s `create_user` defaults to
`is_verified=False`. Zero existing test files across OBJ-001–OBJ-004 ever override this. Once
`/auth/login`'s new `is_verified` enforcement lands, **every existing test that logs in via a
default `user_factory()` call will start failing** with `400 "Email not verified"` instead of
`200` — a suite-wide regression across ~13 pre-existing files
(`test_refresh_rotation.py`, `test_token_type_enforcement.py`, `test_logout.py`,
`test_password_reset_invalidation.py`, `test_timing_side_channel.py`,
`test_rate_limit_ip_spoofing.py`, `test_audit_logging.py`, and more), not hypothetical. This pass's
own new tests are unaffected (each passes `is_verified=True` explicitly where a working login is
needed). **Recommended fix for developer's Phase 3:** change `create_user`'s default to
`is_verified=True`, update the one test that asserts the old default
(`tests/api/test_me_endpoint.py:39`). Full detail in
`test_login_refresh_verification_enforcement.py`'s module docstring.

## Phase 2 (red phase) — 2026-08-24

- `tests/api/test_verify_email.py` (9) — `POST /auth/verify-email`: success sets `is_verified=True`
  + returns `UserResponse` (no tokens), row deleted on success, replay-after-success rejected,
  expired/wrong code rejected, error message asserted **distinct** from `/auth/verify-otp`'s,
  shared-attempts lockout, rate limit (10/min), schema validation.
- `tests/api/test_resend_verification_email.py` (8) — anti-enumeration generic 200; fresh row for
  an unverified user; **silent no-op for an already-verified user** (asserted via both DB state and
  zero `EmailSender.send` calls); cooldown preserves vs. rotates the code; rate limit (5/min);
  schema validation.
- `tests/api/test_register_email_verification.py` (8) — response shape/status unchanged on success;
  a `purpose=email_verification` row created; `EmailSender.send` called once with the code in the
  body; **highest-value test**: `test_register_rolls_back_entirely_when_email_send_fails` mocks
  `EmailSendError`, asserts `503` **and**, via a fresh `SELECT` (not just the status code), that no
  `User` row survives — plus a companion test proving the email can register again afterward.
- `tests/api/test_login_refresh_verification_enforcement.py` (7) — unverified user blocked at login
  with exact `400 "Email not verified"`; verified user logs in normally; a wrong password for an
  unverified user still gets the ordinary generic credentials error (never leaks unverified state);
  structural (non-wall-clock) assertion that `verify_password_or_dummy` still runs exactly once —
  finding #5's guarantee isn't reopened; `/auth/refresh` rejects a token whose user became
  unverified after issuance; **regression guard**: `/auth/me` must NOT reject an unverified user
  holding a pre-existing access token (catches an accidental over-broad check landing inside
  `get_current_user`).
- `tests/api/test_verification_purpose_isolation.py` (3) — **highest-value test in the whole pass**
  (direct analogy to OBJ-002's family-revocation test): proves generalizing
  `_check_and_consume_otp`'s hardcoded purpose into a parameter did not merge the
  `reset_password`/`email_verification` attempt budgets, tested in both directions plus a
  DB-state coexistence check.
- `tests/unit/test_email_sender.py` (12) — `EmailSendError` is an `Exception` subclass;
  `EmailSender` is a real ABC (direct instantiation raises `TypeError`); the documented `send(*, to,
  subject, body, html_body=None) -> None` signature; `ConsoleEmailSender` never raises and logs
  (via `logging`/`caplog`, deliberately **not** `capsys`/stdout, per the non-negotiable
  no-stdout-capture instruction) the full plaintext body; `deps.get_email_sender()` defaults to
  `ConsoleEmailSender`, is a cached singleton, raises `NotImplementedError` for any other
  `EMAIL_PROVIDER`; `Settings.EMAIL_PROVIDER`/`EMAIL_FROM` exist with safe defaults; both templates
  embed the OTP with distinct subjects.

### Verification method — two independent environment blockers, documented not worked around

1. **`test_email_sender.py` — verified by real execution**, no Postgres needed. Ran twice
   foreground: **12 failed, 0 passed** both times. Every failure inspected: 6
   `ModuleNotFoundError` (`app.core.email` package doesn't exist), 2 `AttributeError`
   (`deps.get_email_sender`, `Settings.EMAIL_PROVIDER` missing), 4 more `ModuleNotFoundError` for
   submodules — all traced to specific missing OBJ-005 pieces, none broken tests.
2. **The 5 `tests/api/**` files could not be executed live** — a genuinely new blocker (OBJ-000
   through OBJ-004 all self-provisioned Postgres successfully). `initdb.exe` is now blocked by a
   Windows Application Control policy (`pg_ctl`/`postgres`/`psql` still run fine) — worked around
   by reusing a leftover already-initialized data directory (`%TEMP%\api-fa-test-pgdata`, port
   5433). Running the suite against it then hit a **different, more severe** block:
   `ValueError: the greenlet library is required... DLL load failed while importing _greenlet: An
   Application Control policy has blocked this file.` **Confirmed project-wide, not OBJ-005-
   specific**: the pre-existing, previously-green `test_me_endpoint.py` (OBJ-001) fails identically
   alone. SQLAlchemy's async engine needs the native `greenlet` extension for every DB-touching
   test, regardless of objective — this blocks Phase 3 verification for **every** open objective's
   `tests/api/**`, not just this one, until resolved through a sanctioned channel (not something to
   route around from inside an agent session).
   - Given real execution was blocked, all 35 `tests/api/**` tests were instead verified by direct,
     complete reading of `auth.py`/`deps.py`/`security.py`/`config.py`: confirmed no
     `/verify-email`/`/resend-verification-email` route exists yet (404 today); confirmed
     `/auth/login`/`/auth/refresh` check only `is_active`, never `is_verified` (every enforcement
     test's expected `400` is a `200` today — a clean assertion failure, not an error); confirmed
     `register()` has no `Verification`-row creation, no `EmailSender` call, no rollback logic;
     confirmed `get_current_active_user` checks only `is_active` (the `/auth/me` guard test is
     expected to already pass today, by design).

### Out of scope
Scenario 1.8 (no plaintext token in logs — deployment note, not test-checkable per the requirements
doc itself); Option B (warn-but-allow) scenarios — Gate 1 locked Option A; Scenario 3.5's
localization concern; true concurrent/TOCTOU testing on the shared-attempts budget (same
established project convention).

**Gate 2: awaiting user approval.** Developer should read the `greenlet` blocker note and the
cross-cutting `tests/factories.py` risk note above before starting Phase 3.
