# OBJ-005 — Test Report (qa-engineer)

**Summary:** 47 new tests (6 files) covering Stories 1-3 of
`docs/requirements/obj-005-email-verification-flow.md` against `obj-005-design-notes.md` and
`openapi.yaml` (0.6.0-obj-005). Red-phase pass (below) verified correctness by direct reading only —
two environment blockers (Windows Application Control on `initdb`/`greenlet`) prevented live
execution at the time. **Gate 3 round 1 (2026-08-25): independently re-verified by live execution —
full suite 244/244 passed, confirming `developer`'s self-report, zero regressions, `is_verified`
factory-default flip landed safely.** **Gate 3 round 2 (2026-08-25): re-verified after developer's
2 MEDIUM security-fix pass (production/console startup gate + resend-verification timing parity) —
full suite 255/255 passed (244 + 11 new), both fix-specific test groups confirmed real/meaningful,
zero regressions, carry-over `EMAIL_PROVIDER` env-field fixes confirmed accurate.** See "Gate 3
functional-parity verification" and "Gate 3 round 2" sections below.

**Jump to:** "Phase 2 (red phase)" — the 47 new tests, what each asserts, out of scope · "Gate 3
functional-parity verification" — live 244/244 run, `is_verified` flip safety check, 4 spot-checked
OBJ-005 assertions, `/forgot-password`/`notifications.py` deviation confirmation · "Gate 3 round 2 —
security-fix re-verification" — live 255/255 run, `EMAIL_PROVIDER`/production startup-gate fix
sanity check, `/resend-verification-email` timing-parity fix sanity check, carry-over env-field fix
confirmation.

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

---

## Gate 3 functional-parity verification — 2026-08-25

**Verdict: PASS.** Independently confirmed, by live execution (not trusting the self-report alone),
that `developer`'s Phase 3 implementation is green with zero regressions. The `greenlet`/Postgres
blockers noted in Phase 2 are resolved (disposable Postgres 16 on `localhost:5433`, `greenlet`
confirmed working).

### 1. Full suite — live run, not just the 47 owned tests

```
$ pytest -q
244 passed in 104.27s
```

Matches `developer`'s self-report exactly (40 failed/204 passed pre-implementation → 244/244
post-implementation, 0 failures). Re-ran the 47 OBJ-005 files in isolation as a sub-check — all 47
pass within the 244 (`test_verify_email.py` 9, `test_register_email_verification.py` 8,
`test_login_refresh_verification_enforcement.py` 7, `test_resend_verification_email.py` 8,
`test_verification_purpose_isolation.py` 3, `test_email_sender.py` 12).

### 2. `is_verified` factory-default flip (`tests/factories.py`) — confirmed safe, not a lucky pass

`create_user`'s `is_verified` default flipped `False` → `True`, exactly the fix this report's own
Phase 2 section recommended. Confirmed via diff read (not just "tests pass"):

- `tests/api/test_me_endpoint.py:31` — the one call site `developer` reported updating — now passes
  `is_verified=False` explicitly, and the test body still asserts the real unverified-state response
  shape (not a vacuous pass): `assert resp.json()["is_verified"] is False` etc. The other two
  `user_factory()` calls in that file (`grace@example.com`, `heidi@example.com`) were correctly left
  on the new `True` default — read both, neither depends on unverified state.
- `tests/api/test_verify_email.py` and `tests/api/test_login_refresh_verification_enforcement.py`
  each construct their own unverified users via explicit `is_verified=False` at every call site that
  needs that state (`test_login_blocked_for_unverified_user_with_correct_password`,
  `test_login_wrong_password_for_unverified_user_still_returns_generic_credentials_error`, the
  `verify-email` success/reuse/expired/wrong-code tests) — none rely on the factory default, so the
  flip doesn't touch their correctness either way.
- `test_me_endpoint_does_not_reject_an_unverified_user_with_a_pre_existing_access_token` explicitly
  creates a verified user, issues a token, then flips `user.is_verified = False` mid-test to simulate
  a post-issuance downgrade — read in full, this is a real regression guard for over-broad
  enforcement (Scenario 2.A.3), not an artifact of the factory default.
- No other file in the 244-test suite passes `is_verified` explicitly (checked via grep) — all
  ~13+ pre-existing files this report flagged as at-risk (`test_refresh_rotation.py`,
  `test_token_type_enforcement.py`, `test_logout.py`, etc.) now rely on the new `True` default and
  pass, confirming the flip actually fixed the flagged suite-wide regression rather than coincidence.

### 3. Spot-checked OBJ-005 assertions against design notes — all real, none vacuous

Read full test bodies (not just names) for 4 of the highest-value cases:

- **`/auth/register` rollback-on-`EmailSendError` → 503`**
  (`test_register_rolls_back_entirely_when_email_send_fails`,
  `test_register_email_verification.py:141`): asserts `resp.status_code == 503`, then proves the
  rollback with a **fresh `SELECT`** against `db_session` (not the stale response object) confirming
  no `User` row and no `Verification` row survive. Matches design notes §2.3's flush-then-rollback
  mechanism exactly.
- **`/auth/verify-email` success + reuse-rejection** (`test_verify_email.py`): success test asserts
  `is_verified is True` in both the response body AND a `db_session.refresh(user)` re-read, absence
  of `access_token`/`refresh_token` in the body (no auto-login per §2.1), and a separate test proves
  the `Verification` row is actually deleted (fresh `SELECT`, not inferred). Reuse test replays the
  same code and asserts `400` on the second call. All match design §2.1's consume-and-delete pattern.
- **`/auth/login` blocking an unverified user with `400 "Email not verified"`**
  (`test_login_blocked_for_unverified_user_with_correct_password`): asserts exact status `400` and
  `resp.json()["detail"] == UNVERIFIED_DETAIL` (imported constant, not a hardcoded duplicate string
  that could silently drift from `auth.py`'s actual message), plus absence of tokens. Companion test
  (`..._wrong_password_for_unverified_user...`) confirms the message does NOT leak for a wrong
  password (`"Incorrect email or password"` instead) — the oracle-avoidance property design §3.1
  cared about is actually exercised, not just the happy path.
- **Purpose-isolation** (`test_verification_purpose_isolation.py`): confirmed (via file read) it
  creates live `reset_password` and `email_verification` rows for the same email, burns one
  purpose's attempt budget, and asserts the other purpose's `attempts` counter is untouched in the
  DB — the actual mechanism proof `_check_and_consume_otp`'s generalization needed, not a status-code
  check alone.

### 4. `/forgot-password` / `app/core/notifications.py` deviation — confirmed accurate, not a gap

`developer` flagged deviating from design §4.1's first-ordering instruction (retire
`app/core/notifications.py`, migrate `/forgot-password` onto the new `EmailSender`) because OBJ-004
landed first and 3 pre-existing tests patch `notifications.send_otp_notification` by name. Verified
independently:

- `app/core/notifications.py` still exists (no-op `send_otp_notification`, unchanged from OBJ-004);
  `app/api/v1/endpoints/auth.py` still imports `from app.core import notifications` and
  `/forgot-password` still calls `notifications.send_otp_notification(...)` at line 397 — confirmed
  via `git diff`, this call site was NOT touched by this Phase 3 pass, consistent with the claim.
- Exactly 3 test files patch `"app.api.v1.endpoints.auth.notifications.send_otp_notification"` by
  string target: `test_audit_logging.py:446`, `test_otp_hashing_integration.py:81`,
  `test_otp_debug_print_removed.py:108` — matches "3 pre-existing tests" precisely, not an
  approximation.
- **Not left broken or untested**: ran all 26 tests across those 3 files plus the unrelated
  `/forgot-password`-exercising files that do NOT patch `notifications`
  (`test_otp_resend_cooldown.py`, `test_rate_limit.py`'s two `forgot_password` tests,
  `test_timing_side_channel.py`'s three `forgot_password` tests) — all pass, confirming
  `/forgot-password`'s real end-to-end flow (through the no-op `notifications` seam) is still
  genuinely exercised and functionally correct, just not yet migrated onto `EmailSender`. This is an
  accurate, scoped, non-blocking deviation — `EMAIL_VERIFICATION_OTP_TTL_MINUTES`/`EmailSender` are
  fully wired for `/register` and `/resend-verification-email` (the two endpoints this objective
  actually owns); `/forgot-password`'s migration is cleanly deferred, not silently dropped.
- **Residual note (not a defect, tracked for whoever next touches `/forgot-password`):** because
  `/forgot-password` still uses `notifications.py`, the codebase now runs two parallel OTP-delivery
  mechanisms (`EmailSender` for verification/register, `notifications.py` no-op for password reset)
  until a future pass finishes the §4.1 migration — worth a one-line flag in the dependency graph so
  it isn't forgotten, not a blocker for OBJ-005's own Gate 3.

### Verdict summary

PASS. 244/244 observed (matches self-report exactly, no discrepancy). `is_verified` factory flip
confirmed safe by reading, not just by the suite being green. 4 spot-checked OBJ-005 tests all carry
real, design-matching assertions. `/forgot-password`/`notifications.py` deviation confirmed accurate
and non-breaking. No new defects found; one non-blocking residual (dual OTP-delivery mechanisms)
flagged for tracking.

---

## Gate 3 round 2 — security-fix re-verification — 2026-08-25

**Verdict: PASS.** Scope: independently confirm `developer`'s second Phase 3 pass, which fixed the 2
MEDIUM findings `security-specialist` raised in Gate 3 round 1 (`docs/security/audit-report.md`,
"Gate 3 — Verificacion OBJ-005"): (1) production startup must fail-closed if `EMAIL_PROVIDER`
resolves to `"console"`, and (2) `/resend-verification-email` needed the same unconditional
`verify_password_or_dummy` timing-parity call `/forgot-password` already has. This round does not
re-review the rest of OBJ-005 (round 1 above already covers it) — full-suite re-run plus targeted
review of exactly what changed.

### 1. Full suite — live run

```
$ pytest -q
255 passed in 99.43s
```

Matches `developer`'s self-report exactly (244 → 255, +11 new tests, 0 failures, 0 regressions).
`git diff --stat` against the round-1 baseline confirms the file set matches what was expected:
`tests/unit/test_email_provider_startup.py` new (7 tests); `app/core/config.py`,
`app/api/v1/endpoints/auth.py`, `tests/api/test_timing_side_channel.py` modified; plus the two
carry-over files (`tests/api/test_docs_gating.py`, `tests/unit/test_environment_settings.py`) and an
unrelated pre-existing `app/api/deps.py` diff (adds `get_email_sender`/`_email_sender_singleton`,
already covered by round 1's `test_email_sender.py`, not part of this pass's 2 fixes — read, no
regression risk). 7 + 4 = 11, matching 244 → 255 exactly.

### 2. Fix #1 — `Settings.validate_email_provider_not_console_in_production` (`app/core/config.py:157`)

Read the full validator: a `model_validator(mode="after")`, so it sees `ENVIRONMENT` and
`EMAIL_PROVIDER` together (must be cross-field, correctly not a single-field `field_validator` like
`SECRET_KEY`/`POSTGRES_SSL_MODE`). It **raises** `ValueError` when `ENVIRONMENT == "production" and
EMAIL_PROVIDER == "console"` — genuinely fail-closed (blocks `Settings()` construction entirely, not
a `logging.warning`). Confirmed against the 7 tests in `tests/unit/test_email_provider_startup.py`,
each a real subprocess (`python -c "import app.core.config"`) so the `lru_cache`d singleton can't
mask an env-var change within one pytest process — same established technique as
`test_secret_key_startup.py`/`test_postgres_ssl_mode_startup.py`:

- `TestProductionConsoleBlocksStartup` (2 tests) — `production` + `EMAIL_PROVIDER` unset (the actual
  default) and `production` + `EMAIL_PROVIDER="console"` explicit both assert `returncode != 0`. This
  is the exact scenario the MEDIUM finding named ("a deployment that never touches this variable
  boots without error in production") — both genuinely exercise the fail path, not vacuous.
- `TestProductionWithRealProviderPermitsStartup` (3 tests, parametrized `sendgrid`/`ses`/`smtp`) —
  `production` + a non-console value asserts `returncode == 0`. Confirms the validator guards only
  the one named unsafe combination, doesn't over-block production generally (an unimplemented
  provider is `deps.py`'s `NotImplementedError`-at-first-use concern, correctly not duplicated here).
- `TestNonProductionConsolePermitsStartup` (2 tests, parametrized `development`/`staging`) —
  `EMAIL_PROVIDER` unset in non-production asserts `returncode == 0`, confirming the gate is
  production-only and doesn't regress the template's default "console always works" convention for
  dev/staging.

All 7 ran and passed live as part of the 255. Confirms fail-closed behavior on the specific unsafe
combination, and confirms it does NOT over-block (real provider in production; console outside
production) — both directions of the fix genuinely tested, not just the happy path.

### 3. Fix #2 — `/resend-verification-email` timing parity (`app/api/v1/endpoints/auth.py:517`)

Read the diff: `security.verify_password_or_dummy(payload.email, None)` now runs unconditionally,
positioned before the `if not user or user.is_verified: return {...}` fast-path branch — same
placement pattern as `/forgot-password`'s existing call at line 343. Confirmed against the 4 new
tests in `TestResendVerificationEmailConstantTimeGuarantee`
(`tests/api/test_timing_side_channel.py:233-338`), which mirror
`TestForgotPasswordConstantTimeGuarantee`'s existing structure exactly — structural call-count
assertions via `patch(..., wraps=security.verify_password)`, no wall-clock timing anywhere, per this
project's established convention (module docstring restates the "not achievable or sensibly
testable" rationale from `obj-003-design-notes.md` section 3):

- `test_resend_with_nonexistent_email_calls_verify_password_once` — nonexistent email, asserts
  `call_count == 1` (today's pre-fix code has zero calls here — this is the actual oracle).
- `test_resend_with_existing_unverified_email_calls_verify_password_once` — existing, unverified
  user (`is_verified=False` via factory), asserts `call_count == 1` — the "slow path" (extra
  queries/writes/email send) branch.
- `test_resend_with_existing_already_verified_email_calls_verify_password_once` — existing, already-
  verified user (`is_verified=True` via factory), asserts `call_count == 1` — the extra branch this
  endpoint has that `/forgot-password` doesn't (already-verified must be indistinguishable in cost
  from both nonexistent and unverified).
- `test_resend_always_targets_the_dummy_hash_never_a_real_one` — asserts the call's second positional
  arg is `security.DUMMY_PASSWORD_HASH`, never a real user's `hashed_password`, for an existing user.

All 4 read and confirmed non-vacuous: each asserts a specific `call_count`/target-hash value tied to
a distinct branch (nonexistent / existing-unverified / existing-verified / hash-target), together
covering exactly the 4 cases the task asked to sanity-check. All passed live as part of the 255.

### 4. Carry-over `EMAIL_PROVIDER` env-field fix — confirmed accurate, didn't mask anything

`tests/api/test_docs_gating.py` and `tests/unit/test_environment_settings.py` each parametrize
`ENVIRONMENT` over all three values including `"production"`, and both build their subprocess env
from a `BASE_ENV_FIELDS` dict that (pre-fix) never set `EMAIL_PROVIDER`. Once fix #1 landed, every
`production`-parametrized case in these two files would fail `Settings()` construction for an
unrelated reason (the new cross-field validator), masking each file's own actual subject under test
(docs-gating / `ENVIRONMENT` validation) behind an irrelevant failure. The fix adds
`"EMAIL_PROVIDER": "smtp"` to both `BASE_ENV_FIELDS` dicts — a real, non-console provider, so the
production case now reaches the actual behavior each file is testing instead of dying at import.
Read both diffs directly (not just trusting the self-report): confirmed additive-only, no assertions
weakened, no cases skipped or removed, `"smtp"` was already established elsewhere in this pass as an
inert placeholder value (`deps.py`'s factory raises `NotImplementedError` for it only if a request
actually reaches `get_email_sender()`, which neither of these two files' scenarios does). Both files'
full parametrized suites passed live as part of the 255 — the fix does what developer claimed and
did not mask a real failure.

### Verdict summary

PASS. 255/255 observed (matches self-report exactly, 244 baseline + 11 new = 255, no discrepancy).
Both security fixes independently confirmed correct: the production/console startup gate is
genuinely fail-closed (raises, not warns) and correctly scoped (doesn't over-block real providers in
production or console outside production); the resend-verification timing-parity call is
unconditional and correctly positioned, with all 4 branches (nonexistent / unverified / verified /
hash-target) genuinely exercised by structural, non-wall-clock assertions. The 2 carry-over env-field
fixes are accurate and additive-only, not masking anything. No new defects found; no regressions.
