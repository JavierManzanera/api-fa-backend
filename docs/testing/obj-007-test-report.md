# OBJ-007 — Test Report (qa-engineer)

**Summary:** 15 new/changed tests across 3 files, against `docs/api/obj-007-design-notes.md` and
the updated `/auth/register` block in `docs/api/openapi.yaml`. `tests/api/test_register_email_
verification.py` rewritten (13 tests: 7 top-level new-account-branch tests, unchanged status code
narrowed from 201→200 where the response contract changed; 6 new tests in
`TestDuplicateEmailAntiEnumeration` — this objective's actual scope). `tests/api/test_timing_side_
channel.py` gains `TestRegisterConstantTimeGuarantee` (2 tests, bcrypt-hash call-count parity).
`tests/api/test_audit_logging.py`'s `TestRegisterEvent` (2 tests) updated for the new status codes,
internal outcome distinction unchanged. **Red phase only** — `pytest --collect-only` confirms zero
import/collection errors; live execution blocked by the same documented Postgres/`asyncpg`
environment gap OBJ-005 hit (no live test DB in this session — devops-engineer's domain to
provision, not self-provisioned here). Correctness verified instead by direct reading of every new
assertion against the current (pre-OBJ-007) `app/api/v1/endpoints/auth.py` register handler — see
"Verification method" below for the full per-test trace.

**Jump to:** "Phase 2 (red phase) — 2026-08-25" — the 3 files touched, what each new/changed test
asserts, out of scope · "Verification method" — why live execution wasn't possible, and the
per-test reasoning proving each assertion fails for the right reason today · "Deliberately skipped:
live timing measurement" — why §3's bcrypt-hash parity requirement is tested via call-count spy,
not wall-clock.

## Phase 2 (red phase) — 2026-08-25

### `tests/api/test_register_email_verification.py` — full rewrite (13 tests)

New-account branch (response contract changed 201+`UserResponse` → 200+`MessageResponse`; server
effects unchanged from OBJ-005):
- `test_register_new_email_returns_200_generic_message` — asserts the exact body
  `{"msg": GENERIC_REGISTRATION_MESSAGE}` (literal text from design notes §1 / `openapi.yaml`'s
  example, hardcoded in-test — deliberately **not** imported from `auth.py`, where the constant
  doesn't exist yet, to avoid a collection-time import error masking which behavior each test
  checks) and that the body has *only* the `msg` key (no leaked `id`/`email`/etc.).
- `test_register_creates_an_email_verification_row`, `test_register_calls_email_sender_send_with_a_
  six_digit_code_in_the_body` — regression anchors for OBJ-005 server-side effects, updated only
  for the new status code.
- `test_register_rolls_back_entirely_when_email_send_fails`, `test_register_503_response_shape` —
  unchanged (503 rollback path is untouched by OBJ-007 for the new-account branch); **expected to
  already pass today**, kept as regression anchors.
- `test_register_after_rollback_the_email_is_available_again` — retry-after-rollback succeeds with
  the new 200 contract (was 201).
- `test_register_missing_password_returns_422` — unchanged, unaffected by this objective.

`TestDuplicateEmailAntiEnumeration` — the objective's actual point, all new:
- `test_duplicate_email_returns_200_not_400` — the core contract break; today's explicit `400` (the
  audit finding #6 oracle) must be gone.
- `test_response_is_identical_for_new_and_duplicate_email` — **highest-value test in this file**:
  registers a fresh email and a duplicate email in the same test, asserts both response bodies are
  `== {"msg": GENERIC_REGISTRATION_MESSAGE}` via direct JSON equality, not two independently-checked
  status codes — the actual property design notes §1 requires.
- `test_duplicate_email_creates_no_new_user_or_verification_row` — DB-state complement (fresh
  `SELECT`s), confirms zero new rows on the duplicate path.
- `test_duplicate_email_sends_a_notification_not_a_new_otp` — asserts exactly one `EmailSender.send`
  call whose body contains no 6-digit token (distinguishes the new "already have an account" copy
  from an OTP) — deliberately does **not** assert exact wording, since design notes §4 explicitly
  leaves that copy to `developer`/product judgment.
- `test_duplicate_email_returns_503_when_notification_send_fails` — §3's 503 symmetry extended to
  the duplicate branch; also confirms the pre-existing user row is untouched by the failure.
- `test_new_and_duplicate_503_bodies_are_identical` — closes the residual oracle design notes §3
  names explicitly: an attacker who can force `EmailSender` failures must not be able to
  distinguish branches by response content either.

### `tests/api/test_timing_side_channel.py` — new `TestRegisterConstantTimeGuarantee` (2 tests)

Mirrors this file's established `wraps=`/call-count spy convention (no wall-clock timing anywhere,
per the file's own module docstring and this project's OBJ-003 precedent), but wraps
`security.get_password_hash` instead of `verify_password` — `/register`'s real cost driver is a
bcrypt **hash**, not a verify, and (unlike every other class in this file) there's no dummy-vs-real
"target hash" to compare, since `get_password_hash` always hashes whatever it's given.
- `test_register_with_new_email_calls_get_password_hash_once` — regression anchor; the new-account
  branch already does this today.
- `test_register_with_duplicate_email_calls_get_password_hash_once` — the actual new assertion;
  today's duplicate branch never calls it at all.

Docstring flags explicitly: design notes §3 offers two implementation options for the duplicate
branch (call `get_password_hash` unconditionally, recommended — or add a separate dummy-hash
helper). These two tests assume the recommended option; if `developer` takes the alternative, the
tests need a small follow-up patch to target that helper instead — called out in-file so it isn't a
surprise at Gate 3.

### `tests/api/test_audit_logging.py` — `TestRegisterEvent` updated (2 tests, not new)

Both tests' `resp.status_code` assertions moved 201→200 and 400→200. The internal audit-log outcome
assertions (`"success"` / `"duplicate"`) are **unchanged** — design notes §2 explicitly exempts
audit logging from the anti-enumeration constraint, so this is the one place in the codebase that
still legitimately distinguishes the two branches, and the test suite must keep proving that.

### Out of scope

- **Live wall-clock timing measurement** for §3's bcrypt-hash parity — deliberately skipped, same
  established project convention as every other timing-parity test in this codebase since OBJ-003
  (`obj-003-design-notes.md` §3.4: "not achievable or sensibly testable... testable via call-count/
  mock assertions... not via timing measurement"). The call-count spy tests above are the intended,
  sufficient proxy.
- **Exact wording of the duplicate-branch notification email** — design notes §4 explicitly leaves
  this to `developer`/product judgment; only the structural "not an OTP" property is asserted.
- **Rate limiting on `/register`** — design notes §4 confirms this objective does not add one (out
  of Gate 1 scope); no test added or removed for it here.
- **DB query-count asymmetry** between the two branches — design notes §4 accepts this per existing
  `/forgot-password` precedent (OBJ-003 finding #5); not tested here, flagged in design notes as
  `security-specialist`'s call to re-confirm at Gate 3 if desired.

## Verification method — red phase confirmed by reading, not live execution

**Collection confirmed clean:** `pytest --collect-only -q` on all 3 touched files ran cleanly — 44
tests collected, **zero** import/collection errors. This rules out typos/broken imports as the
source of any failure below.

**Live execution blocked:** no reachable Postgres at `TEST_DATABASE_URL` (`localhost:5433` —
`docker --version` → command not found, no Docker Desktop in this session; port-probe timed out).
This is the same documented environment gap `docs/testing/obj-005-test-report.md`'s Phase 2 section
hit and resolved the same way there: provisioning a disposable test database is `devops-engineer`'s
domain (per this project's agent-domain discipline), not self-provisioned by `qa-engineer` mid-task.
All 15 new/changed tests in this pass are in `tests/api/**`, which requires the live DB — none could
be executed.

**Correctness verified instead by direct, complete reading** of the current (pre-OBJ-007)
`register()` handler (`app/api/v1/endpoints/auth.py` lines 203-266) against every new/changed
assertion:

- Today's code: `@router.post("/register", response_model=UserResponse,
  status_code=status.HTTP_201_CREATED)`; on a duplicate email, raises `HTTPException(400, "The user
  with this email already exists...")` immediately, before any bcrypt-hash or `EmailSender` call on
  that branch; on a new email, returns the created `User` ORM object (serialized as `UserResponse`)
  at `201`.
- Every test asserting `resp.status_code == 200` on either branch **fails today** on that exact
  line — current responses are `201` (new) / `400` (duplicate), never `200`. This is true for all 7
  top-level new-account tests (fails at the status-code assertion, before reaching any row/body
  checks that would otherwise already pass) and all 6 `TestDuplicateEmailAntiEnumeration` tests
  (fails at `200 != 400`).
- `test_duplicate_email_sends_a_notification_not_a_new_otp` and
  `test_duplicate_email_returns_503_when_notification_send_fails` fail for the *additional*,
  deeper reason that the duplicate branch never reaches any `EmailSender` call at all today (the
  `HTTPException` raise happens first) — confirmed the override wiring (`_override_email_sender`,
  identical mechanism already proven working by the pre-existing, currently-passing new-account
  `EmailSender` tests in this same file) is not itself the point of failure.
- `TestRegisterConstantTimeGuarantee.test_register_with_duplicate_email_calls_get_password_hash_
  once` fails for the same reason: `security.get_password_hash` is never called on today's duplicate
  branch (confirmed via reading — the only `get_password_hash` call in `register()` is inside the
  new-`User` construction, unreachable once the duplicate check has already raised).
- **Two tests are expected to already PASS today**, kept as explicit regression anchors, not
  red-phase failures: `test_register_rolls_back_entirely_when_email_send_fails` /
  `test_register_503_response_shape` (the new-account 503/rollback path is untouched by OBJ-007) and
  `test_register_missing_password_returns_422` (422 validation is untouched). This matches this
  project's established convention (OBJ-001–OBJ-005 test reports) of explicitly flagging
  already-green anchors rather than presenting every test in a red-phase file as failing.
- `test_register_with_new_email_calls_get_password_hash_once` (the regression-anchor half of the new
  timing class) still **fails today**, not because the hash call is missing (it already happens),
  but because the test also asserts `resp.status_code == 200` — today `201`. Noted so this isn't
  mistaken for a flaky/incorrect assertion.

No test in this pass fails due to a missing fixture, a bad import, or a typo — every failure traces
to either the still-`201`/`400` response contract or the entirely-missing duplicate-branch
bcrypt-hash/`EmailSender`/`503` behavior, exactly the gap `developer`'s Phase 3 pass needs to close.

**Recommendation for Gate 3:** once a devops-provisioned test Postgres is available, re-run this
file set live before signing off — this report's confidence rests on careful reading, not an
executed red run, which is a materially weaker form of verification than OBJ-005's own Gate 3 round
(live 244/244) and should not be treated as equivalent.

**Gate 2: awaiting user approval.**
