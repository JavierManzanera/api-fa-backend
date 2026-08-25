# OBJ-009 — Register Rate Limit — Test Report

> **Summary (read this, skip the rest unless you need detail):**
> - **Status:** Phase 2 (red phase) complete for test authoring. **Execution blocked** by a pre-existing, suite-wide environment issue unrelated to these tests (see §2) — red-phase confirmation below is via static code inspection + collection check, not an actual pytest run. Re-run once §2's blocker is cleared, before `developer` starts, and again at Gate 3.
> - **File:** `tests/api/test_register_rate_limit.py` — 6 tests (4 top-level + 2 in `TestRateLimitDoesNotReopenEnumeration`).
> - **Covers:** 5/min threshold + 429 on the 6th request, `Retry-After` header presence, sliding-window reset via `freeze_time`, and — the actual point of this objective — that the 429 threshold and body are identical whether the traffic hits the new-account or duplicate-email branch of `/register` (guards design notes §2/§4's "must not become a new enumeration side channel" constraint).
> - **Out of scope:** implementation itself (that's `developer`'s job next); OpenAPI spec changes (already done by `solution-architect` in the Gate 1 commit — verified present, no change needed here, see §3).
> - **OpenAPI:** `docs/api/openapi.yaml`'s `/auth/register` already had `'429': $ref: '#/components/responses/RateLimited'` as of commit `98d0388` — no edit made.
> - **Red-phase confirmation:** not run-confirmed due to the environment blocker; statically confirmed instead (`app/api/v1/endpoints/auth.py`'s `register()` has no `enforce_rate_limit` call and no `REGISTER_RATE_LIMIT_PER_MINUTE` constant as of this branch's HEAD) — every `429`-asserting test in the new file is expected to fail on the first assertion after 5 requests (it will keep getting `200`s and never see a `429`), which is a correct red failure, not a broken test.
> - **Flakiness/environment risk:** `tests/api/**` needs Postgres at `TEST_DATABASE_URL` (port 5433 confirmed listening in this environment) — same requirement as every other API test file, nothing new introduced here.

## Jump-to index

- [§1 — Test file: what's covered](#1--test-file-whats-covered) — the 6 tests, grouped by intent.
- [§2 — Execution blocker: environment, not test content](#2--execution-blocker-environment-not-test-content) — the `ModuleNotFoundError: No module named 'jose'` that currently blocks 100% of `tests/api/**`, reproduced against a pre-existing file to prove it isn't caused by this new one.
- [§3 — OpenAPI contract check](#3--openapi-contract-check) — confirmed already present, no change made.
- [§4 — Red-phase confirmation method](#4--red-phase-confirmation-method) — static-inspection substitute for an actual pytest run, and what to re-check once the blocker clears.

---

## §1 — Test file: what's covered

`tests/api/test_register_rate_limit.py`, mirroring `tests/api/test_rate_limit.py` and `tests/api/test_resend_verification_email.py`'s established style (module-level `_register()` helper, local literal `REGISTER_RATE_LIMIT_PER_MINUTE = 5` constant — not imported from `auth.py`, per this project's existing convention of not importing a symbol that doesn't exist yet, which would fail the whole file at collection).

Top-level (module-scope) tests:
1. `test_register_rate_limited_after_5_requests_per_ip_email` — repeats the SAME email 6 times; request 1 hits the new-account branch, requests 2-6 hit the duplicate-email branch (the email now exists) — this naturally exercises the shared-budget property across a branch transition mid-run. Asserts `[200]*5 + [429]`.
2. `test_register_429_response_carries_retry_after` — asserts the `Retry-After` header is present on the 429, matching `openapi.yaml`'s `RateLimited` component.
3. `test_register_rate_limit_resets_after_window_elapses` — uses `freezegun.freeze_time` to advance 61s past the 60s window and confirms a fresh request succeeds again (sliding window, not permanent lockout).
4. `test_register_missing_password_returns_422` — quick regression guard on existing validation behavior, unrelated to rate limiting directly.

`TestRateLimitDoesNotReopenEnumeration` (the actual point of this objective, per design notes §2/§4):
5. `test_duplicate_email_only_traffic_is_also_rate_limited_after_5` — pre-creates the user via `user_factory` so EVERY request in the test hits the duplicate-email branch exclusively (no new-account call at all), and asserts the same 5-then-429 threshold. Catches a future implementation that only wires `enforce_rate_limit` into `_handle_new_email_registration` and leaves duplicate-email traffic completely unthrottled — the original finding #16 DoS-amplification shape.
6. `test_429_body_is_identical_whether_the_email_is_new_or_already_registered` — exhausts the limit independently for a never-before-seen email (new-account branch) and a pre-existing email (duplicate branch), then asserts the two resulting 429 responses are byte-for-byte identical (status, JSON body, and the exact `Retry-After` value) — the direct test for design notes §2's "must not become a new anti-enumeration side channel on top of OBJ-007's finding #6" constraint.

Not covered (explicitly out of scope): the rate limiter's own unit-level mechanics (already covered by `tests/unit/` for `app/core/rate_limit.py`, unchanged by this objective); X-Forwarded-For spoofing resistance for `/register` specifically (already proven generically for the shared `client_ip()`/`enforce_rate_limit` mechanism by `tests/api/test_rate_limit_ip_spoofing.py` against `/forgot-password` — same code path, no `/register`-specific variant needed per that file's own "prove it once, cross-reference elsewhere" convention).

## §2 — Execution blocker: environment, not test content

Running `pytest tests/api/test_register_rate_limit.py -v` fails at fixture setup for every test with:

```
app\api\deps.py:5: in <module>
    from jose import jwt, JWTError
E   ModuleNotFoundError: No module named 'jose'
```

This is **not** caused by the new test file. Reproduced identically against the pre-existing, previously-passing `tests/api/test_resend_verification_email.py` (8/8 tests, same error, same line). Root cause: this branch (`obj-009-register-rate-limit`) still imports `python-jose` in `app/api/deps.py` and `app/core/security.py` (the PyJWT migration is a separate, unmerged objective — OBJ-008, `obj-008-pyjwt-migration` branch) — but the shared Python environment currently has `PyJWT==2.13.0` installed and **not** `python-jose`. `pip show python-jose` confirms it's absent; `requirements.txt`/`requirements.lock.txt` both still pin `python-jose[cryptography]==3.5.0` for this branch. This looks like cross-branch environment drift from a concurrent OBJ-008 session sharing the same global `site-packages` (no per-worktree venv in use here) rather than anything wrong with this branch's own dependency files.

Per this project's agent-domain discipline (CLAUDE.md directive #6, "installing packages" is explicitly named as `devops-engineer`'s domain), I did not `pip install python-jose` myself to work around this. Flagging back to the orchestrator: `devops-engineer` should restore `python-jose` in this shared environment (or move to isolated per-worktree venvs, the same fix already adopted for git worktree isolation) before `developer` or a Gate-3 verification pass can run anything in `tests/api/**` on this branch — this blocks the whole suite, not just the new file.

Confirmed unaffected: Postgres is reachable (port 5433 listening, matching `TEST_DATABASE_URL`'s default) — this is not a database blocker.

## §3 — OpenAPI contract check

`docs/api/openapi.yaml`, `/auth/register` → `post` → `responses`, already contains (as of commit `98d0388`, `solution-architect`'s Gate 1 commit):

```yaml
'429':
  $ref: '#/components/responses/RateLimited'
```

positioned between `'422'` and `'503'`, ascending-status-code order, matching every other multi-error-response path in the file. The shared `RateLimited` component (`Retry-After` header + `HTTPError` body) was already defined pre-existing (used by `/forgot-password`, `/verify-otp`, `/verify-email`, `/resend-verification-email`, `/reset-password`). No new component needed. **No edit made to `openapi.yaml`** — task step 2 was already satisfied by Gate 1.

## §4 — Red-phase confirmation method

Since §2's blocker prevents an actual pytest run, red-phase status was confirmed by two substitute checks instead:

1. **Collection check** — `pytest tests/api/test_register_rate_limit.py --collect-only -q` succeeds cleanly: 6 tests collected, no syntax/import errors in the test file itself (collection does not trigger the `client` fixture, so it doesn't hit §2's blocker).
2. **Static code inspection** — `grep -n "RATE_LIMIT_PER_MINUTE\|enforce_rate_limit" app/api/v1/endpoints/auth.py` shows `FORGOT_PASSWORD_RATE_LIMIT_PER_MINUTE`, `VERIFY_OTP_RATE_LIMIT_PER_MINUTE`, `RESET_PASSWORD_RATE_LIMIT_PER_MINUTE`, `VERIFY_EMAIL_RATE_LIMIT_PER_MINUTE`, `RESEND_VERIFICATION_RATE_LIMIT_PER_MINUTE` and five `enforce_rate_limit` call sites (`/forgot-password`, `/verify-otp`, `/verify-email`, `/resend-verification-email`, `/reset-password`) — but **no** `REGISTER_RATE_LIMIT_PER_MINUTE` constant and **no** `enforce_rate_limit` call anywhere in `register()` (`auth.py:220-252`, read in full — the handler goes straight from `rate_limit.client_ip(http_request)` to the `SELECT User` lookup with nothing in between). Every request in every new test will therefore receive `200` (or, for the pre-existing-user variant, still `200` via the duplicate branch) indefinitely, with no `429` ever produced — so every test's `429`/threshold assertion is expected to fail, for exactly the right reason (missing implementation), not a fixture bug or a trivially-true assertion.

**Action for whoever runs this next:** once §2's environment blocker is cleared, run `pytest tests/api/test_register_rate_limit.py -v` and confirm the failure mode matches this prediction (6 failures, all on a `429`/threshold assertion, none on setup/collection) before treating this as a valid red baseline — if instead something errors at setup/collection, that's a different, newly-introduced problem to fix, not this document's prediction.
