# OBJ-009 — Register Rate Limit — Test Report

> **Summary (read this, skip the rest unless you need detail):**
> - **Status:** Gate 3 PASSED (2026-08-25, qa-engineer). Full suite run independently against an isolated venv + disposable Postgres, not trusting the developer's self-report — **281 passed, 0 failed** (280 pre-existing + 1 new structural guard added this pass). The Phase 2 §2 environment blocker (`ModuleNotFoundError: jose`) is fully resolved — this branch now has its own `.venv` built from its own lockfiles.
> - **File:** `tests/api/test_register_rate_limit.py` — now **7 tests** (4 original top-level + 2 in `TestRateLimitDoesNotReopenEnumeration` + 1 new top-level structural guard, see §8).
> - **Covers:** 5/min threshold + 429 on the 6th request, `Retry-After` header presence, sliding-window reset via `freeze_time`, byte-identical 429 body/headers regardless of branch, and (new) a source-inspection guard that `enforce_rate_limit` is called exactly once, only inside `register()`, with the literal `scope="register"`.
> - **Out of scope:** implementation itself (already done, verified below); OpenAPI spec changes (already done by `solution-architect`, verified present, no change).
> - **Anti-enumeration re-verification (§7):** PASS — reasoned through the specific failure mode of a same-scope two-call-site split (which would pass every *behavioral* test unchanged) and confirmed the new structural test (§8) is what actually closes that gap; the two pre-existing behavioral tests were also confirmed to correctly fail against a hypothetical different-scope-per-branch implementation (traced by hand, not just read).
> - **Scope-collision check (§6):** PASS — `scope="register"` is one of exactly 6 distinct scope-string literals across the whole codebase (`register`, `forgot_password`, `verify_otp`, `verify_email`, `resend_verification_email`, `reset_password`), 6 `enforce_rate_limit` call sites total, one per endpoint. No collision.
> - **Flakiness/environment risk:** unchanged — `tests/api/**` needs Postgres at `TEST_DATABASE_URL`; this pass used a disposable instance on port 5434 (5433 was occupied by concurrent Gate-3 work on another worktree) — no risk carried forward, nothing project-permanent about the port choice.

## Jump-to index

- [§1 — Test file: what's covered](#1--test-file-whats-covered) — the original 6 tests, grouped by intent.
- [§2 — Execution blocker: environment, not test content](#2--execution-blocker-environment-not-test-content) — historical (Phase 2); resolved as of §5 below.
- [§3 — OpenAPI contract check](#3--openapi-contract-check) — confirmed already present, no change needed.
- [§4 — Red-phase confirmation method](#4--red-phase-confirmation-method) — static-inspection substitute used during Phase 2, superseded by the real run in §6.
- [§5 — Gate 3 environment: isolated venv + disposable Postgres](#5--gate-3-environment-isolated-venv--disposable-postgres) — how this independent verification pass was provisioned.
- [§6 — Gate 3 full suite result](#6--gate-3-full-suite-result) — 281 passed, 0 failed, exact commands run.
- [§7 — Anti-enumeration and scope-collision re-verification](#7--anti-enumeration-and-scope-collision-re-verification) — the two checks the orchestrator specifically asked to double-check, reasoned through by hand.
- [§8 — New structural regression guard added](#8--new-structural-regression-guard-added) — one new test closing a blind spot the behavioral tests couldn't cover.

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

---

## Gate 3 — Functional Verification (2026-08-25, qa-engineer)

Per this project's Gate discipline, the developer's self-reported test results were **not** trusted — everything below was independently re-derived from a clean checkout of `origin/obj-009-register-rate-limit` (commits `98d0388`, `3aca16a`, `6b4bb19`, `5bbf20f`), in a fresh worktree, on a second local branch (`obj-009-qa-verify`, tracking the same remote ref) since another worktree already held `obj-009-register-rate-limit` for concurrent Gate-3 work by another agent.

### §5 — Gate 3 environment: isolated venv + disposable Postgres

- **venv:** built fresh, from this checkout's own `requirements-dev.lock.txt` (`python -m venv .venv-qa-verify` against a local Python 3.11.8 interpreter, then `pip install -r requirements-dev.lock.txt`). Confirmed `python-jose==3.5.0` present and `PyJWT` absent — correct for this branch (the PyJWT migration is unmerged OBJ-008), matching this doc's §2 root-cause analysis and `tests/README.md`'s per-worktree/per-checkout venv convention (2026-08-25, devops-engineer). Did not touch or rely on any global/shared interpreter.
- **Postgres:** port 5433 (the documented default) was already occupied — `netstat` showed a listener there, almost certainly a concurrent Gate-3 pass on another worktree for this same branch. Provisioned an independent disposable instance instead: `initdb`/`pg_ctl` from `C:\Program Files\PostgreSQL\16\bin`, own data directory under the scratchpad temp path, port **5434**, `trust` auth, `test`/`test` role + `api_fa_test` database created to match `TEST_DATABASE_URL`'s shape. Stopped (`pg_ctl stop -m fast`) after the run — nothing left running.
- `TEST_DATABASE_URL=postgresql+asyncpg://test:test@localhost:5434/api_fa_test` exported for every pytest invocation below.

### §6 — Gate 3 full suite result

```
pytest --collect-only -q     -> 280 tests collected, no ModuleNotFoundError (before adding §8's new test)
pytest -q                    -> 280 passed in 120.16s   (before §8's addition)
pytest tests/api/test_register_rate_limit.py -v -> 6/6 passed (before §8's addition)
```

After adding §8's new structural test:

```
pytest tests/api/test_register_rate_limit.py -v -> 7/7 passed, 10.64s
pytest -q                                        -> 281 passed in 122.74s (0:02:02), 0 failed
```

**Verdict: PASS.** Exact count: **281 passed, 0 failed, 0 errors, 0 skipped.**

**Scope-collision check (task step 5):** `grep -n "scope="` across `app/` shows exactly 6 `enforce_rate_limit` call sites in `app/api/v1/endpoints/auth.py`, one per endpoint, with 6 distinct scope-string literals: `register`, `forgot_password`, `verify_otp`, `verify_email`, `resend_verification_email`, `reset_password`. `app/core/rate_limit.py` itself never hardcodes a scope value (it's always the caller-supplied parameter). No two endpoints share a scope string, so no endpoint's traffic can count against another's budget — PASS, no collision.

### §7 — Anti-enumeration and scope-collision re-verification

Task step 4 asked specifically to re-verify that (a) duplicate-email-only traffic is throttled at the same threshold as new-email traffic, and (b) the 429 body/headers are byte-identical regardless of branch — and to add a targeted check if there was any doubt these were airtight.

**Code-level confirmation first (not just trusting the tests):** read `app/api/v1/endpoints/auth.py`'s `register()` in full (lines 227–279). `enforce_rate_limit(db, scope="register", ip=ip, email=user_in.email, limit=REGISTER_RATE_LIMIT_PER_MINUTE)` is the first statement after computing `ip`, unconditionally, before the `SELECT User` lookup that decides which branch runs. `grep -c "enforce_rate_limit("` across the whole `app/` tree returns exactly 6 (one per endpoint) — confirmed there is no second call site anywhere for `/register`.

**Re-ran and confirmed green:**
- `test_duplicate_email_only_traffic_is_also_rate_limited_after_5` — pre-creates the user via `user_factory` so all 6 requests hit the duplicate-email branch exclusively; asserts `[200]*5 + [429]`. PASS.
- `test_429_body_is_identical_whether_the_email_is_new_or_already_registered` — exhausts the limit independently for a never-seen email and a pre-existing email, asserts identical JSON body and identical `Retry-After` value on both 429s. PASS.

**Doubt check — was there a gap these two tests could miss?** Traced through the hypothetical regression design notes §4 point 1 explicitly warns about: a future edit that splits `enforce_rate_limit` into two call sites, one inside `_handle_new_email_registration` and one inside `_handle_duplicate_email_registration`.

- If the two call sites used **different** `scope` strings (e.g. `register_new` / `register_duplicate`): traced by hand — in `test_register_rate_limited_after_5_requests_per_ip_email` (request 1 = new branch, requests 2–6 = duplicate branch), the duplicate-branch counter would only have accumulated 4 hits by request 6, so request 6 would wrongly return `200` instead of `429`. This is caught — the existing test would fail, correctly.
- If the two call sites used the **same** `scope="register"` and same `limit`: only one branch executes per request, so the observed 200/429 sequence and response bodies would be *identical* to the correct single-call-site implementation — **none of the 6 behavioral tests would fail**. This is a real blind spot, not a hypothetical worry: it exactly matches design notes §4 point 1's own stated concern ("two call sites, even with identical arguments today, is a maintenance hazard"), and nothing observable from the HTTP layer would ever catch it drifting later.

This gap is real, so per task step 4's instruction, a new targeted check was added rather than treating the existing 6 as sufficient — see §8.

### §8 — New structural regression guard added

Added `test_register_rate_limit_call_site_is_singular_and_shared` to `tests/api/test_register_rate_limit.py` (bottom of file). Uses `inspect.getsource()` on `register`, `_handle_new_email_registration`, and `_handle_duplicate_email_registration` individually to assert, by source inspection rather than HTTP behavior:

1. `register()`'s own body contains exactly one `enforce_rate_limit(` call.
2. Neither `_handle_new_email_registration` nor `_handle_duplicate_email_registration` contains any `enforce_rate_limit(` call.
3. `register()`'s call uses the literal `scope="register"`.

This closes exactly the blind spot identified in §7 — a same-scope two-call-site split would still fail this test even though it would pass every behavioral one. Ran standalone and as part of the full suite: PASS in both (see §6). Test count: file now has 7 tests (was 6); full suite now 281 (was 280).

**Not in scope for this addition:** re-litigating the `limit=REGISTER_RATE_LIMIT_PER_MINUTE` value or window (already covered by the original 6 tests); IP-spoofing resistance for `/register` specifically (already covered generically for the shared `client_ip()` mechanism per §1's "prove it once" convention, unchanged by this objective).

**Flakiness/environment risk carried forward:** none new. The disposable Postgres instance and venv used for this pass were both local and torn down / left in place under `.venv-qa-verify` (gitignored, not committed) respectively — a future Gate-3 pass on this same branch should still follow `tests/README.md`'s per-checkout venv convention rather than assuming this one persists.
