# OBJ-013 — Rate Limiter Keying Hardening — Test Report

> **Summary (read this, skip the rest unless you need detail):**
> - **Status:** Phase 2 (red phase) COMPLETE, verified 2026-08-25 by `qa-engineer`. Two new files, **8 new tests**: `tests/api/test_rate_limit_keying.py` (7 tests) + `tests/unit/test_rate_limit_ip_multiplier_setting.py` (1 test). Authored by a prior, session-truncated `qa-engineer` run in a now-stale worktree (`agent-aa5dbabe02925d348`, branch `obj-013-work`); copied verbatim (byte-for-byte diff confirmed), independently read, and independently executed by this pass — not re-authored.
> - **Result: 4 RED, 4 GREEN, exactly matching the files' own docstring predictions, for the right reasons.** RED: `TestEmailRotationBypassNowClosed` (2 tests, `AssertionError 200 != 429` — no IP-only check exists yet), `TestDimensionParitySymmetric` (1 test, same reason), `test_rate_limit_ip_multiplier_setting_defaults_to_five` (1 test, `AttributeError: 'Settings' object has no attribute 'RATE_LIMIT_IP_MULTIPLIER'`). GREEN (regression guards, must stay true after the fix too): `TestSpoofedXffRotationRegressionGuard`, `TestLegitimateSharedIpTrafficNotThrottled`, `TestOriginalPerEmailLimitsUnchanged` (2 tests).
> - **Real finding, not a broken test (§2):** `obj-013-rate-limiter-keying`'s tip (`a7db0ef`) was cut from `main` *before* OBJ-009 (register rate limiting, PR #10) merged — so `/auth/register` initially had **zero** rate limiting on this branch, which the design doc's own §4 table anticipated ("None (pending merge via OBJ-009; this design applies automatically once merged)") but which broke `TestSpoofedXffRotationRegressionGuard` (expected green, was red for an unrelated reason). Fixed by merging `origin/main` into this branch (clean, no conflicts, commit `11f6027`) before running the suite — not by touching the test.
> - **Full suite: 294 tests, 290 passed, 4 failed — the exact 4 documented red tests, zero regressions** across the other 290 (286 pre-existing + 4 new green).
> - **Design doc:** `docs/api/obj-013-design-notes.md` — read in full before this pass; §3's exact signature and §4's call-site table are what the red tests assert against.
> - **Out of scope:** implementation (`app/core/rate_limit.py`, `app/core/config.py`'s `RATE_LIMIT_IP_MULTIPLIER`) — zero app code touched this pass, confirmed before and after.
> - **Flakiness/environment risk:** `tests/api/**` needs Postgres; this pass used a disposable `initdb`/`pg_ctl` instance on port 5544 (avoiding 5433/5434 in case of concurrent worktree use), torn down after. No project-permanent port choice.

## Jump-to index

- [§1 — Files copied, and provenance](#1--files-copied-and-provenance) — where the tests came from, verbatim-copy proof.
- [§2 — Branch staleness finding: OBJ-009 not yet merged onto obj-013's tip](#2--branch-staleness-finding-obj-009-not-yet-merged-onto-obj-013s-tip) — the one real discrepancy found, and the fix applied.
- [§3 — What's RED today, and why that's correct](#3--whats-red-today-and-why-thats-correct) — 4 tests, each traced to the specific missing piece.
- [§4 — What's GREEN today, and why that's correct](#4--whats-green-today-and-why-thats-correct) — 4 regression-guard tests, each traced to why current code already satisfies them.
- [§5 — Full suite result](#5--full-suite-result) — 294 total, 290 passed, 4 failed, exact commands.
- [§6 — Out of scope](#6--out-of-scope) — what this pass deliberately did not touch or assert.

---

## §1 — Files copied, and provenance

Copied verbatim (byte-for-byte `diff` confirmed identical) from the stale, uncommitted worktree `C:\Users\jmanz\Documents\workspace\projects\api-fa-backend\.claude\worktrees\agent-aa5dbabe02925d348` (branch `obj-013-work`), left behind by a prior `qa-engineer` run that was cut off by a session-limit error before it could commit:

- `tests/api/test_rate_limit_keying.py` (326 lines, 7 test methods across 5 classes)
- `tests/unit/test_rate_limit_ip_multiplier_setting.py` (32 lines, 1 test function)

Both files were read in full by this pass (not just diffed) before trusting their docstrings' RED/GREEN predictions. Both carry unusually detailed docstrings explicitly stating which classes are expected red/green today and why — this report independently verifies those claims by execution, below.

## §2 — Branch staleness finding: OBJ-009 not yet merged onto obj-013's tip

`obj-013-rate-limiter-keying`'s tip (`a7db0ef`, the design-notes-only commit) is **not** an ancestor of `origin/main` (`git merge-base --is-ancestor a7db0ef origin/main` → false). `main` has since merged PR #10 (`obj-009-register-rate-limit`, commit `5bbf20f` "feat(obj-009): enforce rate limiting on POST /auth/register"), which the design doc's §4 table explicitly anticipated but does not itself contain:

> "`POST /auth/register` ... Call-site diff needed: **None (pending merge via OBJ-009; this design applies automatically once merged)**"

Running the new suite against `a7db0ef` as-is confirmed the practical consequence: `app/api/v1/endpoints/auth.py`'s `register()` had **zero** `enforce_rate_limit` call at all (grep confirmed only 5 call sites, not 6). This made `TestSpoofedXffRotationRegressionGuard` fail — not because of anything related to finding #17's keying bug, but because `/register` had no rate limiting whatsoever yet on this branch, an unrelated already-fixed-upstream prerequisite gap.

**Fix applied:** `git merge --no-commit --no-ff origin/main` — completed automatically with zero conflicts (the two branches touch disjoint files: `obj-013`'s design doc vs. `obj-009`'s `auth.py`/rate-limit test file). Committed as `11f6027` on `obj-013-rlk-qa` (this pass's local branch name; pushed to the correctly-named remote `obj-013-rate-limiter-keying` — see final commit note). After the merge, `register()` gained its `scope="register"` `enforce_rate_limit` call (confirmed via grep) and `tests/api/test_register_rate_limit.py` (7 tests) came in with it, raising full-suite collection from 287 to 294. Re-running the new suite after the merge flipped `TestSpoofedXffRotationRegressionGuard` from red to green, matching its docstring's original claim — confirming this was a branch-staleness artifact, not a test defect.

This is flagged explicitly per this pass's instructions to treat any docstring/reality mismatch as a real finding rather than silently forcing green. No test file content was altered to produce this fix — only the branch's base was brought current with an already-merged, already-closed prerequisite objective.

## §3 — What's RED today, and why that's correct

All 4 failures were inspected individually; each fails for exactly the missing-implementation reason its docstring predicts, not an unrelated bug:

1. **`TestEmailRotationBypassNowClosed::test_distinct_emails_same_ip_throttled_at_26th_request`** — 26 requests, same real IP, 26 distinct never-repeated emails. Expected: first 25 succeed, 26th is `429` (IP-only check). Got: all 26 return `200` (`assert 200 == 429`). Confirms no IP-only check exists yet — the exact bypass finding #17 describes.
2. **`TestEmailRotationBypassNowClosed::test_distinct_emails_same_ip_429_carries_retry_after`** — same root cause; the 26th request that should 429 instead returns `200`.
3. **`TestDimensionParitySymmetric::test_429_body_and_headers_identical_whether_ip_or_email_dimension_tripped`** — its IP-triggered half depends on the same not-yet-implemented check; fails at `assert ip_triggered_resp.status_code == 429` (got `200`) before ever reaching the body/header parity assertion. The email-triggered half (not shown as a separate failure since the test fails on its first assertion) would pass on its own — consistent with the email-keyed path being unchanged.
4. **`test_rate_limit_ip_multiplier_setting_defaults_to_five`** — `AttributeError: 'Settings' object has no attribute 'RATE_LIMIT_IP_MULTIPLIER'`, raised by pydantic's `Settings.__getattr__`. Confirms the field genuinely does not exist in `app/core/config.py` yet (grep confirmed zero occurrences of `RATE_LIMIT_IP_MULTIPLIER` in `app/core/`). A clean `AttributeError`, not a masked import or fixture error — the right kind of red for a not-yet-added setting.

## §4 — What's GREEN today, and why that's correct

All 4 pass for the reasons their regression-guard docstrings state — verified by reading the assertion path, not just the pass/fail color:

1. **`TestSpoofedXffRotationRegressionGuard::test_spoofed_xff_per_request_does_not_change_real_throttle_key`** — sends a different (fake, untrusted) `X-Forwarded-For` per request but the same real IP and same email. Since `TRUSTED_PROXY_COUNT=0` (suite default), the header is ignored; the real `(ip, email)` pair is constant, so today's single combined query already throttles at request 6. Passes now only because of the OBJ-009 merge in §2 (register previously had no rate limiting to trip at all).
2. **`TestLegitimateSharedIpTrafficNotThrottled::test_20_distinct_emails_same_ip_under_ip_threshold_all_succeed`** — 20 distinct emails, one shared IP, all succeed. True today because the current code has no IP-only check to false-positive on (each distinct-email request never repeats the current AND-keyed triple), and will remain true after the fix since 20 < the new 25/min IP threshold.
3. **`TestOriginalPerEmailLimitsUnchanged::test_forgot_password_still_429s_on_6th_request_same_email_and_ip`** — same `(ip, email)` repeated 6 times against `/forgot-password` (an endpoint unaffected by the OBJ-009 merge, already had rate limiting) — trips the existing 5/min email limit today, unchanged by this objective's scope.
4. **`TestOriginalPerEmailLimitsUnchanged::test_verify_otp_still_429s_on_11th_request_same_email_and_ip`** — same pattern against `/verify-otp`'s existing 10/min limit; intermediate statuses are legitimately `400` (wrong OTP / lockout, a separate mechanism), only the final 11th-request `429` is asserted, matching the file's own noted precedent in `test_rate_limit.py`.

## §5 — Full suite result

Environment: this worktree's own `.venv` (Python 3.11.8, built from `requirements-dev.lock.txt`), disposable Postgres 16 via `initdb`/`pg_ctl` (port 5544, `trust` auth, own data directory outside the repo, torn down after this pass).

```
TEST_DATABASE_URL=postgresql+asyncpg://test:test@localhost:5544/api_fa_test \
  .venv/Scripts/python -m pytest -q
```

**294 collected, 290 passed, 4 failed, 0 errors — 473.54s.** The 4 failures are exactly the 4 listed in §3, nothing else. Collection was clean both before and after adding the two new files (`pytest --collect-only -q` — no import errors), confirming the new files import and collect without requiring any app-code change, per the task's requirement. 286 pre-existing tests + 4 new green tests = 290 passed; 4 new red tests = 4 failed. Zero regressions.

## §6 — Out of scope

- **Implementation** (`app/core/rate_limit.py`'s two-independent-checks rewrite, `app/core/config.py`'s `RATE_LIMIT_IP_MULTIPLIER` field) — `developer`'s Gate 2/3 step, not touched here. Confirmed untouched both before this pass (grep for `RATE_LIMIT_IP_MULTIPLIER` = 0 hits) and after (no app-code diff in this pass's commits, only test files + this report + the OBJ-009 merge-forward).
- **`database-architect`'s flagged index follow-up** (design notes §4: a new `ix_rate_limit_hits_scope_email_created_at` index) — not this role's artifact; not applied or tested here.
- **The residual fully-distributed-attacker gap** (design notes §6: unique IP *and* unique email per request defeats both independent checks) — explicitly out of scope for finding #17's keying fix per the design doc; no test asserts this is closed, because it isn't meant to be by this objective.
- **CIDR/subnet-bucketed IP keying, global circuit-breaker ceiling, CAPTCHA** — design-doc backlog items (§2/§6), not implemented or tested, consistent with the design doc's own scope boundary.
