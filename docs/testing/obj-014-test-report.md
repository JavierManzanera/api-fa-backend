# OBJ-014 — Test Report: Rate Limiter Reserved-Slot DoS Mitigation (Finding #20) + Settings Validators (Finding #21)

> **Summary (read this, skip the rest unless you need detail):**
> - **Status: Gate 3 — VERIFICATION PASS, PASS.** This is a verification-only pass (no red phase authored here — TDD red→green was already done by `developer` per `docs/api/obj-014-design-notes.md` §9; this file independently re-confirms it).
> - **Files verified:** `tests/api/test_rate_limit_reserved_slots.py` (5 tests, new), `tests/unit/test_rate_limit_settings_validators.py` (14 tests, new — design doc §9 says "15", actual collected count is 14; documentation-count discrepancy only, not a functional gap — see §4 below), plus 8 pre-existing regression tests across `tests/api/test_rate_limit.py`, `test_rate_limit_ip_spoofing.py`, `test_rate_limit_keying.py` (×2), `test_register_rate_limit.py` (×3), `test_resend_verification_email.py`, all updated from threshold `limit` to `limit - 1`.
> - **Independently reproduced and confirmed correct:** the "limit − reserved" mechanism for a single non-rotating (IP, email) pair, traced line-by-line against `app/core/rate_limit.py` and cross-checked against §3's pseudocode — the implementation is an exact match, no divergence found.
> - **Finding #20 mitigation confirmed genuine**, not just test-adjusted-to-pass: temporarily disabled the reserved-band check in a scratch edit (reverted after, `git diff --stat` clean) and re-ran the new test file — 3 of 5 tests (the ones that actually depend on the mechanism) failed with the exact expected pre-fix symptom; the other 2 (total-ceiling-unchanged, reserved=0 opt-out) correctly still passed, since those properties hold with or without the band. This proves the tests are not vacuously green.
> - **Finding #21 mitigation confirmed genuine**: `RATE_LIMIT_IP_MULTIPLIER` and `RATE_LIMIT_EMAIL_RESERVED_SLOTS` field_validators independently re-run via the subprocess-based startup test — invalid values (`0`, negative) block startup with `ValueError`; valid values and the unset/default case permit it.
> - **Full suite: 325 passed, 0 failed**, run twice (once with the mechanism intact, once as part of the red/green sanity check) against a disposable self-provisioned Postgres 16 (port 5434, to avoid colliding with any other concurrent agent's instance on the project's usual 5433) and a fresh per-worktree `.venv`. Matches the design doc §9 claimed count exactly.
> - **Out of scope for this pass:** distributed multi-IP DoS (2+ attacker IPs) remains unmitigated by design (§6 of the design doc, explicitly accepted residual risk) — not re-litigated here, already correctly documented. No new flaky/environment risk identified beyond what `tests/README.md` already documents for this suite.

## Jump-to index

- [§1 — Scope and inputs](#1--scope-and-inputs) — what this pass verified against, environment used.
- [§2 — Mechanism trace: independent verification against §3](#2--mechanism-trace-independent-verification-against-3) — line-by-line implementation vs. design doc pseudocode.
- [§3 — Finding #20: attack scenario reproduction](#3--finding-20-attack-scenario-reproduction) — victim-gets-through + ceiling-unchanged, both confirmed.
- [§4 — New test files reviewed](#4--new-test-files-reviewed) — what each of the 5 + 14 tests actually asserts, and the count discrepancy vs. §9's claim.
- [§5 — The 8 modified pre-existing regression tests](#5--the-8-modified-pre-existing-regression-tests) — each one's new threshold checked against the mechanism, not just "was it changed."
- [§6 — Red/green sanity check (non-vacuousness proof)](#6--redgreen-sanity-check-non-vacuousness-proof) — mechanism temporarily disabled, exact expected 3/5 failures observed, reverted clean.
- [§7 — Finding #21 verification](#7--finding-21-verification) — validator subprocess tests re-run independently.
- [§8 — Full suite run](#8--full-suite-run) — environment, command, result.
- [§9 — Verdict](#9--verdict)

---

## §1 — Scope and inputs

Read in full before this pass: `docs/api/obj-014-design-notes.md` (all sections, including §9's implementation note), `app/core/rate_limit.py`, `app/core/config.py`, `tests/api/test_rate_limit_reserved_slots.py`, `tests/unit/test_rate_limit_settings_validators.py`, and the diffs for the 8 modified pre-existing test files (via `git show 9b4e378 -- <file>` for each).

Environment: worktree `obj-014-gate3-qa`, branched from `origin/obj-010-013-residual-hardening` (which already has the OBJ-014 developer implementation + the `database-architect` index follow-up merged in — commit `38d16ff`). Fresh per-worktree `.venv` built from `requirements-dev.lock.txt` (greenlet imports cleanly in this environment — the previously-flagged Windows Application Control blocker, `tests/README.md`'s "KNOWN BLOCKER" note, does not reproduce here). Disposable Postgres 16 self-provisioned via `initdb`/`pg_ctl`, port **5434** (not the suite's usual 5433, to avoid colliding with another concurrent agent's instance in a parallel worktree — no other change to `tests/conftest.py`/`TEST_DATABASE_URL` conventions).

## §2 — Mechanism trace: independent verification against §3

Read `app/core/rate_limit.py`'s `enforce_rate_limit` line-by-line against design doc §3's pseudocode. Confirmed exact match, no divergence:

- `resolved_reserved` defaults to `settings.RATE_LIMIT_EMAIL_RESERVED_SLOTS`, clamped to `max(0, min(reserved, limit - 1))` — matches §3 exactly, including the "never consume the entire pool" defensive floor.
- `main_pool_limit = limit - resolved_reserved` — matches.
- IP-only check unchanged, runs first — matches §3's stated ordering rationale.
- Email-only check: same uncapped `COUNT(*)` as pre-OBJ-014 — matches; the hard block at `email_hit_count >= limit` is unconditional on IP, exactly as designed (total ceiling never weakened).
- Reserved-band check (`email_hit_count >= main_pool_limit and resolved_reserved > 0`): the `EXISTS` query filters on `(scope, email, ip, created_at > window_start)` — an IP already recorded for this email this window is blocked even below `limit`. Matches §3's `exists()` construct exactly, including the SQLAlchemy import (`from sqlalchemy import exists` alongside `func, select`, confirmed present at the top of the file).
- `_raise_rate_limited`'s `distinct_ip_count_for_email` observability addition (§2.7) is present and log-only — confirmed it is never passed to the `HTTPException` (only to `audit_log.log_auth_event`), preserving the anti-oracle property from §5.

**Config side** (`app/core/config.py`): `RATE_LIMIT_EMAIL_RESERVED_SLOTS: int = 1` placed in the same section as `RATE_LIMIT_IP_MULTIPLIER`, both with `field_validator`s (`>= 1` and `>= 0` respectively) matching §7's spec verbatim, including the exact error-message wording tracing to finding #21/#20.

**Conclusion of this section: the implementation is a faithful, unmodified translation of the design doc's mechanism.** No shortcuts, no silent deviation.

## §3 — Finding #20: attack scenario reproduction

Reproduced via `TestVictimFreshIpProtectedAfterAttackerExhaustsMainPool` (already-authored test, independently re-run and traced): attacker IP fires 4 requests (`MAIN_POOL_LIMIT = 5 - 1`) against a victim's email, all succeed (main pool, unrestricted, matching pre-OBJ-014 behavior). A 5th request from the SAME attacker IP is refused (429) even though the raw tally (4) hasn't reached `limit` (5) — this is the reserved-band block. A 6th request, from the victim's own genuinely fresh IP, succeeds — confirming the fix's core promise: **a fresh, different IP gets through at least once even after the attacker's fixed IP has exhausted everything it can claim.**

Total ceiling confirmed unchanged via `TestTotalCeilingPerEmailUnchanged`: after the main pool (4, attacker) + reserved slot (1, victim) = 5 = `limit` total hits land, a THIRD, never-before-seen IP is still blocked (429) — proving the reserved pool is a bounded subset of the existing `limit`, not an additional unbounded budget. This is exactly the property that distinguishes the adopted design from the rejected §2.3 "unconditional first-time-IP-always-passes" alternative (which would have let this third IP through, reopening finding #17).

Both properties independently confirmed true by direct test execution (§8), not just read from the test file's assertions.

## §4 — New test files reviewed

**`tests/api/test_rate_limit_reserved_slots.py` — 5 tests** (design doc §9 says "10 tests" — see note below):
1. `test_attacker_fills_main_pool_then_victim_fresh_ip_still_gets_through` — the core finding #20 closure proof (§3 above).
2. `test_ceiling_still_exactly_limit_a_third_fresh_ip_is_still_blocked` — total ceiling unchanged (§3 above).
3. `test_zero_reserved_slots_lets_attacker_consume_entire_budget_alone` — `RATE_LIMIT_EMAIL_RESERVED_SLOTS=0` is a genuine opt-out (main_pool_limit == limit, no protection, matches pre-OBJ-014 exactly) — confirms 0 isn't silently treated as some other default.
4. `test_single_ip_single_email_capped_at_main_pool_not_beyond_original_limit` — regression guard: a single non-rotating actor's ceiling only ever goes DOWN (to `limit - reserved`), never above the pre-OBJ-014 `limit`.
5. `test_reserved_slots_larger_than_limit_still_leaves_main_pool_of_at_least_one` — the defensive clamp, exercised via a direct `enforce_rate_limit` call (bypassing HTTP), confirming `main_pool_limit` floors at 1 even when `reserved_slots` is requested far larger than `limit`.

**Count discrepancy noted**: design doc §9 states "10 tests" for this file; actual collected count (`pytest --collect-only`) is 5. Each of the 5 present tests is substantive (none trivial/tautological — confirmed via §6's disable-and-rerun check, which shows 3 of the 5 genuinely depend on the mechanism). This reads as an inaccurate count in the developer's self-report, not a coverage gap — the 5 tests that exist do cover every property §2–§6 of the design doc calls out (main pool behavior, reserved-band blocking, ceiling invariance, the 0 opt-out, and the defensive clamp). Flagging the discrepancy for the record; not treating it as a blocking issue since the actual coverage is sound.

**`tests/unit/test_rate_limit_settings_validators.py` — 14 tests** (design doc §9 says "15 tests"; actual collected count is 14 — same class of minor self-report inaccuracy, not a coverage gap): covers both validators' invalid boundaries (parametrized `0`/`-1`/`-5` for the multiplier, `-1`/`-5` for reserved slots), valid boundaries (`1`/`5`/`10` and `0`/`1`/`3` respectively), the unset/default case for each, and an explicit default-value assertion (`RATE_LIMIT_EMAIL_RESERVED_SLOTS == 1`). Uses the same subprocess-import technique as `test_secret_key_startup.py`, correctly needed here since `Settings` is an `lru_cache`d singleton that a same-process re-import wouldn't actually re-validate.

## §5 — The 8 modified pre-existing regression tests

Read each diff (`git show 9b4e378 -- <file>`) individually, not just trusted the commit message's claim:

| File | Test(s) modified | Old assertion | New assertion | Reasoning checks out? |
|---|---|---|---|---|
| `test_rate_limit.py` | `test_forgot_password_rate_limited_after_5_requests_per_ip_email` | first 5 succeed, 6th 429 | first 4 succeed, 5th+ 429 | **Yes** — single, never-rotated real IP (shared `client` fixture), so `main_pool_limit = 5-1 = 4` applies exactly. |
| `test_rate_limit_ip_spoofing.py` | `test_varying_x_forwarded_for_does_not_bypass_forgot_password_rate_limit` | first 5 succeed, 6th 429 | first 4 succeed, 5th+ 429 | **Yes** — `TRUSTED_PROXY_COUNT=0` makes the spoofed `X-Forwarded-For` decorative; the real IP is still one fixed value, same shape as above. |
| `test_rate_limit_keying.py` | `TestSpoofedXffRotationRegressionGuard` (register) | first 5 succeed, 6th 429 | first 4 succeed, 5th+ 429 | **Yes** — same decorative-header reasoning; real IP constant. |
| `test_rate_limit_keying.py` | `TestOriginalPerEmailLimitsUnchanged` (forgot-password) | first 5 succeed, 6th 429 | first 4 succeed, 5th+ 429 | **Yes** — same reasoning. Notably, this file's *third* rate-limit test (`test_verify_otp_still_429s_on_11th_request_same_email_and_ip`) was correctly **left unmodified**: it only asserts the 11th-request index is 429 without asserting on any earlier index, and that property holds unchanged regardless of the reserved-band mechanism (the boundary shifts one request earlier, from index 10 to index 9, but index 10 stays 429 either way, since a blocked request is never recorded and the tally stays pinned). Confirmed this by reasoning through the mechanism, not just noting it wasn't touched. |
| `test_register_rate_limit.py` | 3 tests (`test_register_rate_limited_after_5_requests_per_ip_email`, `test_register_rate_limit_resets_after_window_elapses`, `TestRateLimitDoesNotReopenEnumeration`'s test) | first 5 succeed / loop 5 times, 6th 429 | first 4 succeed / loop 4 times, 5th+ 429 | **Yes**, all three — same single-fixed-IP shape throughout. |
| `test_resend_verification_email.py` | `test_resend_rate_limited_after_5_requests_per_ip_email` | first 5 succeed, last (6th) 429 | first 4 succeed, 5th+ 429 | **Yes** — same reasoning, `main_pool_limit` computed inline as `RATE_LIMIT-1`. |

**All 8 threshold changes independently verified as the correct, mechanically-derived consequence of `limit - RATE_LIMIT_EMAIL_RESERVED_SLOTS` (default 1) applied to a single, non-rotating (IP, email) pair — not values adjusted-until-green.** Each modified assertion was checked against the actual banding logic in §2, not just accepted because the commit message said so.

## §6 — Red/green sanity check (non-vacuousness proof)

To confirm the new tests actually exercise the mechanism (rather than being trivially satisfied regardless of implementation), the reserved-band check in `app/core/rate_limit.py` was temporarily short-circuited (`if False and email_hit_count >= main_pool_limit ...`) and `tests/api/test_rate_limit_reserved_slots.py` re-run:

```
3 failed, 2 passed in 6.72s
FAILED ...TestVictimFreshIpProtectedAfterAttackerExhaustsMainPool::test_attacker_fills_main_pool_then_victim_fresh_ip_still_gets_through
FAILED ...TestFix20DoesNotWeakenExistingEmailBruteForceProtection::test_single_ip_single_email_capped_at_main_pool_not_beyond_original_limit
FAILED ...TestReservedSlotsClampedDefensively::test_reserved_slots_larger_than_limit_still_leaves_main_pool_of_at_least_one
```

The 2 that still passed (`TestTotalCeilingPerEmailUnchanged`, `TestReservedSlotsSettingDisablesMitigationWhenZero`) are correctly indifferent to the mechanism being active — they assert properties true both with and without the band (total ceiling, and the `reserved=0` no-op case). This is the expected split, not a red flag.

File reverted immediately after (`git checkout -- app/core/rate_limit.py`; `git diff --stat` confirmed clean before proceeding). This proves the 3 failing tests are load-bearing — genuinely exercising the fix, not cosmetically passing regardless of implementation.

## §7 — Finding #21 verification

Re-ran `tests/unit/test_rate_limit_settings_validators.py` independently (14 tests, all green) — this exercises, via real subprocess `Settings` construction:
- `RATE_LIMIT_IP_MULTIPLIER ∈ {0, -1, -5}` → non-zero exit (blocked at startup with `ValueError`).
- `RATE_LIMIT_IP_MULTIPLIER ∈ {1, 5, 10}` and unset (default 5) → exit 0.
- `RATE_LIMIT_EMAIL_RESERVED_SLOTS ∈ {-1, -5}` → non-zero exit.
- `RATE_LIMIT_EMAIL_RESERVED_SLOTS ∈ {0, 1, 3}` and unset (default 1) → exit 0.

Confirms both findings-#21-class values are genuinely rejected at settings-load time, not just structurally present in the code without being wired to `Settings`' actual construction path.

## §8 — Full suite run

```
cd <worktree>
python -m venv .venv && .venv/Scripts/pip install -r requirements-dev.lock.txt
# disposable Postgres 16, initdb/pg_ctl, port 5434 (own worktree instance)
TEST_DATABASE_URL="postgresql+asyncpg://test@localhost:5434/api_fa_test" .venv/Scripts/python -m pytest -q
```

Result (run after the §6 revert, i.e. against the real, intact implementation):

```
325 passed in 170.48s (0:02:50)
```

Matches design doc §9's claimed count exactly. Zero unexplained regressions. Postgres instance and data directory torn down afterward (disposable, this worktree only).

## §9 — Verdict

**PASS.**

- Finding #20 (single-IP email-budget DoS) is genuinely mitigated: a victim's fresh IP is guaranteed at least `RATE_LIMIT_EMAIL_RESERVED_SLOTS` (default 1) requests through per window even after an attacker's fixed IP has exhausted the rest of the shared budget, and the total per-email ceiling is unchanged (still `limit`) — confirmed by direct reproduction (§3) and by disabling the mechanism and observing the expected failures (§6), not merely by reading the design doc's claim.
- Finding #21 (missing multiplier validator) is genuinely mitigated, plus the proactive companion validator on the new setting — confirmed by independent subprocess-based startup tests (§7).
- The developer's "limit − reserved is a correct, designed consequence, not a bug" reasoning for the 8 modified pre-existing tests **independently checks out** — each modified threshold was traced against the actual banding logic, not accepted on the commit message's word alone (§5).
- Residual risk (2+ distinct attacker IPs still fully deny a window) is accurately and explicitly documented in the design doc §6 and not overstated as fixed anywhere in the tests or implementation.
- One minor, non-blocking finding: the design doc §9 implementation note overstates the new test counts ("10" and "15" vs. actual 5 and 14) — flagged in §4, does not affect the verdict since actual coverage of every mechanism property is present regardless of the miscount.
- Full suite: **325 passed, 0 failed**, independently reproduced.
