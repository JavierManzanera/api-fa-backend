# OBJ-003 — Test Report (qa-engineer)

**Summary:** 47 new tests (5 files) covering findings #7 (OTP-at-rest HMAC), #8 (TLS to Postgres),
#5 (timing side-channel, incl. the OBJ-002 `/auth/logout` fold-in) — derived directly from
`docs/api/obj-003-design-notes.md` (no business-analyst Gherkin doc for this infra-hardening
objective; each test/class docstring traces to a design-notes section instead). Gate 3 verdict:
**PASS** (unanimous with security-specialist/database-architect). Final suite: 118/118 green (up
from 71), zero regressions.

## Phase 2 (red phase) — 2026-08-23

Files: `tests/unit/test_otp_hashing.py` (11), `tests/api/test_otp_hashing_integration.py` (5, real
`/forgot-password` flow, OTP recovered via `capsys` against the debug print mock — flagged as
environment-dependent since OBJ-004 plans to remove that print), `tests/unit/test_database_ssl.py`
(11, targets `app.core.database._build_ssl_connect_arg`; no real TLS-terminated Postgres stood up —
this sandbox has none configured, and `database-architect` confirmed `engine` is never connected to
in this suite regardless), `tests/unit/test_postgres_ssl_mode_startup.py` (11, subprocess-per-case
technique matching `test_secret_key_startup.py`'s), `tests/api/test_timing_side_channel.py` (9,
call-count/`wraps=` spy assertions only — never wall-clock, per design notes §3's explicit
instruction).

**Required factory fix**: `tests/factories.py`'s `create_verification` now seeds
`security.hash_otp(code)` instead of plaintext. **Side effect, expected and self-resolving**: 17
previously-green tests (`test_otp_lockout.py` all 6, `test_otp_resend_cooldown.py` both,
`test_password_reset_invalidation.py` all 6, 3 of 5 in `test_rate_limit.py`) went transiently red
with `AttributeError: module 'app.core.security' has no attribute 'hash_otp'` — mechanical
consequence of the factory needing `hash_otp` before it exists; not broken tests, no edits needed
once `developer` implements the function.

Also landed: `tests/conftest.py` gained `POSTGRES_SSL_MODE=disable` in the required-env bootstrap;
`test_secret_key_startup.py` proactively got the same, to avoid masking `SECRET_KEY` assertions
once the new required field lands.

**Verification:** full suite (OBJ-000-003) **57 failed, 61 passed** (118 total) — 40 new-test
failures + 17 factory-fix-induced (both traced to specific missing pieces), 7 new-test passes
(deliberate regression anchors), 54 pre-existing unaffected. Math confirmed internally consistent
(118−71=47 new; 57−17=40; 61−54=7; 40+7=47).

Out of scope: real TLS-terminated-Postgres integration test; wall-clock timing measurement; true
concurrency/TOCTOU on the OTP-hash path (same established convention).

Risks flagged for developer: the 17-test transient regression is expected; `_build_ssl_connect_arg`
name is coupled to the test import (rename-safe if behavior is equivalent); logout's DB-call-count
assertions require the no-op branch to share the client fixture's session (same testability
requirement as OBJ-001's rate limiter); `test_otp_hashing_integration.py` depends on the debug print
mock staying in place until OBJ-004 provides a replacement; the `code`→`code_hash` rename
(database-architect's recommendation) was not required by this pass but would touch 4 lines in this
file if taken later.

**Gate 2: APPROVED 2026-08-23.**

## Gate 3 verification (qa-engineer, 2026-08-23) — Verdict: PASS

- Reproduced independently: two foreground runs, **118 passed, 0 failed** both times (115.8s,
  110.0s), no flakiness — matches developer's reported count.
- `test_otp_hashing.py`'s key-derivation test independently re-implements the Option B HMAC
  construction rather than importing `security`'s internals — confirmed genuinely checks the chosen
  construction (traced `security.py:26-29` byte-for-byte against the test's own expected-value
  helper); the Option-A-rejection negative test confirmed non-redundant by hand-tracing what a
  hypothetical Option-A implementation would and wouldn't pass.
- `test_database_ssl.py`'s two load-bearing tests confirmed they'd catch a "naive
  `create_default_context()` for both `require` and `verify-full`" bug — traced `database.py:19-25`
  showing `require` explicitly sets `check_hostname=False`/`verify_mode=CERT_NONE`, genuinely
  distinguishable from `verify-full`'s default posture.
- `test_otp_hashing_integration.py`'s three assertions (not-6-digit-shaped, is-64-hex-shaped,
  equals-`hash_otp`-of-the-real-recovered-OTP) read directly, confirmed via a fresh DB round-trip
  (not a cached ORM object) — leaves no gap between "looks hashed" and "is the app's own hash of the
  real value."
- `test_timing_side_channel.py`'s call-count/call-argument spy assertions traced against
  `auth.py`'s actual control flow line by line for all four surfaces (`/login` nonexistent-email,
  `/login` wrong-password regression anchor, `/forgot-password` both branches,
  `/auth/logout` three cases) — confirmed by hand that the pre-fix code would have produced
  different call counts in each red-phase case (e.g. zero `verify_password` calls for a nonexistent
  login email under the old `if not user or ...` short-circuit).
- Both Gate-1-approved decisions (TLS Option A: safe default + escape hatch; dummy-work Option A:
  unconditional bcrypt tax) confirmed matching implementation, not the rejected alternatives.
- Implementation vs. `openapi.yaml`/design notes read line by line — no design deviation found
  anywhere, matching developer's own "design deviations: none" claim.
- Regression check: full 118/118 both runs; file-timestamp check confirms only
  `test_secret_key_startup.py` was touched among pre-existing files (one documented line), and the
  17 transiently-red tests are green again for the *real* documented reason (verified
  `tests/factories.py:90` calls `security.hash_otp`), not because any were weakened.
- Cross-checked both concurrent Gate 3 passes (database-architect, security-specialist) — no
  discrepancy with this pass's own findings.

**Conclusion:** PASS. Suite reproducible, substantive, matches spec/design notes line by line
including both Gate-1 decisions. No new blocking findings.
