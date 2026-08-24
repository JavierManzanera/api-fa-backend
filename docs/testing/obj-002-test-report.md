# OBJ-002 — Test Report (qa-engineer)

**Summary:** 22 new red-phase tests (4 files under `tests/api/`) covering all 16 Gherkin scenarios
in `docs/requirements/obj-002-session-token-lifecycle.md`, verified against
`docs/api/openapi.yaml` (v0.3.0-obj-002)/`obj-002-design-notes.md`. Gate 3 verdict: **PASS**
(unanimous with security-specialist/database-architect). Final suite: 71/71 green (49 OBJ-001 +
22 OBJ-002), no regressions.

## Phase 2 (red phase) — 2026-08-21

Files: `tests/api/test_logout.py` (8), `test_refresh_rotation.py` (7, including the highest-value
test in this pass — `test_reuse_detected_revokes_entire_token_family`, a 3-deep rotation chain
proving whole-family revocation, not single-token rejection), `test_password_reset_invalidation.py`
(7), `test_legacy_token_fail_closed.py` (2). Verified against throwaway Postgres 16 (same
`initdb`/`pg_ctl` pattern): new files alone **20 failed, 2 passed**; full suite (OBJ-000/001/002)
**20 failed, 51 passed** (71 total) — zero regressions against OBJ-001's 49. Every failure traced
to a specific missing OBJ-002 piece (no `/auth/logout` route → 404s; `/auth/refresh` still echoes
the token back, unrotated; `User.token_version` doesn't exist → `AttributeError`; no `ver` check in
`get_current_user`).

2 tests pass already as expected (regression guards for OBJ-001 behavior, not new proof):
`test_expired_refresh_session_returns_401` (**known weak point** — currently riding on the JWT's
own `exp` claim, not yet distinguishing a table-level expiry check) and
`test_forged_access_token_with_correct_looking_ver_still_needs_real_signature`.

Out of scope: Scenario 2.3 (concurrent-request race, same TOCTOU convention as OBJ-001), Scenario
3.5 (iat-based forged-`ver` protection — no committed mechanism to test against, flagged as a
residual gap for a future objective), "logout all devices" (not in OBJ-002 scope).

Risks flagged for developer (all resolved correctly in Phase 3, see below): the
`test_expired_refresh_session_returns_401` weak point; a fixture/session-identity assumption on
`token_version` reads; `refresh_sessions` needs registering in `app/models/__init__.py`; the
anti-oracle status codes (esp. `/auth/logout`'s always-`204`) are load-bearing per the Gate 1
decision, not incidental — don't "fix" them to match the AC's original `401` proposal.

**Gate 2: APPROVED 2026-08-21.**

## Gate 3 verification (qa-engineer, 2026-08-23) — Verdict: PASS

- Reproduced independently: two foreground runs, **71 passed, 0 failed** both times (84.9s, 76.5s),
  no flakiness.
- All 22 tests read against the diff: real end-to-end HTTP calls, real bcrypt users, real JWTs
  decoded with `python-jose` for structural claim assertions — no mocked DB session or
  monkeypatched helpers.
- `test_reuse_detected_revokes_entire_token_family` confirmed genuinely load-bearing: traced
  `auth.py:352-359`'s `_revoke_active_sessions(db, RefreshSession.family_id == ...)` call — a real
  family-wide bulk UPDATE, not per-row. Hand-traced a weakened alternative (`id ==` instead of
  `family_id ==`) and confirmed it would pass every other test in the file but fail this one
  specifically.
- `test_expired_refresh_session_returns_401` re-confirmed still riding on the JWT-level `exp` check
  (`security.py` raises before the table lookup at `auth.py:342` is ever reached) — carried forward
  as a known, non-blocking caveat, not fixed by this pass (would need a test that mints a long-`exp`
  JWT with a manually-backdated DB row).
- Implementation vs. spec read line by line: `/auth/refresh`'s 5-branch state machine, `/auth/logout`
  always-204 idempotency (including a wrong-token-type submission), `/auth/reset-password`'s atomic
  bump+bulk-revoke in one transaction/commit, `get_current_user`'s zero-extra-query `ver` check,
  legacy-token fail-closed on both refresh and access paths — all confirmed matching
  `openapi.yaml`/`obj-002-design-notes.md` exactly.
- FK-ordering fix (developer's `await db.flush()` between the new row's INSERT and the old row's
  `replaced_by` UPDATE) spot-checked as correct — a `ForeignKeyViolationError` would have surfaced
  as a raw DB error in any rotation test; none did.
- Regression check: full 71/71 both runs; file-timestamp check confirms only one pre-existing
  OBJ-001 test file was touched (`test_token_type_enforcement.py`, one test updated — see
  `obj-002-design-notes.md`'s Phase 3 addendum for why that change is legitimate, not a weakening).

**Conclusion:** PASS. Suite reproducible, substantive, matches spec line by line. Both Phase 2/3
watch-items (family-wide revocation; expiry-test weak point) confirmed exactly as claimed — no
discrepancy between developer's report and actual code.
