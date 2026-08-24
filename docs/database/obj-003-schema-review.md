# OBJ-003 — Schema Review (database-architect)

**Summary:** `Verification.code` plaintext → HMAC-SHA256 hex digest is a value-shape-only change
requiring **zero migration** — the existing unbounded `String` column already fits a 64-char
digest, and `code` was never a query/index predicate. Verdict: **cleared**, both Phase 1 and the
Phase 3 confirmation. One non-blocking naming recommendation (`code` → `code_hash`), not taken by
developer.

## Phase 1 informal review — 2026-08-23

`app/models/verification.py:14`: `code: Mapped[str] = mapped_column(String, nullable=False)` — a
bare, unbounded `String` (SQLAlchemy compiles this to unqualified `VARCHAR` on Postgres, no length
constraint). A 64-char hex digest fits exactly as designed — confirmed by reading the model, not
assumed from the design doc. Optional, non-blocking defense-in-depth for a future migration:
explicit `String(64)` or a `CHECK (code ~ '^[0-9a-f]{64}$')` constraint.

**Naming recommendation: `code` → `code_hash`.** The column no longer stores anything resembling
user-submitted plaintext; a name that still reads as `code` invites treating it as loggable/
displayable. Checked the real diff cost by grep (not assumed): exactly 2 production references
(`app/models/verification.py:14`, `auth.py` lines ~73/238) + 1 test-support site
(`tests/factories.py`'s internal construction) — the ~10 test call sites across the suite are
unaffected because `code=` there is the *factory's own parameter name*, not the column name. A
3-file, ~4-line change. Non-blocking either way — flagged so the choice (made once, in OBJ-006's
real migration, or left as-is) is informed.

Index impact: none. The only index is the pre-existing single-column `email` (OBJ-001's
recommended composite index is still unapplied, unrelated to this change). `_check_and_consume_otp`
filters on `(email, purpose, expires_at)` only; `code` is compared in Python after fetch, never a
`WHERE` predicate — widening its content has zero effect on index shape or query plan.

HMAC comparison mechanism confirmed as designed: lookup is by `(email, purpose, expires_at)`, not
by digest, so hash-collision behavior is irrelevant here (a collision could only matter for a
`WHERE code_hash = :x` lookup, which this code never does). No FK/uniqueness/nullability change.

**Gate status: cleared**, no blocking data-model issues.

## Gate 3 confirmation — 2026-08-23

Re-checked Phase 3 implementation against the Phase 1 review above, not a fresh review.
- `Verification.code` unchanged as expected (confirmed by direct read) — the rename recommendation
  was deliberately not taken by developer (avoided an unscoped ripple into
  `test_otp_hashing_integration.py`'s four direct `Verification.code` reads); 64-char digest still
  fits with no migration needed.
- `POSTGRES_SSL_MODE` confirmed non-schema: a plain pydantic-settings `str` field, consumed only as
  `create_async_engine`'s `connect_args={"ssl": ...}` — connection-layer only, no table/column/
  migration implication whatsoever.
- No new column, table, or index beyond what Phase 1 anticipated — enumerated all model files,
  confirmed `rate_limit.py`/`refresh_session.py` unchanged, only `Verification.code`'s value shape
  (already covered) has any DB-adjacent footprint.

**Gate 3 status: CONFIRMED PASS.** No schema drift, no missed migration.
