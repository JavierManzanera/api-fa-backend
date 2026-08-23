# OBJ-002 — Session & Token Lifecycle: API Design Notes

**Author:** solution-architect
**Input:** `docs/security/audit-report.md` finding #3 (reused as Phase 1 threat-model input,
not re-audited here), OBJ-001's closed implementation (`app/core/security.py`,
`app/api/deps.py`, `app/api/v1/endpoints/auth.py`) and its design precedent
(`docs/api/obj-001-design-notes.md`), `app/models/rate_limit.py` as the established
Postgres-table style reference. Companion artifact: `docs/api/openapi.yaml` (v0.3.0-obj-002).

This document covers what the OpenAPI spec can't express on its own: the `refresh_sessions`
table shape, the reuse-detection state machine, the `token_version`/`ver` claim design, and how
pre-OBJ-002 tokens are affected. Module ownership follows OBJ-001's established rule: `app/core/
security.py` remains the single place that encodes/decodes JWT claims; nothing else decodes a
token inline.

---

## 0. Threat recap (finding #3)

> Un token robado sigue siendo válido durante toda su vida útil natural (hasta 7 días para el
> refresh) incluso después de que el usuario cambie su contraseña. Combinado con #1 (ya cerrado),
> un refresh token robado daba acceso persistente de hasta 7 días sin forma de revocarlo.

Three gaps, three remedies, all covered below:
1. No `/logout` → **§4, new endpoint**.
2. `/refresh` doesn't rotate → **§1-2, rotation + reuse detection**.
3. Password reset doesn't invalidate outstanding tokens → **§3, `token_version`**.

---

## 1. Persistence: the `refresh_sessions` table

**Decision:** a new Postgres table, following the established style of `rate_limit_hits`
(`app/models/rate_limit.py`) and `verifications` — a plain SQLAlchemy model landing via
`Base.metadata.create_all` today (same ordering wrinkle already noted for every table added
before OBJ-006's real Alembic migrations land), formalized by `database-architect` in their
Phase 1 pass.

**Explicitly not this:** the table does **not** store the raw JWT string anywhere. It stores only
an opaque identifier (`jti`, a fresh UUID minted at issuance) and metadata. The JWT itself stays
a bearer credential validated by signature; the table exists purely to answer "has this specific
refresh token already been consumed, and by which login session does it belong to."

```
refresh_sessions
├── id            UUID PK          -- == the `jti` claim of the refresh token this row represents
├── family_id     UUID NOT NULL    -- constant across a rotation chain; == id of the row created at login
├── user_id       UUID NOT NULL FK -> users.id
├── issued_at     TIMESTAMPTZ NOT NULL   -- Python-side default, NOT server_default (see note below)
├── expires_at    TIMESTAMPTZ NOT NULL   -- mirrors the JWT's `exp`; authoritative for the table's own expiry check
├── revoked_at    TIMESTAMPTZ NULL       -- NULL = active; set on rotation-supersession, logout, reuse-triggered
│                                            family revocation, or password-reset bulk revocation
└── replaced_by   UUID NULL FK -> refresh_sessions.id  -- set at rotation time; audit-trail pointer, not required
                                                            for correctness (family_id + revoked_at already
                                                            suffice for the state machine), but cheap and useful
                                                            for incident-response ("show me this token's chain").
```

Illustrative DDL (proposal for `database-architect` to formalize, not applied — matches the
"informal review, real migration lands in OBJ-006" pattern already established for
`verifications.attempts` and `rate_limit_hits`):

```sql
CREATE TABLE refresh_sessions (
    id          UUID PRIMARY KEY,
    family_id   UUID NOT NULL,
    user_id     UUID NOT NULL REFERENCES users(id),
    issued_at   TIMESTAMPTZ NOT NULL,
    expires_at  TIMESTAMPTZ NOT NULL,
    revoked_at  TIMESTAMPTZ NULL,
    replaced_by UUID NULL REFERENCES refresh_sessions(id)
);
CREATE INDEX ix_refresh_sessions_family_id ON refresh_sessions (family_id);
CREATE INDEX ix_refresh_sessions_user_id_revoked_at ON refresh_sessions (user_id, revoked_at);
```

- `id` (PK) covers the hot-path lookup: "find the row for this token's `jti`" on every
  `/auth/refresh` and `/auth/logout` call.
- `(family_id)` covers the reuse-detection bulk revoke: "revoke every row in this family."
- `(user_id, revoked_at)` covers the reset-password bulk revoke ("revoke every live row for this
  user") and is a natural fit for a future "list my active sessions" / "log out all devices"
  endpoint if ever wanted (not in OBJ-002's scope — flagged as a free extension point, not built).

**Unlike `RateLimitHit.ip`, `user_id` IS a real FK here** (not a deliberate no-FK-by-design like
`rate_limit_hits`/`verifications`). Those two tables must work for unauthenticated/nonexistent
emails (that's load-bearing for their anti-enumeration properties). `refresh_sessions` rows are
only ever created for an already-authenticated, already-existing user (at `/auth/login` success or
`/auth/refresh` rotation) — an FK is correct and safe here, no enumeration concern applies.

**`issued_at`/`expires_at` are Python-side, not `server_default=func.now()`** — same reasoning
qa-engineer/developer already established for `Verification.created_at` and `RateLimitHit.
created_at` during OBJ-001: freezegun-frozen tests need every timestamp in a request's lifecycle
(JWT `exp`/`iat` and the mirroring table row) to agree, and a Postgres-side `now()` would ignore
the frozen clock. Keep this pattern consistent — do not introduce a `server_default` here.

**Row count / growth:** one row per login + one row per successful rotation (bounded by how often
a client refreshes, typically far lower volume than `rate_limit_hits`' one-row-per-request). Still
unbounded over time with no cleanup. Recommend folding "purge `refresh_sessions` rows past
`expires_at` (or `revoked_at` older than some retention window, if keeping revoked rows briefly
for audit is wanted)" into the same OBJ-006 scheduled-cleanup item already tracked for
`rate_limit_hits` — same shape of problem, same fix, one cron job can reasonably do both. Do not
purge revoked rows immediately on revocation; keep them at least long enough to serve as the
reuse-detection signal (a purged row and a never-issued row are indistinguishable, which would
silently defeat detection for anything purged too aggressively) — recommend a minimum retention of
`REFRESH_TOKEN_EXPIRE_DAYS` past `expires_at` before a cleanup job removes a row, so no live client
can still be holding a reference to it.

---

## 2. Rotation + reuse detection (`/auth/refresh`)

**Claim addition:** refresh tokens gain a `jti` claim (fresh UUID, set at issuance) in addition to
OBJ-001's `{sub, exp, iat, type}`. Access tokens do **not** get a `jti` — see §3 for why.

**State machine on `POST /auth/refresh`** (full detail also in `openapi.yaml`'s endpoint
description; repeated here with the reasoning):

```
decode JWT (signature + exp + type=="refresh")
  └─ fail → 401 (unchanged from OBJ-001)

SELECT * FROM refresh_sessions WHERE id = :jti
  ├─ no row
  │     → 401. Covers: forged/garbage jti, a purged row, AND every pre-OBJ-002
  │       legacy token (no jti claim at all → lookup by NULL finds nothing).
  │       No family action — there is no family_id to act on.
  │
  ├─ row.revoked_at IS NOT NULL
  │     → REUSE DETECTED. UPDATE refresh_sessions SET revoked_at = now()
  │       WHERE family_id = row.family_id AND revoked_at IS NULL.
  │       → 401 (same generic message as every other branch here).
  │
  ├─ row.revoked_at IS NULL AND row.expires_at < now()
  │     → 401. Ordinary expiry, NOT treated as reuse — no family action.
  │       (Largely redundant with the JWT's own `exp` check, since both are set
  │       from the same REFRESH_TOKEN_EXPIRE_DAYS value at issuance — kept as a
  │       defensive second check because the table, not the JWT, is what
  │       `/auth/logout` and reuse-detection actually mutate.)
  │
  └─ row valid
        load User by sub (existing OBJ-001 "inactive/not found" → 400 check happens here)
        compare payload.ver against user.token_version
          ├─ mismatch → 401 (password-reset invalidation — see §3)
          └─ match:
                UPDATE this row: revoked_at = now(), replaced_by = <new jti>
                INSERT new refresh_sessions row (same family_id, new jti,
                    user_id, issued_at=now, expires_at=now+REFRESH_TOKEN_EXPIRE_DAYS)
                issue new access_token {sub, exp, iat, type=access, ver=user.token_version}
                issue new refresh_token {sub, exp, iat, type=refresh, ver=user.token_version, jti=new id}
                → 200 with BOTH new tokens
```

**Why revoke the whole family on reuse, not just deny the replay (the standard "refresh token
rotation with reuse detection / breach detection" pattern):** this is a recommendation, stated
explicitly rather than left implicit, per the task's own instruction. Reasoning: if refresh token
A was rotated into B, and someone later replays A, there are exactly two explanations —
(a) a client bug/race double-submitted A before the rotation response reached it, or (b) A was
stolen (copied out-of-band) and the thief is now racing the legitimate holder of B. A design that
only rejects the replay of A and leaves B alone cannot tell these apart, and in case (b) leaves the
thief's knowledge of the family (if they also have or later obtain a descendant) unaddressed. The
standard mitigation — and what this design adopts — is to treat *any* reuse of an already-rotated
token as a breach signal for the entire lineage and revoke every currently-active descendant,
forcing a full re-login. This trades a small false-positive cost (a genuine client-side race trips
the same response as an attack) for closing the actual persistent-access scenario finding #3
describes. This is the industry-standard shape (used by, e.g., Auth0's and IETF's refresh-token
rotation guidance) — flagging it as a recommendation adopted here, not asserting it's the only
possible design.

**Response uniformity:** every failure branch above returns the identical `401` / `"Invalid or
expired refresh token"` body, matching this codebase's established anti-oracle convention (OBJ-001
made the same call for OTP lockout-vs-expiry). An attacker who has a revoked/reused/stale token
gets no signal about *which* case they hit. Recommend (not a hard requirement of this spec, since
it has no HTTP surface) that the reuse-detected branch specifically gets a structured server-side
log line distinct from ordinary expiry — that's OBJ-004's structured-auth-logging scope, flagged
here so it isn't lost.

**Known residual gap, flagged rather than silently accepted (consistent with OBJ-001's precedent
for the rate-limiter/lockout TOCTOU):** the read-then-write sequence above (`SELECT` the session
row, then later `UPDATE`+`INSERT`) has no row lock. Two concurrent `/auth/refresh` calls
presenting the *same* still-valid token could both read `revoked_at IS NULL` before either commits,
both proceed to "rotate," and both insert a child row — breaking the single-child-per-parent
invariant the reuse-detection logic assumes. Recommend `SELECT ... FOR UPDATE` on the session row
(or an atomic `UPDATE ... WHERE revoked_at IS NULL RETURNING ...` as the commit gate, mirroring the
"atomic UPDATE" hardening already recommended for the OTP-lockout TOCTOU) as a follow-up. Proposing
this get tracked into the same OBJ-006 concurrency-hardening backlog item already opened for the
rate-limiter/lockout races, rather than opening a new one — same class of gap, same fix shape,
same non-blocking severity (bounded double-rotation, not an unbounded bypass).

---

## 3. `token_version` / `ver` claim (finding #3, the password-reset invalidation leg)

**Schema addition:** `User.token_version: int, NOT NULL, default=0` (a `database-architect`
schema-review item, same "lands informally via `create_all` until OBJ-006" note as every other
column added since OBJ-001).

**Claim addition:** both access and refresh tokens gain a `ver` claim, set to `user.token_version`
at issuance time.

**Why access tokens carry `ver` but not `jti`, and why this doesn't reintroduce a per-request
table dependency:** the task's own framing is the right constraint — a short-lived access token
should not need a persistent-table round trip on every request, for latency. `get_current_user`
(`app/api/deps.py`) already performs `SELECT * FROM users WHERE email = :sub` on **every** call
today, unconditionally — it needs the `User` row anyway (for `is_active`, for the object the route
handler receives). Comparing `payload.ver == user.token_version` is a field comparison against a
row that query *already returns* — it adds zero additional queries. This is the reconciliation:
access tokens stay decoupled from `refresh_sessions` (no `jti`, no session-table lookup, no new
query there), but they are not fully "check nothing but the signature" stateless either — they piggy-back
their one invalidation check onto the DB read the endpoint was always going to do. Refresh tokens,
being long-lived and already backed by a table for rotation (§2), pay one extra indexed PK lookup
per use, which is the acceptable cost the task describes for that side.

**Validation logic (both call sites):**

| Call site | Module | Check | On mismatch |
|---|---|---|---|
| `get_current_user` | `app/api/deps.py` | `payload.get("ver") == user.token_version` | 401, generic message (same as OBJ-001's `type` check) |
| `/auth/refresh` handler | `app/api/v1/endpoints/auth.py` | same, using the `User` row already loaded for the inactive/not-found check | 401, generic message |

**Fail-closed rule, same as OBJ-001's `type` claim precedent:** a **missing** `ver` claim is
treated identically to a **mismatched** one — reject, no special-casing. `payload.get("ver")`
on a token with no such claim returns `None`; comparing `None == user.token_version` is `False`
for any user whose `token_version` starts at its default of `0` (or any other int) — so the
absence of the claim alone is sufficient to reject, no extra code path needed.

**Reset-password's bulk `refresh_sessions` revocation (recommended, in addition to bumping
`token_version`):** `token_version` alone is sufficient to invalidate every *access* token and,
via the `ver` check in the state machine above, every *refresh* token too — so it is technically
sufficient on its own. This design additionally recommends `/auth/reset-password` also run
`UPDATE refresh_sessions SET revoked_at = now() WHERE user_id = :id AND revoked_at IS NULL` in the
same transaction. Rationale: defense in depth and observability — it means a stolen refresh token
replayed after a reset trips the *session-revoked* branch (§2) in addition to the `ver`-mismatch
branch, so the two independent checks don't have to agree on being the only line of defense, and
anyone inspecting `refresh_sessions` later sees an honest, explicit `revoked_at` on every row that
predates the reset rather than only an implicit "well, `ver` doesn't match anymore" inference. Cost
is one indexed `UPDATE` on a per-user, per-reset basis (rare event, cheap query) — not on any hot
path. Marked as a recommendation because it's not strictly required for correctness (the `ver`
check alone closes the finding); confirm with `database-architect`/`developer` if the extra write
is wanted or if `token_version` alone is preferred for a leaner reset-password handler.

---

## 4. `/auth/logout` — design rationale (recap of `openapi.yaml`'s inline description)

Full contract lives in `openapi.yaml`; the reasoning behind each decision the task asked for:

- **Receives the refresh token in the body, not the access token from the header.** Access tokens
  are stateless-by-design (§3) — there is nothing server-side an access token alone could target
  for revocation. The refresh token is what the whole threat (finding #3) is actually about.
- **Invalidates exactly one session row** (the `jti` match), not the whole family. Logout is a
  deliberate, expected client action; treating it like reuse detection (family-wide revoke) would
  make a retried/double-submitted logout call cascade into revoking sibling devices' sessions,
  which is not what a user clicking "log out" on one device expects or wants.
- **Status code: `204`, idempotently, for any well-formed request body — not an error for an
  already-invalid/expired/unknown token.** Reasoning given in full in the spec: the caller's
  desired end state already holds in every one of those cases, and returning a differentiated
  error would (a) create yet another oracle surface inconsistent with this codebase's established
  anti-enumeration philosophy, and (b) needlessly break a legitimate "log out" click on an already-
  expired session. `422` is reserved purely for request-shape validation failures, unrelated to
  token validity. Signature verification still gates any DB write, so this idempotency can't be
  abused to probe/revoke arbitrary sessions by guessing a `jti`.

**Explicitly out of scope for OBJ-002 (flagged, not built):** a "log out all devices" endpoint.
The `(user_id, revoked_at)` index proposed in §1 would make it a cheap addition later (same bulk-
revoke query already used internally by reset-password), but the task asked for single-session
`/auth/logout` only — noting the extension point rather than building it preemptively.

---

## 5. Pre-OBJ-002 tokens — explicit confirmation (task item 4)

**Confirmed: yes, every token issued before this objective's implementation lands becomes
unusable in practice, by construction, not by an extra migration step.**

- **Refresh tokens issued pre-OBJ-002** carry no `jti` claim. `/auth/refresh`'s session-table
  lookup (`SELECT ... WHERE id = :jti`) on a `None`/missing `jti` finds no row → falls into the
  "no row found" branch → `401`. No code needs to special-case "old-format token"; the absence of
  the claim alone routes it to rejection.
- **Access tokens issued pre-OBJ-002** carry no `ver` claim. `get_current_user`'s comparison
  `payload.get("ver") == user.token_version` is `None == <int>` → `False` → `401`. Same mechanism,
  same outcome, no special-casing.
- This is the **same fail-closed pattern OBJ-001 already established** when it introduced the
  `type` claim (a missing claim is treated as a wrong one, not given a backward-compatibility
  pass) — OBJ-002 is consistent with that precedent, not introducing a new philosophy.
- **Practical consequence:** deploying OBJ-002 forces every currently-logged-in user to re-login
  once their existing access token naturally expires (≤ `ACCESS_TOKEN_EXPIRE_MINUTES`) and their
  refresh token is rejected on next use. This is expected, intentional, and was already true of
  OBJ-001's rollout for the same reason (its `type`-claim introduction had the identical global-
  logout side effect) — not a new operational surprise, just re-confirming it applies again here.
  No migration/backfill of `token_version` is needed for this to work: new column defaults to `0`
  for all existing rows, and old tokens fail on claim-*absence* before `token_version`'s actual
  value is ever compared.

---

## 6. Open decisions needing confirmation (not architectural — implementation/ops choices)

Mirrors OBJ-001 design notes' own §5 pattern — these don't change the HTTP contract shape, so they
don't block `qa-engineer` from writing contract tests against `openapi.yaml` as it stands, but need
a decision before/during implementation:

1. **`refresh_sessions` table/column naming** — proposed above; low-stakes bikeshed, confirm with
   `database-architect` before their Phase 1 pass formalizes the migration.
2. **Reset-password's bulk `refresh_sessions` revocation** — recommended in §3 as defense-in-depth
   alongside `token_version`, but not strictly required for correctness. Confirm whether to include
   it or keep reset-password's handler leaner (relying on `ver` mismatch alone).
3. **Concurrent-rotation race (§2 residual gap)** — recommend tracking into the same OBJ-006
   concurrency-hardening backlog item already opened for the rate-limiter/OTP-lockout TOCTOU gaps,
   rather than opening a new backlog entry. Confirm that grouping is acceptable.
4. **`refresh_sessions` cleanup/retention** — recommend folding into OBJ-006's already-tracked
   `rate_limit_hits` cleanup job (same cron, different table), with a minimum retention of
   `REFRESH_TOKEN_EXPIRE_DAYS` past a row's `expires_at`/`revoked_at` before purge (so no live
   client reference can still exist). Confirm retention window and whether one shared job or two
   separate jobs is preferred.
5. **"Log out all devices" endpoint** — noted in §4 as a natural, cheap future extension (the
   `(user_id, revoked_at)` index already supports it) but explicitly not built now. Confirm it
   stays out of OBJ-002's scope.
