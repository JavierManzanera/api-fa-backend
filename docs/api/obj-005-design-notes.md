# OBJ-005 — Email Verification Flow: API Design Notes

**Author:** solution-architect
**Input:** `docs/requirements/obj-005-email-verification-flow.md` (business-analyst, 3 stories, 24
Gherkin scenarios) + `dependency_graph.md`'s OBJ-005 Gate 1 approval (2026-08-23, 5 decisions
locked). Companion artifacts read in full for this pass: `app/api/v1/endpoints/auth.py`,
`app/models/verification.py`, `app/models/user.py`, `app/api/deps.py`, `app/core/security.py`,
`app/core/config.py`, `app/core/rate_limit.py`, `app/schemas/user.py`, plus
`docs/api/obj-003-design-notes.md` (OTP-HMAC pattern this must stay consistent with) and
`docs/api/obj-004-design-notes.md` (the interim `notifications.send_otp_notification` seam this
objective's `EmailSender` abstraction is meant to absorb).

**Restart note:** a prior attempt at this pass was interrupted by an infrastructure error before
any file was produced. `docs/api/openapi.yaml`'s `info` block already carried a partially-written
paragraph referencing this objective (correct endpoint names, correct finding number, but the
actual path items were never added and this document did not exist) — treated as a draft to
verify and complete, not as prior authority. Confirmed via direct read that no `docs/api/obj-005-
design-notes.md` existed before this pass.

**Quick index:** finding #11 confirmed no transposition (§0) · reuses the existing `Verification`
OTP table with `purpose="email_verification"`, own 30-min TTL distinct from password-reset's 10-min
(§1) · two new endpoints, `POST /auth/verify-email` (consumes, sets `is_verified=True`) and
`POST /auth/resend-verification-email` (mirrors `/forgot-password`, silent no-op if already
verified) (§2) · `/auth/register` now rolls back atomically (flush-then-rollback, not
commit-then-delete) if the verification email fails to send, returns `503` (§2.3) · login/refresh
gain an `is_verified` check, extending the existing `is_active` 400-branch precedent — the one item
flagged for a Gate 1 nod (§3, resolved 2026-08-24, see `dependency_graph.md`) · new `EmailSender`
ABC + `ConsoleEmailSender` default, replaces OBJ-004's interim `notifications.py` seam either way
regardless of landing order (§4) · no new `openapi.yaml` schemas, only new path items (§5) ·
testability guidance for qa-engineer emphasizing purpose-isolation and register-rollback proof (§6).
Jump to: "1. Token mechanism", "2. New endpoints", "3. Login/refresh enforcement mechanics",
"4. EmailSender abstraction", "5. openapi.yaml impact", "6. Testability guidance", "7. Open items".

---

## 0. Finding-number verification (per this project's now-established practice, after OBJ-003's
transposition)

`docs/security/audit-report.md:102` — **`### 11. BAJO — "is_verified" es un campo sin función (dead
code de diseño)"`**, fix text: *"implementar el flujo `/verify-email` faltante y aplicarlo en
`login`, o documentar que `is_verified` es un placeholder no funcional."* Matches
`dependency_graph.md`'s OBJ-005 row citation exactly — **no transposition**, same clean result as
OBJ-004's §0 (unlike OBJ-003's).

---

## 1. Token mechanism — reusing the `Verification` table, `purpose="email_verification"`

**Not a fresh design choice — Gate 1 already settled this (decision 2):** reuse the existing
6-digit OTP infrastructure (`Verification` table, HMAC-hashed per OBJ-003), explicitly **overriding**
the business-analyst's own recommendation of a long random link-token. This section designs the
mechanics of that reuse, not whether to do it.

### 1.1 What "reuse" means concretely

- Same `Verification` model, same `HMAC-SHA256`-at-rest storage (`security.hash_otp` /
  `security.verify_otp_hash`, OBJ-003 §1) — **no new hashing mechanism, no new key.** A
  `Verification` row with `purpose="email_verification"` is byte-for-byte the same shape as one
  with `purpose="reset_password"`; only the `purpose` string and the caller's business logic differ.
- Same 6-digit numeric format (`_generate_otp()`, CSPRNG via `secrets.choice`, OBJ-001) — no new
  code-space decision needed.
- Same constant-time comparison (`hmac.compare_digest` inside `verify_otp_hash`) — no new timing
  work required; this closes the requirements doc's "no timing side-channel between valid/invalid
  token" note (Edge Cases § Timing Side-Channels) for free, by construction.
- **Separate lockout/rate-limit budget, same mechanism.** `_check_and_consume_otp`
  (`auth.py:42-80`) already filters by `Verification.purpose == RESET_PASSWORD_PURPOSE` — it just
  hardcodes that one value today. **Decision:** generalize it to take `purpose` (and, for clarity,
  `max_attempts`) as parameters:

  ```python
  EMAIL_VERIFICATION_PURPOSE = "email_verification"

  async def _check_and_consume_otp(
      db: AsyncSession,
      email: str,
      otp: str,
      *,
      purpose: str = RESET_PASSWORD_PURPOSE,
      max_attempts: int = MAX_OTP_ATTEMPTS,
  ) -> Verification:
      ...  # body unchanged except `Verification.purpose == purpose` and
           # `verification.attempts >= max_attempts`
  ```

  Existing call sites (`verify_otp`, `reset_password`) keep working unchanged (default argument
  preserves current behavior byte-for-byte). New call sites (`verify_email`) pass
  `purpose=EMAIL_VERIFICATION_PURPOSE` explicitly. Because the query already filters on `purpose`,
  a failed email-verification attempt cannot decrement the password-reset budget for the same email
  and vice versa — this is the "same-table sharing does NOT imply shared lockout counters" property
  the requirements doc calls out (Edge Cases § Interaction with OBJ-001/003 Verification Table),
  and it falls out of the existing query shape for free once the hardcoded value becomes a
  parameter. `max_attempts` is exposed as a parameter (not hardcoded) purely so a future purpose
  could tune its own budget without touching this function's body again — email verification itself
  uses the **same** value as password reset (5), per Gate 1 decision 5's "reuse the constants
  pattern," not a fresh number.

### 1.2 TTL — a genuine, intentionally *different* choice from password-reset's 10 minutes

Password-reset's OTP TTL is a hardcoded `timedelta(minutes=10)` literal at the `/forgot-password`
call site (`auth.py:258`) — no named constant exists for it today (flagged as a minor pre-existing
cleanup opportunity below). Email verification does **not** have to use the same TTL, and
shouldn't: `/forgot-password`'s 10-minute window guards an *active credential-change* flow, where
the security literature's tight-window recommendation applies directly. Email verification is a
one-time account-activation step, typically completed less urgently (a new user checking their
inbox minutes-to-hours after signup, not mid-password-reset). A 10-minute window would generate
avoidable `resend-verification-email` traffic (and support friction) without a matching security
benefit — the 5-attempt lockout budget, not the TTL length, is what actually bounds brute-force
risk on a 6-digit code, and that budget is unchanged regardless of TTL.

**Decision:** `EMAIL_VERIFICATION_OTP_TTL_MINUTES = 30` — a new named constant, distinct from
password-reset's. Not routed to Gate 1: this is a UX/ops tuning parameter with no security
trade-off attached (the lockout, not the TTL, is the control that matters), same category as
OBJ-001's rate-limit thresholds, which were decided by solution-architect/qa-engineer without a
separate ask. **Cleanup flag for `developer`, not blocking:** extract `/forgot-password`'s inline
`timedelta(minutes=10)` into a named `RESET_PASSWORD_OTP_TTL_MINUTES = 10` constant alongside the
new one, so both purposes' TTLs are equally discoverable at the top of `auth.py` rather than one
being a named constant and the other a magic number.

### 1.3 Schema impact — flagged for `database-architect`, but there is almost nothing to review

`Verification.purpose` (`app/models/verification.py:15`) is an unconstrained `String` column,
already carrying the comment `# e.g., 'reset_password', 'verify_email'`. Adding
`"email_verification"` as a live value requires **zero DDL** — no new column, no new table, no
type/length change. This is even more minimal than every prior objective's schema touch
(`attempts`, `code`'s semantic reinterpretation, `token_version`, `refresh_sessions`) — none of
which needed a value-only change like this one.

**Two things still flagged for `database-architect`'s Phase 1 pass, not decided here:**
1. **Comment accuracy.** The existing inline comment says `'verify_email'`; this design uses
   `"email_verification"` (matching Gate 1 decision 2's exact wording and the requirements doc's
   own AC text). Comment should be corrected to match whichever value actually ships — a one-line
   fix, flagged so it isn't silently inconsistent.
2. **Composite index reinforcement, not a new recommendation.** `database-architect`'s OBJ-001
   Gate 3 review already recommended `Index("ix_verifications_email_purpose_expires_at", "email",
   "purpose", "expires_at")` (still not applied — see §5 below), specifically because dead rows
   accumulate per email **across purposes** as they multiply. Email verification adds a second
   live purpose to that same accumulation pattern, reinforcing (not creating) the case for that
   index landing sooner rather than later. No new index shape is needed beyond what's already
   recommended.

### 1.4 OBJ-006 coordination — checked directly, not assumed

The task instructions asked whether OBJ-006's "real Alembic migrations now mid-flight" status
changes how this objective's schema change should land. **Checked directly:** `alembic/` does not
exist anywhere in this repository yet (confirmed via glob) — only `docs/database/obj-006-
migration-plan.md` (the migration *plan*, database-architect's Phase 1 deliverable) exists.
`dependency_graph.md`'s OBJ-006 section says database-architect is "cleared to author the actual 7
Alembic migration files next," but no evidence exists that authorship has actually started; treat
OBJ-006 as **plan-complete, migrations-not-yet-written**, not "mid-flight" in the sense of having
real migration files to coordinate against today.

**This doesn't matter for OBJ-005 either way**, and that's the useful finding to flag: because §1.3
established this objective needs **zero DDL**, there is nothing to coordinate with OBJ-006 about —
not "land it informally via `create_all` today, formalize later" (the pattern every prior
objective followed), but genuinely **nothing to migrate, ever**, for this specific change. If
OBJ-006's migrations land before OBJ-005's Phase 3 implementation, developer does not need to
write migration `0008`; if OBJ-005 lands first, there is nothing pending for OBJ-006 to pick up
retroactively. The only schema item connected to this objective at all is the pre-existing
composite-index recommendation from §1.3.2, already tracked (and already inside OBJ-006's migration
plan as migration `0002`) independently of this objective's existence.

---

## 2. New endpoints

### 2.1 `POST /auth/verify-email` — consumes the code, same mechanics as `/auth/verify-otp`

Per task instruction: designed to accept the code **the same way** `/auth/verify-otp` does.
Concretely, this means reusing the exact same request schema (`OTPVerifyRequest`: `{email, otp}`)
rather than inventing a parallel one — there is no shape difference to justify a new schema.

**Behavior:**
1. Rate limit: `enforce_rate_limit(scope="verify_email", ip=client_ip, email=payload.email,
   limit=VERIFY_EMAIL_RATE_LIMIT_PER_MINUTE)` — `VERIFY_EMAIL_RATE_LIMIT_PER_MINUTE = 10`, same
   value as `VERIFY_OTP_RATE_LIMIT_PER_MINUTE` (Gate 1 decision 5: reuse the constants pattern).
2. `_check_and_consume_otp(db, payload.email, payload.otp, purpose=EMAIL_VERIFICATION_PURPOSE)` —
   same generic-400, same shared-attempts-budget mechanism as `/auth/verify-otp`/`/auth/reset-
   password`, scoped to this purpose only (§1.1).
3. On success: look up the `User` row by email (same query shape as every other endpoint here),
   set `user.is_verified = True`, **delete** the `Verification` row (matching `/auth/reset-
   password`'s "consume and delete" pattern, not `/auth/verify-otp`'s "check without consuming"
   pattern — email verification is a one-shot state transition, not a probe). Commit.
4. Response: `200`, body = `UserResponse` (`id`, `email`, `is_active`, `is_verified`,
   `created_at`) — reuses the existing schema rather than inventing a new one; satisfies Scenario
   1.2's AC ("response contains user.id, user.email, is_verified=True") exactly.

**No auto-login.** The response does **not** include tokens. Not in the AC, not asked for, and
adding it would be scope creep with its own security surface (should a freshly-verified session
skip the normal `/auth/login` credential check? not asked, not designing it). The client is
expected to call `/auth/login` normally afterward, which will now succeed since `is_verified` is
now `True` (§3).

**Reuse-after-success (Scenario 1.5) requires no special-casing.** Because the row is deleted on
success, a replay of the same code lands in `_check_and_consume_otp`'s existing "no live row at
all" branch → the same generic `400` used for every other invalid-code case. Same mechanism
already proven correct for `/auth/reset-password`'s analogous "OTP already consumed" case.

**Error responses:**
- `400` — invalid, expired, already-used, or attempt-locked-out code. All four indistinguishable,
  same generic message, same anti-oracle rule already established for `/auth/verify-otp`/`/auth/
  reset-password`. **Decision: distinct message text from `/verify-otp`'s** ("Invalid or expired
  verification code" vs. "Invalid or expired OTP") — this does **not** reopen an oracle, since the
  two endpoints operate on disjoint `purpose` values and neither response ever depends on data
  reachable from the other; a purpose-specific message is purely a UX clarity improvement with no
  cross-endpoint signal.
- `422` — schema validation.
- `429` — rate limited.

### 2.2 `POST /auth/resend-verification-email` — new endpoint, mirrors `/auth/forgot-password`'s pattern

Gate 1 decision 5 says reuse the existing rate-limit/cooldown infrastructure; the requirements
doc's Story 1.6/1.7 describes exactly `/forgot-password`'s existing shape (generic response,
per-email rate limiting, silent cooldown, soft-invalidate-and-rotate). **Decision:** implement this
as a genuinely new, dedicated endpoint (not folded into `/verify-email` via a flag, the requirements
doc's other named option) — a separate endpoint matches this API's existing one-verb-per-endpoint
convention (`/forgot-password` and `/verify-otp`/`/reset-password` are already three distinct
endpoints, not one overloaded one), and keeps `/verify-email`'s request schema untouched.

**Request:** `EmailRequest` (`{email}`) — the existing schema, no new one needed. Deliberately
**unauthenticated** (no `Authorization` header, no session required) per the requirements doc's own
recommendation (Open Product Decisions §3) — a user who lost their session before verifying still
needs a path to request a fresh code. Not routed to Gate 1: not itemized in the 5 locked decisions,
but it's the same "reuse `/forgot-password`'s shape" instruction as decision 5, not a fresh
trade-off — `/forgot-password` is already unauthenticated for the identical reason.

**Behavior (mirrors `/auth/forgot-password:auth.py:197-268` almost line for line):**
1. Rate limit: `scope="resend_verification_email"`, `limit=RESEND_VERIFICATION_RATE_LIMIT_PER_MINUTE
   = 5` — same value as `FORGOT_PASSWORD_RATE_LIMIT_PER_MINUTE` (Gate 1 decision 5).
2. Look up user by email. **Always return the same generic `200` regardless of whether the email
   exists** — same anti-enumeration property as `/forgot-password`, and explicitly required by the
   requirements doc (Scenario 1.7: "the rate limit applies per email, not per session/user_id, to
   not leak whether an email is registered").
3. **If the user exists but is already verified**, still return the same generic `200` with no
   further action (no new `Verification` row, no email sent) — silently a no-op. This is a
   deliberate anti-oracle extension beyond what `/forgot-password` has to consider (which has no
   "already in the target state" concept): without this, a `200` that visibly sends an email vs. a
   `200` that doesn't would still be internally consistent (no response-shape difference), but the
   *side effect* (an unwanted "your email is already verified" email landing in an already-verified
   user's inbox on every resend spam attempt) is worth avoiding on its own UX merits, not just an
   anti-oracle one.
4. Cooldown check: same shape as `/forgot-password`'s existing cooldown block (§ the
   `existing_result`/`cooldown_cutoff` logic at `auth.py:231-243`), scoped to `purpose=
   EMAIL_VERIFICATION_PURPOSE`, using `EMAIL_VERIFICATION_RESEND_COOLDOWN_SECONDS = 60` — same
   value as `OTP_RESEND_COOLDOWN_SECONDS` (Gate 1 decision 5's literal "60s resend cooldown").
5. Rotate: delete-then-insert a fresh `Verification` row for `(email, purpose=
   email_verification)`, same as `/forgot-password`'s rotate step, using the `EMAIL_VERIFICATION_
   OTP_TTL_MINUTES` TTL from §1.2.
6. Send the fresh code via `EmailSender` (§4). **This is the one place this endpoint's fail-behavior
   genuinely differs from `/register`'s (§2.3):** a resend's email-send failure does **not** get
   the "roll back and fail loudly" treatment Gate 1 decision 3 mandates for `/register`, because
   there is no create-then-orphan risk here — the user row and the (still-live, not-yet-rotated)
   previous `Verification` row both already exist regardless of whether this specific resend's send
   succeeds. **Decision:** on a `EmailSendError`, still rotate the row (already done in step 5) but
   return the same generic `200` regardless — matching `/forgot-password`'s own existing
   anti-enumeration contract, which already tolerates the "we said we sent it, verify from your own
   observation" trust model implicit in every OTP-delivery endpoint in this codebase. **Not routed
   to Gate 1** — this only affects behavior on a downstream email-provider outage, a low-stakes
   operational edge case, not a product-shaping decision like decision 3 (which concerns the
   very-first, only-chance-to-deliver code at registration, a materially different stakes profile
   from a resend the user can simply request again).

**Response:** `200`, `MessageResponse` (`{"msg": "If the email exists and is not yet verified, a
verification code has been sent."}`) — deliberately reworded from `/forgot-password`'s message
(which doesn't need the "and is not yet verified" clause) rather than reusing the identical string,
since this endpoint has a third possible real-world state (already verified) that the message
should not contradict.

**Error responses:** `422` (validation), `429` (rate limited). No `400`/`404` — same "always 200"
shape as `/forgot-password`.

### 2.3 `POST /auth/register` — triggers verification-code send; fails closed per Gate 1 decision 3

**Response shape and success status code are unchanged** (`201`, `UserResponse`, `is_verified:
false`) — Scenario 1.1's AC is explicit that the response body must not change to carry any
token/secret. What changes is the server-side effect and, critically, the **failure mode**.

**Decision (implements Gate 1 decision 3 literally): if the verification email fails to send, the
entire registration is rolled back — no `User` row, no `Verification` row survive.** This requires
restructuring `register`'s transaction boundary, not just adding a call at the end:

```python
@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def register(
    user_in: UserCreate,
    db: AsyncSession = Depends(deps.get_db),
    email_sender: EmailSender = Depends(deps.get_email_sender),
) -> Any:
    result = await db.execute(select(User).filter(User.email == user_in.email))
    if result.scalars().first():
        raise HTTPException(status_code=400, detail="The user with this email already exists in the system.")

    user = User(email=user_in.email, hashed_password=security.get_password_hash(user_in.password),
                is_active=True, is_verified=False)
    db.add(user)
    await db.flush()  # assigns user.id -- needed before the Verification row and the response, no commit yet

    otp = _generate_otp()
    verification = Verification(
        email=user.email,
        code=security.hash_otp(otp),
        purpose=EMAIL_VERIFICATION_PURPOSE,
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=EMAIL_VERIFICATION_OTP_TTL_MINUTES),
    )
    db.add(verification)
    await db.flush()

    subject, body = render_verification_email(otp)
    try:
        await email_sender.send(to=user.email, subject=subject, body=body)
    except EmailSendError:
        await db.rollback()  # undoes BOTH the User and the Verification insert -- same transaction
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Registration could not be completed: the verification email could not be sent. Please try again.",
        )

    await db.commit()
    await db.refresh(user)
    return user
```

**Why `flush()` twice, not one `commit()` at the end followed by a conditional delete on failure:**
a `flush()` sends the pending `INSERT`s to Postgres (assigning `user.id`, satisfying the
`Verification.email` FK-less-but-logically-dependent relationship) **without** ending the
transaction — `db.rollback()` on a flushed-but-uncommitted transaction cleanly undoes both inserts
atomically, with no window where a partially-created user is externally visible (no other
connection can see uncommitted rows in Postgres's default isolation level) and no need for manual
compensating deletes if the email send fails after all. This is a strictly cleaner mechanism than
"commit, then delete the user row if the email fails," which would have a real (if brief) window
where a fully-committed, unverifiable user row exists — and would need to also manually clean up
the `Verification` row, duplicating what `rollback()` gets for free.

**New response:** `503` — "verification email could not be sent, registration rolled back." Per
Gate 1 decision 3's exact wording ("fail the registration... registration fails (rolled back) if
the email send fails") and matching the business-analyst's own primary recommendation
(`obj-005-email-verification-flow.md` Open Product Decisions §4: "Fail the registration (return
503 or 502)"). **503 chosen over 502**: this service is not acting as a gateway/proxy to the email
provider in the HTTP sense 502 implies; 503 ("service temporarily unavailable," attributable to a
downstream dependency outage) is the more standard fit and matches how a transient external-
dependency failure is conventionally surfaced.

**Not an enumeration concern:** unlike `/forgot-password`/`/verify-email`, `/register`'s existing
enumeration behavior (explicit `400` "already exists") is **out of this objective's scope** —
that's audit finding #6, tracked separately as OBJ-007, blocked on its own pending product
decision. This objective does not touch that branch or its status code.

---

## 3. Login/refresh enforcement mechanics — the one sub-decision within the already-locked Option A

Gate 1 decision 1 locked **that** unverified users are blocked (Option A) — not **how** the
rejection is shaped. The requirements doc's own Scenario 2.A.1 AC text asks for something this
codebase's existing precedent already doesn't fully deliver ("no difference in
response time/status between wrong password and unverified"), so this needs an explicit,
documented resolution rather than a silent pick.

### 3.1 The tradeoff, stated precisely

Telling an attacker who has already supplied a **correct** password "this account exists but isn't
verified" (as opposed to reusing the generic wrong-credentials message) reveals two things beyond
"the account exists": (a) that the submitted password is genuinely correct, and (b) that the
account is unverified specifically (not merely inactive, not merely nonexistent). For an attacker
running a credential-stuffing list against this login endpoint, (a) is the materially valuable
signal — it confirms a breached-password-reuse hit even though no session is actually granted.

### 3.2 Resolution: distinguishable message, same status code family already in use — not routed to
Gate 1 as blocking

**Decision:** `/auth/login` gains a check, positioned immediately after the existing `is_active`
check (same 400 status family, same "business-state error, distinct from credential validation"
category already established for that check):

```python
if not user.is_active:
    raise HTTPException(status_code=400, detail="Inactive user")
if not user.is_verified:
    raise HTTPException(status_code=400, detail="Email not verified")
```

**This is not a new class of oracle being introduced — it is the same class already accepted by
this codebase's existing `is_active` branch, extended by one more business-state predicate.**
`/auth/login`'s current code **already** distinguishes "wrong credentials" (generic 400) from
"correct credentials, but inactive account" (a distinct 400 message) — a password-correct-but-
blocked-account signal of exactly the same shape and severity as the one `is_verified` would add.
This precedent was never flagged as a gap by any prior Gate 3 security-specialist pass (OBJ-001,
OBJ-002, OBJ-003 all reviewed `/auth/login` directly and found no oracle issue with it). Extending
the same accepted pattern to a second business-state predicate is consistent, not a fresh
regression — and deliberately **not** what the requirements doc's Scenario 2.A.1 AC literally asks
for (byte-identical response across wrong-password vs. unverified), for the same reason OBJ-001's
Scenario 2.6 and OBJ-003's finding #5 design both already declined to chase perfect,
literal indistinguishability where this codebase has a standing, reviewed precedent that stops
short of it.

**Ordering preserves OBJ-003's timing guarantee.** The `is_verified` check sits *after*
`verify_password_or_dummy` (finding #5's structural bcrypt-always guarantee, §3.1 of
`obj-003-design-notes.md`) — exactly like the existing `is_active` check. The bcrypt call still
executes exactly once per request regardless of account state; nothing about this addition reopens
finding #5.

**`/auth/refresh` — same predicate, same status family, no new oracle beyond what already exists
there either.** `/auth/refresh` already has an analogous 400 branch: `if not user or not
user.is_active: raise 400 "User inactive or not found"` (`auth.py:385-386`), positioned after
session-row/reuse/expiry checks and before the `ver`-claim comparison. **Decision:** add the
`is_verified` check at the same point, piggybacking on the same `User` row already loaded (no
extra query, same pattern already used for `token_version`):

```python
if not user or not user.is_active:
    raise HTTPException(status_code=400, detail="User inactive or not found")
if not user.is_verified:
    raise HTTPException(status_code=400, detail="Email not verified")
```

This implements Scenario 2.A.4 exactly (a holder of an otherwise-valid refresh token cannot mint a
new access token once `is_verified` is `False`) and Scenario 2.A.3's "auditing gate, not
re-verification" framing: the check runs fresh against the DB on every refresh/login call, never
baked into a JWT claim, so it responds immediately to a `User.is_verified` change without needing
any token-level revocation mechanism.

### 3.3 Deliberately NOT checked at `/auth/me` / `get_current_active_user`

Scenario 2.A.3's core point is that **existing, already-issued access tokens keep working** even if
`is_verified` were hypothetically reverted to `False` later — enforcement is a gate on **new**
session issuance (login, refresh), not a revocation of sessions already granted. **Decision:**
`deps.get_current_active_user` (which backs `/auth/me` and any future protected endpoint) is **not**
changed — it continues to check only `is_active`, exactly as it does today. This mirrors
`is_active`'s own existing scope precisely: `is_active` is likewise checked only at
`get_current_active_user`, never baked into `get_current_user`'s core claim checks, and never
revokes a token already in flight either. No new inconsistency introduced — `is_verified` now
follows the identical enforcement-surface pattern `is_active` already established.

### 3.4 Recommendation for a quick Gate 1 nod (non-blocking)

This resolution follows firm, already-reviewed precedent, so it is **not** treated as blocking
Phase 2 — but flagged as the one item worth a quick explicit sign-off at Gate 1, since §3.1's
tradeoff (confirming password-correctness to an attacker via a distinguishable state message) is a
real, if bounded and precedented, choice rather than a pure architecture call. If the user's threat
model wants the requirements doc's stricter original AC (byte-identical response regardless of
account state), the alternative is: fold `is_verified` into the *same* generic message as wrong
credentials at `/login` (returning the ordinary "Incorrect email or password" 400 for a correct-
password-but-unverified account too) and the *same* generic 401 at `/refresh` (folding into
"Invalid or expired refresh token" rather than the `is_active` 400 branch) — both straightforward
one-line changes if the recommendation above isn't the user's preference.

---

## 4. `EmailSender` abstraction

### 4.1 Coordination with OBJ-004's interim seam — explicit, per task instructions

`obj-004-design-notes.md` §5.1 designed a **deliberately minimal, non-competing** placeholder:
`app/core/notifications.send_otp_notification(email, otp, *, purpose)`, explicitly documented as
"temporary, pre-OBJ-005... a real pluggable email-sender abstraction lands in OBJ-005 and will
replace this function's BODY (not its call site in auth.py)." Checked directly: **OBJ-004 has not
been implemented yet** (no `app/core/notifications.py`, no `app/core/audit_log.py` exist in the
repository today — only the design notes describing them) — OBJ-004 is Phase-1-design-complete,
Gate-1-approved, but Phase 2/3 have not run. This means the two objectives' implementation order
relative to each other is not yet fixed, and this design must work correctly either way:

- **If OBJ-004 lands its Phase 3 first:** `developer` implements
  `send_otp_notification`'s body as designed (a no-op). When OBJ-005's Phase 3 runs later, its
  correct move is to **retire** `app/core/notifications.py` entirely rather than keep both
  mechanisms — `/forgot-password`'s call site swaps from `notifications.send_otp_notification(...)`
  to the same `email_sender.send(...)` + `render_password_reset_email(otp)` call this document
  designs for `/register`/`/resend-verification-email` below (§4.4). One delivery mechanism, not
  two competing ones, per the task's explicit instruction.
- **If OBJ-005 lands its Phase 3 first:** `developer` builds the `EmailSender` abstraction directly
  (this section) and wires `/forgot-password` onto it immediately, skipping
  `app/core/notifications.py` entirely — there is nothing to fold in yet because it doesn't exist.
  When OBJ-004's Phase 3 runs later, its `send_otp_notification`/audit-logging design should be
  read as **already superseded** for the email-delivery half (the `EmailSender` abstraction is
  strictly more general and already covers what that seam was for); only OBJ-004's *audit-logging*
  scope (§4 of its design notes — the `auth.*` event catalog, unrelated to email delivery) remains
  fully applicable and should still land as designed.

**Either ordering converges on the same end state**: exactly one delivery mechanism
(`EmailSender`), used by every OTP-delivery call site in the codebase. Flagging this explicitly in
both this document and the dependency-graph update (task item 7) so neither objective's Phase 3
`developer` pass is surprised by which of the two scenarios above it's actually in.

### 4.2 Interface — abstract base + explicit failure signal

**Module:** `app/core/email/` (new package — email delivery is a big enough concern to warrant its
own module, not a single file bolted onto `security.py`/`rate_limit.py`'s "one module owns one
concern" pattern, but a small package: base class, default implementation, and templates are three
distinct, independently testable responsibilities).

`app/core/email/base.py`:
```python
from abc import ABC, abstractmethod
from typing import Optional


class EmailSendError(Exception):
    """Raised by any EmailSender implementation on a delivery failure (SMTP
    timeout, provider API error, etc.). Callers (e.g. /auth/register) MUST
    treat this as a hard failure -- per OBJ-005 Gate 1 decision 3, a failed
    send is never silently swallowed or queued. This is the ONLY failure
    signal any EmailSender implementation may use; a `send()` call that
    returns normally is the only success signal (no boolean return value to
    misinterpret)."""


class EmailSender(ABC):
    @abstractmethod
    async def send(
        self, *, to: str, subject: str, body: str, html_body: Optional[str] = None
    ) -> None:
        """Send one email. Must raise EmailSendError (or a subclass) on any
        failure to actually hand the message off for delivery -- never
        return normally on failure, never log-and-swallow. Implementations
        own their own retry policy internally, if any; from the caller's
        perspective this call either fully succeeds or raises."""
```

**Why `send()` returns `None` (raise-on-failure), not `bool`:** the requirements doc's own Scenario
3.4 explicitly names the exact anti-pattern being avoided ("The send attempt returns an error/
exception (not a silent success)"). A `bool` return is exactly the shape that invites a caller to
forget to check it — an exception cannot be silently ignored the same way, and matches this
codebase's existing convention of using exceptions for "the caller has one job: propagate this
failure" cases (e.g. `_decode_refresh_payload` raising rather than returning a sentinel).

### 4.3 Default implementation — `ConsoleEmailSender`

`app/core/email/console.py`:
```python
import logging

from app.core.email.base import EmailSender

_logger = logging.getLogger("app.email.console")


class ConsoleEmailSender(EmailSender):
    """Default/dev implementation -- prints to stdout, never fails. Direct
    successor to the print-based mock this objective retires (both the
    original inline print in auth.py and, if it landed first, OBJ-004's
    interim notifications.send_otp_notification seam -- see §4.1). The
    rendered `body` naturally contains the plaintext OTP code (hashing only
    ever happens at the DB storage boundary, per OBJ-003 -- this function
    never re-derives or needs the hash), satisfying Scenario 3.2's explicit
    "developers can copy-paste it in tests" requirement."""

    async def send(self, *, to: str, subject: str, body: str, html_body: str | None = None) -> None:
        _logger.info(
            "============================================\n"
            " [EMAIL:CONSOLE] To: %s | Subject: %s\n"
            "%s\n"
            "============================================",
            to, subject, body,
        )
```

**Directly, structurally better for testability than both predecessors it replaces:** the original
`print()` required `capsys` stdout capture (OBJ-003's `test_otp_hashing_integration.py`); OBJ-004's
interim seam was monkeypatchable but still a bare function, not a mockable object method.
`ConsoleEmailSender.send` (and any other `EmailSender` implementation) is a regular async method on
an injectable dependency — `qa-engineer`'s Phase 2 pass can `unittest.mock.patch.object` the
injected instance directly and read the real OTP straight out of `body` via the mock's call
arguments, with no stdout scraping and no coupling to *which* concrete `EmailSender` is configured.

**Required, non-optional carry-over for `qa-engineer`:** both `tests/api/
test_otp_hashing_integration.py` (OBJ-003, already flagged once for the OBJ-004 print-removal
change) and any test currently exercising `/forgot-password`'s OTP recovery must standardize on
mocking the injected `EmailSender.send` call, not stdout capture — whichever of OBJ-004/OBJ-005
lands first establishes this pattern; whichever lands second must not reintroduce a competing
capture mechanism.

### 4.4 Email content — a dedicated templates module, not inline strings

`app/core/email/templates.py` — satisfies Scenario 3.5's "template is never written inline in
Python strings" requirement by giving email copy a single owning module, separate from both the
transport (`EmailSender`) and the business logic (`auth.py`):

```python
def render_verification_email(otp: str) -> tuple[str, str]:
    subject = "Verify your email address"
    body = (
        f"Your verification code is: {otp}\n\n"
        "This code expires in 30 minutes. If you did not create an account, "
        "you can safely ignore this email."
    )
    return subject, body


def render_password_reset_email(otp: str) -> tuple[str, str]:
    subject = "Password reset code"
    body = (
        f"Your password reset code is: {otp}\n\n"
        "This code expires in 10 minutes. If you did not request a password "
        "reset, you can safely ignore this email."
    )
    return subject, body
```

Returns `(subject, body)` rather than a single formatted string, matching `EmailSender.send`'s
signature directly. `html_body` is deliberately not populated here (plain-text only) — no
requirement asks for HTML email, and inventing an HTML template doubles the maintenance surface
for no requested benefit; `EmailSender.send`'s `html_body` parameter stays available for a future
provider/fork that wants it, defaulting to `None`. Full provider-specific templating (localization,
external template files/DB-stored copy per Scenario 3.5's options (a)/(b)) is explicitly out of
scope for this template per the requirements doc's own Summary of Deferred Decisions §4 — this
gives `developer` a single, obvious place to extend it later without touching `EmailSender` or any
endpoint.

### 4.5 Provider selection — dependency injection, minimal `Settings` surface

New `Settings` fields (matching this codebase's existing safe-default convention for non-security-
critical fields, same category as `LOG_LEVEL`):

```python
EMAIL_PROVIDER: str = "console"   # console | smtp | sendgrid | ses -- only "console" ships an implementation
EMAIL_FROM: str = "noreply@example.com"
```

`app/api/deps.py` gains a cached factory, mirroring `get_settings()`'s `@lru_cache` singleton
pattern:

```python
from functools import lru_cache
from app.core.email.base import EmailSender
from app.core.email.console import ConsoleEmailSender

@lru_cache
def _email_sender_singleton() -> EmailSender:
    if settings.EMAIL_PROVIDER == "console":
        return ConsoleEmailSender()
    raise NotImplementedError(
        f"EMAIL_PROVIDER={settings.EMAIL_PROVIDER!r} has no implementation in this template. "
        "Implement an EmailSender subclass (app/core/email/base.py) and register it here -- "
        "SMTP/SendGrid/SES specifics are a deployment concern, out of scope for the template itself."
    )

def get_email_sender() -> EmailSender:
    return _email_sender_singleton()
```

Registered via `Depends(deps.get_email_sender)` at every call site (`register`,
`resend_verification_email`, and — once folded in per §4.1 — `forgot_password`), per the
requirements doc's explicit implementation note ("registered as a FastAPI dependency... not
imported directly in business logic"). `EMAIL_PROVIDER` validated as a plain string with a safe
default, not a `field_validator`-enforced enum like `POSTGRES_SSL_MODE`/`ENVIRONMENT` — a bad value
here fails loudly at first *use* (via `NotImplementedError` in the factory) rather than at import
time, which is an intentional, lower-stakes departure from those two fields' fail-at-import
pattern: an email-provider misconfiguration is an operational/delivery problem, not a security
posture regression the way an unset `SECRET_KEY`/`POSTGRES_SSL_MODE` would be, so gating it at
first request rather than at process startup is proportionate, not a gap.

**Real SMTP/SendGrid/SES implementations are explicitly out of scope for this template**, per the
requirements doc's own Summary of Deferred Decisions §1 — the abstraction and the default console
implementation are this objective's full deliverable; a downstream fork wanting real delivery
implements one more `EmailSender` subclass and points `EMAIL_PROVIDER` at it (registration
mechanism left simple/manual here — a plugin-registry pattern would be over-engineering for a
template whose stated goal is staying lean to fork, same reasoning already applied to the rate
limiter's "no Redis" and the audit logger's "no `structlog`" decisions).

---

## 5. `openapi.yaml` impact

`info.version` bumped to `0.6.0-obj-005` (already reflected in the file from the interrupted prior
pass — confirmed correct as the next sequential minor version after `0.5.0-obj-004`, kept as-is).
`info.description`'s OBJ-005 paragraph (already drafted, confirmed accurate against this
document's actual endpoint names) is left in place; **new/changed path items:**

- **`POST /auth/verify-email`** (new) — request `OTPVerifyRequest` (shared with `/auth/verify-
  otp`, §2.1), `200` → `UserResponse`, `400` (generic, purpose-specific message text), `422`,
  `429`.
- **`POST /auth/resend-verification-email`** (new) — request `EmailRequest` (shared with
  `/forgot-password`), `200` → `MessageResponse`, `422`, `429`. No `400`/`404` (always-200 anti-
  enumeration shape, §2.2).
- **`POST /auth/register`** — description gains a note on the new server-side effect (verification
  code generated + emailed) and the new failure mode; gains a **`503`** response
  (`HTTPError`, "verification email could not be sent, registration rolled back") per §2.3. `201`
  response shape unchanged.
- **`POST /auth/login`** — description gains a note on the new `is_verified` enforcement (§3.2);
  the existing `400` response's `examples` map gains a third case (`unverified: { detail: "Email
  not verified" }`) alongside the existing `bad_credentials`/`inactive` examples — no new status
  code, no schema change (`HTTPError` already covers this shape).
- **`POST /auth/refresh`** — description gains an equivalent note; the existing `400` response
  description is widened from "Token was valid but the associated user is inactive or no longer
  exists" to also cover the new unverified case, with a second example added.
- No changes to any other path item, and **no new `components/schemas`** — every new endpoint
  reuses an existing request schema (`OTPVerifyRequest`, `EmailRequest`) and an existing response
  schema (`UserResponse`, `MessageResponse`, `HTTPError`) exactly as designed above; nothing new to
  define at the schema level, only new path items and description text.

---

## 6. Testability guidance for `qa-engineer`'s Phase 2 pass

- **Email delivery**: mock/patch the injected `EmailSender.send` (the concrete instance
  `deps.get_email_sender()` resolves to, i.e. `ConsoleEmailSender` under default test config) —
  read the real OTP out of the mock's `body` call argument. Do **not** reintroduce stdout/`capsys`
  capture for any new test in this pass, and migrate `test_otp_hashing_integration.py` off it if
  OBJ-004 hasn't already done so by the time this pass runs (§4.3).
- **Register rollback (Gate 1 decision 3)**: assert both halves of the failure — mock
  `EmailSender.send` to raise `EmailSendError`, then assert (a) the HTTP response is `503`, and (b)
  **no** `User` row with that email exists afterward (a fresh `SELECT`, not just trusting the status
  code) — this is the test that actually proves the rollback, not just the error surface.
- **Purpose isolation (§1.1)**: the highest-value test in this pass, by the same logic as OBJ-002's
  family-revocation test — create a live `reset_password` `Verification` row and a live
  `email_verification` row for the *same* email, fail the wrong one's OTP repeatedly, and assert
  the other purpose's `attempts` counter is untouched. This is the concrete proof that generalizing
  `_check_and_consume_otp`'s hardcoded purpose (§1.1) didn't accidentally merge the two budgets.
- **Login/refresh enforcement (§3.2)**: assert the exact status code (`400`) and message text
  chosen here for both `/login` and `/refresh`, and assert `/auth/me` (via
  `get_current_active_user`) does **not** reject an unverified user holding an otherwise-valid,
  pre-existing access token (§3.3) — this is the test that would catch an accidental over-broad
  enforcement (checking `is_verified` somewhere it shouldn't be, e.g. inside `get_current_user`
  itself) regressing Scenario 2.A.3.
- **Resend idempotence on an already-verified user (§2.2 step 3)**: assert a resend request for an
  already-verified email returns the same generic `200` with no new `Verification` row created and
  no `EmailSender.send` call made — distinguishes "silently correct no-op" from "silently broken."
- **Structural, not wall-clock, timing assertions**: per OBJ-003's already-established convention
  (§3.4 of `obj-003-design-notes.md`), assert `security.verify_password_or_dummy`'s call count/
  target at `/login`, not response latency, for any test touching the `is_verified` branch's
  interaction with finding #5's guarantee.

---

## 7. Open items — summary

**One item recommended for a quick, non-blocking Gate 1 nod** (§3.4): the login/refresh
enforcement mechanics (distinguishable `400 "Email not verified"`, following the codebase's
existing `is_active`-branch precedent) rather than the requirements doc's stricter literal AC
(byte-identical response regardless of account state). Resolved here with documented reasoning per
task instructions, not blocking Phase 2 — flagged in case the user's threat model wants the
stricter alternative instead (one-line change either way, §3.4).

**Two coordination points, informational, not decisions:**
1. §1.4 — OBJ-006 status checked directly (plan complete, no Alembic files exist yet); moot for
   this objective regardless, since §1.3 established zero DDL is needed for this change.
2. §4.1 — OBJ-004/OBJ-005 implementation-order coordination for the email-delivery seam; both
   orderings converge on the same end state (one `EmailSender` mechanism), documented explicitly
   so neither objective's `developer` pass is surprised.

No other open decisions — Gate 1's 5 locked decisions plus this document's resolutions cover every
design point the requirements doc raised.
