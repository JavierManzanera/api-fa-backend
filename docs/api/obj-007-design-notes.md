# OBJ-007 — Registration Enumeration Policy Decision — Design Notes

> **Summary (read this, skip the rest unless you need detail):**
> - **Status:** Gate 1 (design only) — no red tests written yet, no implementation. `qa-engineer` picks up next.
> - **Endpoint touched:** `POST /auth/register` only. No other endpoint's contract changes.
> - **New response contract:** `200 OK` + `MessageResponse` (`{"msg": "..."}"`) — **always**, regardless of whether the email was already registered. Replaces the old `201 Created` + `UserResponse` (new) / `400` + `HTTPError` (duplicate) split.
> - **Key decision:** reuse `/forgot-password`'s exact generic-response pattern (§1) rather than inventing a third shape or trying to preserve `UserResponse` — returning real user data on only one branch would itself be the enumeration oracle.
> - **Timing parity:** duplicate-email branch must pay an equivalent bcrypt-hash cost to the new-account branch (§3) — extends the `verify_password_or_dummy` precedent from OBJ-003, but for a *hash* operation, not a *verify* operation.
> - **Server-side requirement:** existing-email branch must send a "you already have an account" notification email (not a new OTP), create zero `User`/`Verification` rows, and its `EmailSender` failure must also produce the same `503` as the new-account branch (§2, §3).
> - **Traces to:** `docs/security/audit-report.md` finding #6. Gate 1 decision recorded in `.ai-context/dependency_graph.md` OBJ-007 card (2026-08-25, user).
> - **Spec file changed:** `docs/api/openapi.yaml` — `/auth/register` path block, top-level `description` and `version` bumped. No new/changed schemas (`MessageResponse` already existed, reused as-is).

## Jump-to index

- [§0 — Context and prior state](#0--context-and-prior-state) — what `/register` did before this objective, and why it needed to change.
- [§1 — The unified response contract](#1--the-unified-response-contract) — status code and body decision, and why `UserResponse` couldn't be kept.
- [§2 — Server-side branch behavior (not client-visible)](#2--server-side-branch-behavior-not-client-visible) — the notification-email requirement and the zero-new-rows constraint.
- [§3 — Timing and cost parity](#3--timing-and-cost-parity) — the bcrypt-hash parity requirement and the extended `503` symmetry.
- [§4 — Residual risks / open items for Gate 3](#4--residual-risks--open-items-for-gate-3) — accepted asymmetries, flagged for `qa-engineer`/`security-specialist`, not blocking Gate 1.
- [§5 — Architectural boundaries](#5--architectural-boundaries) — which module owns what, unchanged by this objective.

---

## §0 — Context and prior state

`app/api/v1/endpoints/auth.py` (~line 203-229, current implementation, pre-OBJ-007) does:

```
result = SELECT User WHERE email = user_in.email
if user:
    raise HTTPException(400, "The user with this email already exists in the system.")
# ...else create User + Verification, send verification email, 201 + UserResponse
```

This is audit finding #6 (`docs/security/audit-report.md` line 104): the explicit `400` on a duplicate email is a direct, unauthenticated account-enumeration oracle — contrasted there against `/forgot-password`'s already-correct generic-`200` design (closed under OBJ-003 finding #5's timing work, see `obj-003-design-notes.md` §3.2).

The audit's suggested fix text offered two options: "accept the registration and still return 201, emailing an 'already have an account' notice" OR "document the trade-off as an accepted risk." The user's Gate 1 decision (`.ai-context/dependency_graph.md` OBJ-007 card, 2026-08-25) resolves this explicitly: **mirror `/forgot-password`'s pattern** — not the audit's literal "still 201" phrasing. That's a deliberate refinement, not a contradiction: the audit text was a coarse suggestion; the user's decision picks the more consistent of the two established patterns already in this codebase (`/forgot-password`, and — since OBJ-005 — `/resend-verification-email`) rather than introducing a third precedent. §1 below explains why "201 either way" doesn't actually work once you look at what `201`'s current body contains.

## §1 — The unified response contract

**Decision: reuse `MessageResponse` (`{"msg": string}`) verbatim, at `200 OK`, for both branches.**

Why not keep `201 Created` + `UserResponse` for both branches (the audit's literal suggestion)? Look at what `UserResponse` actually contains (`openapi.yaml` schema, unchanged): `id` (UUID), `email`, `is_active`, `is_verified`, `created_at`. For the new-account branch this is the real, freshly-created row. For the duplicate-email branch there is no new row — so returning `UserResponse` there means one of two things, both rejected:

1. **Return the real existing account's data** (its actual `id`, its actual `is_verified` state, its actual `created_at`). This doesn't just fail to fix the enumeration problem — it upgrades it from "yes/no exists" to "here is a summary of that account," including whether it's verified yet and when it was created. Strictly worse than the `400` it replaces.
2. **Fabricate a fake `UserResponse`** (random UUID, `is_verified: false`, `created_at: now()`). This technically satisfies "same shape," but it's brittle (any future field added to `UserResponse` needs a parallel fake-data decision), easy to get subtly wrong (e.g. `is_verified` semantics), and provides no value to a legitimate caller — a real client's registration UX doesn't need the fabricated id for anything, since the real flow continues via email-link/OTP, not via this response body.

Both options are worse than simply not returning resource data at all. Since `/forgot-password` and `/resend-verification-email` already established the correct pattern for "unauthenticated endpoint whose response must not depend on account existence" — a generic `200`/`MessageResponse` — OBJ-007 adopts that pattern for `/register` rather than inventing a fourth option. This is also why status code changes from `201` to `200`: `201 Created` conventionally pairs with returning a representation of the created resource; since the response no longer represents "the resource that was created" (it's a generic acknowledgment, true in both branches), `200` is the semantically correct code, not just an arbitrary alignment with `/forgot-password`.

**New message** (constant to add in `auth.py`, alongside the existing `GENERIC_OTP_SENT_MESSAGE`):
```
GENERIC_REGISTRATION_MESSAGE = "If this email is not already registered, we've sent you a verification code to complete your registration."
```
Phrasing follows the same "if X, then Y" conditional structure as `GENERIC_OTP_SENT_MESSAGE` ("If the email exists, an OTP has been sent.") — true and non-committal in both branches: a truthful description of the new-account branch's actual effect, and equally truthful (vacuously, via the "if" clause) when the email was already registered and no code was sent.

**Breaking-change note for `developer`/`qa-engineer`:** any existing test or client relying on `201` + `UserResponse` from `/register` needs updating — this is an intentional, user-approved contract break, not a regression to flag.

## §2 — Server-side branch behavior (not client-visible)

Per the Gate 1 decision, these requirements govern internal behavior only — never surfaced in the HTTP response, which is identical either way (§1):

- **New email (unchanged from OBJ-005):** create `User` row, create `purpose="email_verification"` `Verification` row, send verification-code email via the injected `EmailSender`.
- **Already-registered email (new):** create **no** `User` row, **no** `Verification` row — zero new DB rows of any kind for this branch, matching the existing (pre-OBJ-007) behavior of not touching the DB beyond the initial lookup `SELECT`. Instead, send an "already have an account" notification email to that address via the same `EmailSender` abstraction used for the new-account branch (not the older `app/core/notifications.py` placeholder seam — `EmailSender` is the correct owner per `obj-005-design-notes.md` §4, and using the same abstraction on both branches is also what makes the §3 cost-parity requirement natural to implement). Suggested content (copy is `developer`'s/product's call, not prescribed here): something to the effect of "Someone tried to register an account using this email address. If this was you, you already have an account — try logging in or resetting your password. If this wasn't you, no action is needed."
- **Audit logging is exempt from the anti-enumeration constraint** and should keep recording the real distinction — the existing `audit_log.log_auth_event("auth.register", ..., outcome="duplicate")` vs. `outcome="success")` calls are internal-only observability, not part of the HTTP contract, and should be kept (this already matches how `/login` and `/forgot-password` log distinguishable outcomes internally while returning generic-or-uniform responses externally).

## §3 — Timing and cost parity

The HTTP response body and status code being identical (§1) is necessary but not sufficient — response **latency** is also a side channel, per the same reasoning already applied to `/login` and `/forgot-password` (`obj-003-design-notes.md` §3.2, closing audit finding #5).

**Requirement:** both branches of `/register` must perform one bcrypt-cost operation before responding.

- New-account branch already does this: `security.get_password_hash(user_in.password)` is a bcrypt **hash** call.
- Duplicate-email branch currently does nothing bcrypt-related — it returns immediately after the initial `SELECT`. This must change to pay an equivalent bcrypt cost.

**Important distinction from the `/login`/`/forgot-password` precedent:** those endpoints use `security.verify_password_or_dummy`, which performs a bcrypt **verify** against either the real hash or a fixed dummy hash — appropriate there because both branches are already doing a verify. `/register`'s real cost driver is a bcrypt **hash** (`get_password_hash`), not a verify — hash and verify are not guaranteed to cost the same number of bcrypt rounds/time in every implementation, so reusing `verify_password_or_dummy` as-is on `/register`'s duplicate branch would not actually close the gap. `developer` should either:
  (a) call `security.get_password_hash(user_in.password)` unconditionally on the duplicate-email branch too (discarding the result), so both branches pay the literal same operation, or
  (b) add a small `security.py` helper (e.g. `hash_password_dummy()`) if unconditionally hashing the caller-supplied password on the duplicate branch is considered wasteful/undesirable for some other reason.
Option (a) is recommended for simplicity and exactness — it's the same pattern spirit as `verify_password_or_dummy`, just applied to the operation `/register` actually uses. This is an implementation-mechanism decision for `developer`/`security-specialist` to finalize at Gate 3; the **contract requirement** (equivalent bcrypt-hash cost, unconditionally, on both branches) is what this design doc fixes.

**`EmailSender.send()` must also execute on both branches** (§2) — this is not only a functional requirement (the notification must actually be sent) but also a latency-parity contributor, since network-bound email-send calls are not necessarily fast or constant-time themselves. Structuring both branches to make exactly one `EmailSender.send()` call keeps this dimension aligned too.

**`503` symmetry (extends OBJ-005's failure-mode design):** since both branches now make an `EmailSender.send()` call, both branches can now fail that call. The failure response must be identical in both cases — same `503` status, same generic `HTTPError` body (`docs/api/openapi.yaml` — see the `/auth/register` `503` response, wording deliberately branch-agnostic: "a required outbound email could not be sent," not "the verification code" or "the notification"). New-account branch: failure triggers the existing OBJ-005 rollback (no `User`/`Verification` row survives, via `flush()`-then-`rollback()`). Existing-account branch: nothing to roll back, since §2 already prohibits creating rows there. This closes a residual oracle that would otherwise exist if only the new-account branch could ever 503 (an attacker who can force `EmailSender` failures — e.g. during a provider outage — could otherwise distinguish branches by which ones occasionally 503).

## §4 — Residual risks / open items for Gate 3

Not blocking Gate 1, but flagged for `qa-engineer`/`security-specialist` review at Gate 3, consistent with how this project has handled comparable residuals before (see `obj-003-design-notes.md` §3.2's treatment of `/forgot-password`'s own query-count asymmetry):

- **DB query-count asymmetry remains, and is accepted per existing project precedent.** The new-account branch performs more DB round-trips (2 inserts + 2 flushes + a commit) than the duplicate-email branch (a `SELECT` only, beyond the shared bcrypt-hash and email-send calls added by this objective). `/forgot-password` has the identical shape of asymmetry (found-email branch does an extra `SELECT` + `DELETE` + `INSERT` + `commit`; not-found branch does not) and was accepted as closed under OBJ-003 finding #5 on the reasoning that the bcrypt operation dominates the timing signal by orders of magnitude relative to a few extra DB round-trips. The same reasoning is expected to apply here, but re-confirming it (e.g. with an actual timing measurement, not just an assumption) is `security-specialist`'s call at Gate 3, not asserted as proven here.
- **Rate limiting is out of scope for this objective.** `/register` currently has no `rate_limit.enforce_rate_limit` call (unlike `/forgot-password`, `/verify-otp`, `/resend-verification-email`). This objective does not add one — it was not part of the Gate 1 decision — but it's worth noting `/register` is now the last unauthenticated auth endpoint without rate limiting, which `security-specialist` may want to track as a separate future finding if not already covered elsewhere in the audit report.
- **Notification-email copy is not specified here** — the exact subject/body of the "you already have an account" email (§2) is left to `developer`/product judgment. If it will eventually be tested by `qa-engineer` for exact wording, that copy should be finalized before red-phase tests are written to avoid churn.

## §5 — Architectural boundaries

Unchanged by this objective. Per `openapi.yaml`'s `tags` section: the `auth` module owns all identity/credential/session data (`User`, `Verification`, `refresh_sessions`) — no other module reads or writes these tables. Outbound email stays owned by `app/core/email/` (`EmailSender` abstraction, OBJ-005) — this objective extends its use to the duplicate-email branch of `/register` rather than introducing a second email-sending path. No new schema, no new table, no new module boundary crossed.
