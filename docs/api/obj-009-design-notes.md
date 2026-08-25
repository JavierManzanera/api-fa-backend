# OBJ-009 — Register Rate Limit — Design Notes

> **Summary (read this, skip the rest unless you need detail):**
> - **Status:** Gate 1 (design only) — no red tests written yet, no implementation. `qa-engineer`/`developer` pick up next.
> - **Endpoint touched:** `POST /auth/register` only. No other endpoint's contract changes.
> - **New response contract:** adds `429` (via the existing shared `RateLimited` component) to `/register`'s response set. No change to the `200`/`422`/`503` responses OBJ-007 already established.
> - **Limit chosen:** **5 requests/minute per (IP, email)** — matches `/forgot-password` and `/resend-verification-email`, not the `10`/min used by `/verify-otp`/`/reset-password`. Rationale in §1: the `5` group is "endpoints that trigger an outbound email send," the `10` group is "endpoints that check an already-issued OTP." `/register` (post-OBJ-007) sends an email on *every* call, on both branches — it belongs in the `5` group by the same logic already established, not by default/precedent-matching alone.
> - **Key architectural decision:** the `enforce_rate_limit` call must sit in the shared `register()` handler, **before** the new-vs-duplicate-email branch decision (before the existing `SELECT User` lookup) — not duplicated inside each of `_handle_new_email_registration`/`_handle_duplicate_email_registration`. This is what guarantees the check applies identically to both branches by construction, not by two call sites happening to agree (§2 — this is the constraint `developer` must respect, flagged explicitly because getting it wrong would reopen OBJ-007's anti-enumeration guarantee as a new timing/observability side channel).
> - **Scope naming:** `scope="register"`, following the existing `forgot_password`/`verify_otp`/`verify_email`/`resend_verification_email`/`reset_password` snake_case-endpoint-name convention in `app/core/rate_limit.py` call sites.
> - **Traces to:** `docs/security/audit-report.md` finding #16 (`docs/security/audit-report.md` §"Gate 3 — Verificación OBJ-007"). No new Gate 1 user decision needed beyond the value chosen here — finding #16 already specified the fix shape ("same pattern as the other five endpoints"); this doc picks the number and the exact call-site.
> - **Spec file changed:** `docs/api/openapi.yaml` — `/auth/register` path block gains a `429` response entry + a new description paragraph; top-level `info.description` and `version` (bumped to `0.9.0-obj-009`) updated to list the OBJ-009 remediation surface.

## Jump-to index

- [§1 — Choosing the limit: 5/min, and why](#1--choosing-the-limit-5min-and-why) — the email-send-vs-OTP-check grouping that already exists in this codebase, applied to `/register`.
- [§2 — Call-site placement: shared code path, not per-branch](#2--call-site-placement-shared-code-path-not-per-branch) — the anti-enumeration constraint and why it dictates where the call goes.
- [§3 — OpenAPI contract change](#3--openapi-contract-change) — exact diff shape, matching the existing `RateLimited` pattern.
- [§4 — What `developer` must NOT do](#4--what-developer-must-not-do) — concrete anti-patterns that would reopen finding #6.
- [§5 — Architectural boundaries](#5--architectural-boundaries) — unchanged by this objective; restated for completeness.

---

## §1 — Choosing the limit: 5/min, and why

`app/api/v1/endpoints/auth.py` currently defines five rate-limit constants (lines ~32-71):

| Constant | Value | Endpoint | Triggers an email? |
|---|---|---|---|
| `FORGOT_PASSWORD_RATE_LIMIT_PER_MINUTE` | 5 | `/forgot-password` | Yes (OTP email) |
| `VERIFY_OTP_RATE_LIMIT_PER_MINUTE` | 10 | `/verify-otp` | No (checks an existing OTP) |
| `VERIFY_EMAIL_RATE_LIMIT_PER_MINUTE` | 10 | `/verify-email` | No (checks an existing OTP) |
| `RESEND_VERIFICATION_RATE_LIMIT_PER_MINUTE` | 5 | `/resend-verification-email` | Yes (verification email) |
| `RESET_PASSWORD_RATE_LIMIT_PER_MINUTE` | 10 | `/reset-password` | No (checks an existing OTP, then mutates) |

This isn't an arbitrary 5-vs-10 split — it tracks a real distinction, confirmed by reading each handler: `obj-001-design-notes.md` §5 point 2 recommended "5 req/min... on `/forgot-password` (it triggers an email-send side effect), 10 req/min... on `/verify-otp` and `/reset-password`" — i.e. the group that fires an outbound send gets the tighter limit (a legitimate user rarely needs more than 1-2 email requests/minute; the send itself is the expensive/abusable side effect worth throttling harder), while the group that's just checking an already-issued code against `Verification.attempts` gets more headroom (a legitimate user might mistype an OTP a few times in quick succession, and `MAX_OTP_ATTEMPTS` already caps abuse via the separate OTP-lockout mechanism — see `obj-001-design-notes.md` §2 for why these two mechanisms are kept apart).

`POST /auth/register`, post-OBJ-007, sends exactly one outbound email on **every** call, on **both** branches (`_handle_new_email_registration` sends the verification-code email; `_handle_duplicate_email_registration` sends the "you already have an account" notice — `obj-007-design-notes.md` §2-3). It has no OTP-check role at all. It belongs in the email-send group by the same reasoning already applied to `/forgot-password` and `/resend-verification-email`, not merely because it's "the closest analog" — the grouping logic transfers directly, not by loose similarity.

**Decision: `REGISTER_RATE_LIMIT_PER_MINUTE = 5`**, same value and same justification category as `FORGOT_PASSWORD_RATE_LIMIT_PER_MINUTE`/`RESEND_VERIFICATION_RATE_LIMIT_PER_MINUTE`. No deviation found to justify a different number.

## §2 — Call-site placement: shared code path, not per-branch

**This is the load-bearing decision in this doc — get this wrong and OBJ-007's Gate 3 PASS is invalidated.**

`register()` currently reads (`auth.py:220-252`):

```python
async def register(http_request, user_in, db, email_sender):
    ip = rate_limit.client_ip(http_request)
    result = await db.execute(select(User).filter(User.email == user_in.email))
    user = result.scalars().first()

    if user:
        return await _handle_duplicate_email_registration(user_in, ip, email_sender)
    return await _handle_new_email_registration(db, user_in, ip, email_sender)
```

`enforce_rate_limit` must be called **here, in `register()`, before the `SELECT User` lookup** — i.e. before the code even knows which branch it's about to take:

```python
async def register(http_request, user_in, db, email_sender):
    ip = rate_limit.client_ip(http_request)
    await rate_limit.enforce_rate_limit(
        db, scope="register", ip=ip, email=user_in.email, limit=REGISTER_RATE_LIMIT_PER_MINUTE,
    )
    result = await db.execute(select(User).filter(User.email == user_in.email))
    ...
```

This exactly mirrors `/forgot-password`'s existing placement (`auth.py:378-388`: `enforce_rate_limit` call precedes that endpoint's own `SELECT User`) — not a new pattern, the established one.

**Why this matters more here than it would for a generic endpoint:** OBJ-007's entire deliverable was making the new-email and duplicate-email branches of `/register` indistinguishable from the outside — identical status code, identical body (shared module-level constants), identical bcrypt cost (unconditional `get_password_hash` call on both branches), identical email-send call count, identical `503` on send failure (`obj-007-design-notes.md` §1-3, confirmed closed in `audit-report.md`'s Gate 3 OBJ-007 pass, finding #6). Rate limiting is a **new mechanism being added on top of an already-closed anti-enumeration guarantee** — if it were implemented asymmetrically (e.g. only inside `_handle_new_email_registration`, or with a different `scope`/`limit` per branch, or counted differently because one branch does more DB work first), it would reopen finding #6 as a *new* side channel: an attacker could distinguish "new email" from "duplicate email" by noticing which one gets throttled after N requests, even with the response bodies still byte-identical. A single call, in the one code path both branches share, before the branch decision even happens, makes this class of bug structurally unreachable — the same "impossible by construction, not just undiscovered by testing" standard `obj-007-design-notes.md` and the Gate 3 audit already applied to the zero-new-rows guarantee (`_handle_duplicate_email_registration` has no `db` parameter at all).

**Deviation from the audit's literal fix suggestion, and why it's the better implementation of the same goal:** `audit-report.md` §"[NUEVO — #16...]" suggests "requiere pasar `db` también a `_handle_duplicate_email_registration`" — i.e. call `enforce_rate_limit` inside each handler. That would work only if both call sites were kept in perfect sync (same `scope`, same `limit`, same position relative to other work) forever — two call sites is two places for that symmetry to silently drift on a future edit. Calling it once in `register()`, before the branch split, achieves the audit's actual goal (both branches rate-limited, uniformly) more robustly, and as a side benefit means `_handle_duplicate_email_registration` keeps its current signature (still no `db` parameter — the zero-new-rows structural guarantee is untouched). `developer` should implement it this way, not the audit's literal call-site suggestion.

## §3 — OpenAPI contract change

`docs/api/openapi.yaml`, `/auth/register` → `post` → `responses`:

- Added `'429': $ref: '#/components/responses/RateLimited'`, positioned between the existing `'422'` and `'503'` entries (ascending-status-code ordering, matching every other multi-error-response path in this file).
- No new schema — reuses the existing shared `RateLimited` response component (`headers.Retry-After` + `HTTPError` body, `"Too many requests. Please try again later."`) already referenced by `/forgot-password`, `/verify-otp`, `/verify-email`, `/resend-verification-email`, `/reset-password`. Zero new components introduced by this objective.
- Added a description paragraph under `/register`'s existing `description` block documenting the rate-limit addition and explicitly cross-referencing this doc's §2 uniformity constraint, so a future reader of the spec alone (not just this doc) sees the "must not become a branch side channel" warning.
- Top-level `info.description` gained one clause listing the OBJ-009 remediation surface (matching how every prior objective's remediation was listed there), and `info.version` bumped `0.7.0-obj-007` → `0.9.0-obj-009` (skipping `0.8.0` since no `obj-008` spec change exists — OBJ-008 is a `python-jose`→`PyJWT` dependency swap with no HTTP contract surface).

No other endpoint's contract changes. No new/changed schemas.

## §4 — What `developer` must NOT do

Concrete anti-patterns, called out explicitly since this is the kind of mistake that passes a superficial glance:

1. **Do not** call `enforce_rate_limit` separately inside `_handle_new_email_registration` and `_handle_duplicate_email_registration`. Two call sites, even with identical arguments today, is a maintenance hazard and not what this design specifies.
2. **Do not** use a different `scope` string per branch (e.g. `"register_new"` vs. `"register_duplicate"`) — this would let the two branches' rate-limit counters be observed/exhausted independently, itself a distinguishing signal. One `scope="register"` for the whole endpoint.
3. **Do not** place the call after the `SELECT User` lookup or after the branch dispatch — the whole point is that the limiter fires (or doesn't) before the code has any information that could differ between branches.
4. **Do not** wire `REGISTER_RATE_LIMIT_PER_MINUTE` to a different value than `5` without updating this doc's §1 reasoning — if a future objective needs a different number, that's a new Gate 1 decision, not a silent tweak.

## §5 — Architectural boundaries

Unchanged by this objective, restated for completeness: `app/core/rate_limit.py` remains the sole owner of rate-limit enforcement logic and the `RateLimitHit` table (infrastructure module, decoupled from endpoint business logic — `obj-001-design-notes.md` §2 "Module ownership"). `app/api/v1/endpoints/auth.py` remains the sole owner of all identity/credential/session HTTP surface (per `openapi.yaml`'s `tags.auth` description). This objective adds one new call site into an existing module boundary; it does not introduce a new module, table, or ownership question.
