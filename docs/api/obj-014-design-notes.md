# OBJ-014 — Rate Limiter DoS Mitigation (Finding #20) + Multiplier Validator (Finding #21) — Design Notes

> **Summary (read this, skip the rest unless you need detail):**
> - **Status:** Gate 1 design only, as of 2026-08-25 — no code changed by this doc. `developer` implements against §3 (finding #20) and §7 (finding #21).
> - **Findings addressed:** `docs/security/audit-report.md` "Gate 3 — Verificación OBJ-013" §3d (**#20**, MEDIUM — single-IP email-budget DoS against a chosen victim) and §3b (**#21**, LOW — `RATE_LIMIT_IP_MULTIPLIER` has no floor validator).
> - **#20 mechanism chosen: a bounded "reserved fresh-IP slot" pool inside the existing email-only check.** The last `RATE_LIMIT_EMAIL_RESERVED_SLOTS` (default **1**) of each scope's email-keyed `limit` are reserved exclusively for an IP that has **not yet been recorded against that email in the current window** — a single attacking IP can never claim them, guaranteeing the real victim's own (different) IP at least one legitimate attempt per window even while the attacker's IP has already exhausted the rest of the budget. Total ceiling per email per window is **unchanged** (`limit`, same as today) — this does not weaken the existing OTP/registration brute-force protection (findings #2/#16), it only restricts who may claim the last slice of it.
> - **Two more obvious-looking mechanisms were considered and rejected as actually broken, not just suboptimal** — see §2.2/§2.3: a flat per-IP contribution cap on the email tally *reopens* #2/#16 (pushes single-IP brute force from the tight email limit up to the loose IP limit), and an unlimited "first-time-IP-always-passes" grace *reopens* #17 entirely (a botnet using one request per unique IP would never be blocked). The chosen design is a hybrid, bounded specifically to avoid both failure modes.
> - **What this does NOT fully fix, stated plainly:** an attacker with `1 + RATE_LIMIT_EMAIL_RESERVED_SLOTS` distinct IPs (2, at the default) still fully denies every fresh IP for that window — this raises the attacker's cost from "one fixed IP, forever" to "at least two distinct IPs," it does not eliminate the DoS class. Consistent with this project's existing accepted residual-risk framing for distributed attackers (`obj-013-design-notes.md` §6).
> - **CAPTCHA/proof-of-work explicitly NOT adopted here** — already tracked as a separate backlog item (audit-report.md finding #2's original recommendation); see §2.4 for why it's out of scope for this objective specifically (backend-only template, no verification-service abstraction exists yet, bigger scope than a keying-adjacent fix).
> - **#21 fix:** a `field_validator` on `RATE_LIMIT_IP_MULTIPLIER` requiring `>= 1`, same fail-closed pattern as `SECRET_KEY`/`POSTGRES_SSL_MODE`/`ALGORITHM`/`ENVIRONMENT` in `app/core/config.py`. The new `RATE_LIMIT_EMAIL_RESERVED_SLOTS` setting introduced by this doc gets the same validator treatment (`>= 0`) proactively, so it doesn't become a future finding #22 of the same shape.
> - **Gate-1 tradeoff flagged for user visibility (§6):** `RATE_LIMIT_EMAIL_RESERVED_SLOTS` default of `1` is a genuine judgment call (same status as `RATE_LIMIT_IP_MULTIPLIER`'s `5` in OBJ-013) — raising it increases the distinct-IP cost of a full DoS but shrinks the brute-force-facing main pool proportionally; the user may want a different default before `developer` implements it.
> - **OpenAPI impact: none** (§5) — same reasoning as OBJ-013: 429 body/`Retry-After` unchanged; the audit log gains fields, the wire response does not.

## Jump-to index

- [§1 — Finding #20, restated with the mechanism](#1--finding-20-restated-with-the-mechanism) — the exploitable gap, in this doc's own words, with a pointer to the audit report's full analysis.
- [§2 — Design decision: the reserved fresh-IP slot pool](#2--design-decision-the-reserved-fresh-ip-slot-pool) — the chosen mechanism, the two broken-looking alternatives and why each fails, and why CAPTCHA/escalating-delay were not adopted.
- [§3 — Exact query/logic spec for `developer`](#3--exact-querylogic-spec-for-developer) — pseudocode-level detail, new setting, new helper query.
- [§4 — Call-site impact and DB follow-up](#4--call-site-impact-and-db-follow-up) — zero call-site diffs; index recommendation for `database-architect`.
- [§5 — OpenAPI contract impact: none](#5--openapi-contract-impact-none) — same 429 shape; audit-log-only additions.
- [§6 — Residual risk, backlog, and the Gate-1 tradeoff flagged for the user](#6--residual-risk-backlog-and-the-gate-1-tradeoff-flagged-for-the-user)
- [§7 — Finding #21: `RATE_LIMIT_IP_MULTIPLIER` validator spec](#7--finding-21-rate_limit_ip_multiplier-validator-spec)
- [§8 — Architectural boundaries](#8--architectural-boundaries) — unchanged; restated for completeness.

---

## §1 — Finding #20, restated with the mechanism

Full analysis already lives in `docs/security/audit-report.md`, "Gate 3 — Verificación OBJ-013" §3d (finding #20) — read that first if you need the original discovery narrative; not re-derived here. Restated at the level this doc needs:

`enforce_rate_limit`'s email-only check (`app/core/rate_limit.py:75-85`) is a plain `COUNT(*) WHERE scope=scope AND email=email AND created_at > window_start`, with **no `ip` predicate at all** — by design, since that's exactly what closed finding #17 (a distributed attacker rotating both `ip` and `email` per request must now contend with the email-only tally regardless of which IP they used). The side effect: any single IP — including one fixed IP an attacker never bothers to rotate — can, on its own, drive that same tally up to `limit` using a victim's email, with no need to know whether the account exists (anti-enumeration, OBJ-007 finding #6, means the endpoint never branches on that) and no need to touch the victim's real IP at all. Once the tally is at `limit`, the *victim's own* next legitimate request — from their own real, different IP — is blocked too, because the bucket is keyed on `email` alone and shared indiscriminately between whoever supplies that email string. Repeatable every 60s window, at any of the 6 rate-limited endpoints, from one fixed attacker IP, forever.

## §2 — Design decision: the reserved fresh-IP slot pool

**Chosen mechanism:** partition each scope's existing email-keyed `limit` into two bands, evaluated against the *same* uncapped `COUNT(*)` used today:

- **Main pool** — the first `limit - reserved` hits against an email in the window. Behaves **exactly as today**: any IP may contribute, uncapped, first-come-first-served. This is what still fully absorbs single-IP and distributed brute-force volume (findings #2/#16/#17) — untouched.
- **Reserved pool** — the last `reserved` hits (`RATE_LIMIT_EMAIL_RESERVED_SLOTS`, default `1`) before `limit`. A request only gets to consume one of these slots if its **requesting IP has never been recorded against this exact `(scope, email)` in the current window**. An IP that has already been seen for this email — attacker or not — is blocked once the main pool is exhausted, even though the raw tally hasn't reached `limit` yet.

Net effect: the *total* ceiling for a single email per window is unchanged (`limit`, identical to pre-#20 behavior) — this is not a new global limit, it's a restriction on **who** may spend the last slice of the existing one. A victim whose real IP hasn't been used against their own email yet this window is guaranteed at least `reserved` requests through, regardless of how thoroughly a single attacking IP has already hammered the main pool.

**Why this exact shape, and not something simpler** — two more obvious mechanisms were worked through and rejected as actually broken (not merely less elegant), which is worth recording so nobody re-proposes them later:

### §2.1 (for context) — candidates already listed in the audit report

The audit report's own §3d lists four backlog candidates: CAPTCHA, an "IP-diversity requirement before a hit counts," an alternate recovery channel, and audit-log-only observability. This doc's mechanism is a refined, boundedly-safe version of the second one — see §2.2 for why the *naive* version of "IP diversity" doesn't work.

### §2.2 — Rejected: a flat per-IP contribution cap on the email tally

The obvious-looking fix: cap how much any single IP can contribute toward the email tally (e.g. `min(count_from_this_ip, CAP)` summed across distinct IPs via `GROUP BY ip`), forcing an attacker to spread across multiple IPs to fully exhaust `limit`.

**This reopens findings #2/#16.** The tight email-keyed `limit` (5 or 10/min depending on scope) exists specifically to cap *single-IP* OTP/registration brute-forcing against one target — that attack shape is "one IP, one email, N requests," which is structurally identical to the shape finding #20 exploits. If a single IP's contribution to the email tally is capped below `limit`, that IP's *own* further requests against that email stop being throttled by the tight email limit once the cap is reached — they fall through to being governed only by the much looser IP-only limit (`limit × RATE_LIMIT_IP_MULTIPLIER`, 25–50/min by default). That's a straightforward regression of the exact protection OBJ-001/OBJ-009 closed, in exchange for a partial fix to #20. Rejected outright — not a tradeoff worth making.

### §2.3 — Rejected: unlimited "first-time-IP-for-this-email always passes"

The other obvious-looking fix: whenever the email tally would 429, check "has this exact IP been seen for this email yet this window?" — if not, let it through once, on the theory that the real victim's IP is presumably new relative to the attack noise.

**This reopens finding #17 entirely.** A distributed attacker who sends exactly one request per unique IP (precisely the attacker shape finding #17's fix was built to catch) would find "my IP hasn't been seen for this email" true on *every single request*, forever — the email-only tally becomes irrelevant to them, and unlimited distributed brute-forcing against one target email flows freely again. The failure mode is that the grace has no total budget — it's per-IP-unlimited-count-of-IPs, not bounded.

### §2.4 — The fix: bound the grace pool's *total size*, not just its per-IP eligibility

The design in this doc's opening (§2) is the combination that avoids both failure modes: the "IP not yet seen" eligibility check from §2.3 is kept, but it can only ever be exercised against a **fixed total budget** (`reserved` slots, drawn from the *same* `limit` total, not additional to it) — once `reserved` distinct new IPs have used it in a given window (whether that's the real victim's IP or `reserved` attacker decoy IPs), the pool is spent for everyone until the window rolls over. This is what stops §2.3's unlimited-bypass failure: an attacker with a botnet still hits the same `limit` ceiling in total, just distributed slightly differently (main pool + at most `reserved` grace uses). And it avoids §2.2's regression because the *main pool* — where single-IP brute-force volume actually lands — is never capped per-IP; only the last `reserved` slots (small, default 1) carry the new restriction.

### §2.5 — CAPTCHA / proof-of-work: not adopted for this objective

Per the task framing: this service has no UI of its own (a reusable backend template cloned into other projects), so a CAPTCHA-shaped mitigation here could only be an optional verification-token field on the 6 request bodies plus a pluggable verifier hook (analogous to `EmailSender`'s provider abstraction, `app/core/config.py` `EMAIL_PROVIDER`) — a new architectural surface (request schema changes across 6 endpoints in `openapi.yaml`, a new verifier interface, a "what happens when no verifier is configured" fail-open/fail-closed decision) that is materially bigger than a keying-adjacent fix. It's already tracked as a backlog item independent of this objective (audit-report.md finding #2's original recommendation, reaffirmed in OBJ-013 §2's alternatives table and OBJ-013 Gate 3 §3d's mitigation list #1). Not duplicated here; the reserved-slot mechanism above is the proportionate, zero-new-surface fix for this objective specifically.

### §2.6 — Escalating delay: not adopted as the primary mechanism

Considered (per the task's suggestion list): instead of a hard 429 once the email tally is exhausted, respond with a progressively longer computed delay. Rejected as the *primary* fix because it doesn't address the actual defect in #20 — the shared budget itself. An escalating delay changes the attacker's cost curve (each additional request costs more wall-clock time to send) but does nothing to guarantee the victim's own, different IP gets through at all; the victim would still be waiting behind the same shared, attacker-saturated bucket, just with the attacker paying a slower drip instead of a flat rate. It doesn't reserve capacity for anyone. Could be layered on top of the reserved-pool mechanism later (e.g. escalating `Retry-After` for repeat-same-IP-same-email hits specifically) as a further hardening, but that's an orthogonal enhancement, not a substitute — not designed further here, noted as a backlog candidate in §6.

### §2.7 — Cheap add-on adopted alongside the main fix: distinct-IP observability

Audit report §3d's mitigation candidate #4 ("log the many-hits-one-email/few-distinct-ips pattern") is cheap and complements the main fix rather than substituting for it. Adopted as a free addition: when `_raise_rate_limited` is called with `dimension="email"`, also log `distinct_ip_count_for_email` (a `COUNT(DISTINCT ip)` over the same window/email — one more cheap query, or reuse the reserved-pool EXISTS check's data if `developer` finds a way to fold it in cheaply) so monitoring can distinguish "one IP hammering one email" (likely #20-shaped attack) from "many IPs hammering one email" (likely a genuine distributed brute-force attempt, already blocked by the main pool, but worth knowing about) after the fact. Log-only; does not change enforcement.

## §3 — Exact query/logic spec for `developer`

All changes confined to `app/core/rate_limit.py` (email-only branch) and one new setting in `app/core/config.py`. Gate 1 design only — not applied by this doc.

```python
async def enforce_rate_limit(
    db: AsyncSession,
    *,
    scope: str,
    ip: str,
    email: str,
    limit: int,
    ip_limit: int | None = None,
    reserved_slots: int | None = None,   # NEW, optional -- defaults to settings.RATE_LIMIT_EMAIL_RESERVED_SLOTS
    window_seconds: int = DEFAULT_WINDOW_SECONDS,
) -> None:
    resolved_ip_limit = ip_limit if ip_limit is not None else limit * settings.RATE_LIMIT_IP_MULTIPLIER
    resolved_reserved = reserved_slots if reserved_slots is not None else settings.RATE_LIMIT_EMAIL_RESERVED_SLOTS
    # Clamp defensively: reserved must never consume the entire pool, and
    # must never be negative regardless of what a caller passes explicitly
    # (the config-level field_validator in section 7 already prevents a bad
    # *setting* value, but a future explicit per-call override is a second
    # input path worth clamping here too, same defense-in-depth posture as
    # existing `ip_limit`/`limit` handling).
    resolved_reserved = max(0, min(resolved_reserved, limit - 1)) if limit > 0 else 0
    main_pool_limit = limit - resolved_reserved

    now = datetime.now(timezone.utc)
    window_start = now - timedelta(seconds=window_seconds)

    # --- IP-only check: UNCHANGED from OBJ-013, runs first ---
    ip_hits = await db.execute(
        select(func.count()).select_from(RateLimitHit).where(
            RateLimitHit.scope == scope,
            RateLimitHit.ip == ip,
            RateLimitHit.created_at > window_start,
        )
    )
    if ip_hits.scalar_one() >= resolved_ip_limit:
        await _raise_rate_limited(scope=scope, ip=ip, email=email, window_seconds=window_seconds, dimension="ip")

    # --- Email-only check: UNCHANGED tally, NEW banding ---
    email_hits = await db.execute(
        select(func.count()).select_from(RateLimitHit).where(
            RateLimitHit.scope == scope,
            RateLimitHit.email == email,
            RateLimitHit.created_at > window_start,
        )
    )
    email_hit_count = email_hits.scalar_one()

    if email_hit_count >= limit:
        # Main pool AND reserved pool both exhausted -- hard block,
        # regardless of which IP is asking. Identical to pre-OBJ-014
        # behavior at this threshold.
        await _raise_rate_limited(scope=scope, ip=ip, email=email, window_seconds=window_seconds, dimension="email")

    if email_hit_count >= main_pool_limit and resolved_reserved > 0:
        # In the reserved band: only an IP that has NOT yet been recorded
        # against this (scope, email) in the current window may still pass.
        # A repeat IP is blocked here even though email_hit_count < limit --
        # this is the mechanism that closes finding #20 (obj-014-design-notes
        # section 2): a single attacking IP can drive the tally into this
        # band and then gets refused the remaining slots, which stay
        # reserved for a genuinely different IP (the real victim's own).
        ip_already_seen_for_email = await db.execute(
            select(
                exists().where(
                    RateLimitHit.scope == scope,
                    RateLimitHit.email == email,
                    RateLimitHit.ip == ip,
                    RateLimitHit.created_at > window_start,
                )
            )
        )
        if ip_already_seen_for_email.scalar():
            await _raise_rate_limited(scope=scope, ip=ip, email=email, window_seconds=window_seconds, dimension="email")
        # else: falls through -- this IP is genuinely new for this email
        # this window, consumes one reserved slot, request proceeds.

    db.add(RateLimitHit(scope=scope, ip=ip, email=email, created_at=now))
    await db.commit()
```

Notes for `developer`:

- `from sqlalchemy import exists` needed alongside the existing `func, select` import.
- `_raise_rate_limited`'s signature is unchanged; both new 429 sites reuse it exactly as the existing email-dimension call does. Per §2.7, add the cheap `distinct_ip_count_for_email` field to the audit-log call inside `_raise_rate_limited` when `dimension == "email"` — one extra `COUNT(DISTINCT ip)` query, or fold into the existing `email_hits`/EXISTS queries if a single combined query is cheaper; either is fine, this is observability, not enforcement, so exact query shape is `developer`'s call.
- `reserved_slots` is optional and follows the exact same "centralize by default, allow per-call override" convention `ip_limit` established in OBJ-013 — **zero call-site diffs required** at any of the 6 endpoints; all get the mitigation automatically via the new setting's default.
- New setting, `app/core/config.py`, same section as `RATE_LIMIT_IP_MULTIPLIER`:
  ```python
  # OBJ-014 (obj-014-design-notes.md section 2/3): size of the reserved
  # "fresh IP only" slot pool carved out of the tail end of each scope's
  # existing email-keyed `limit` -- NOT an additional budget on top of
  # `limit`, a restriction on who may spend the last `reserved` units of the
  # existing one. Closes audit finding #20 (a single attacking IP could
  # otherwise exhaust a victim's whole email-keyed budget alone). Default 1
  # is deliberately small -- see design notes section 6 for why this exact
  # value needs user sign-off before changing, same posture as
  # RATE_LIMIT_IP_MULTIPLIER.
  RATE_LIMIT_EMAIL_RESERVED_SLOTS: int = 1
  ```
- Ordering: the IP-only check still runs before the email-only check (unchanged from OBJ-013) — no functional dependency between them, kept for continuity with the existing "cheaper-to-reason-about dimension first" comment.
- The extra `EXISTS` query only runs when `email_hit_count` is in the reserved band (i.e., not on every request) — same "narrow-band-only extra query" shape as the pre-existing, already-accepted timing-profile note in `docs/security/audit-report.md` §3c (OBJ-013 Gate 3); not treated as a new blocking concern here for the same reasons stated there (doesn't reveal anything to an attacker they can't already compute from their own request history).

## §4 — Call-site impact and DB follow-up

**Call sites:** zero diffs, same centralization argument as OBJ-013 (`docs/api/obj-013-design-notes.md` §4). All 6 `enforce_rate_limit(...)` calls in `app/api/v1/endpoints/auth.py` (lines 266, 406, 489, 523, 576, 672) keep their existing signature; the mitigation applies automatically via the new setting's default.

**Index follow-up for `database-architect`** (not applied here): OBJ-013 already flagged a new index, `ix_rate_limit_hits_scope_email_created_at (scope, email, created_at)`, to serve the plain email-only `COUNT`. This objective's new `EXISTS` query filters additionally on `ip` — recommend widening that still-unapplied recommendation to `ix_rate_limit_hits_scope_email_ip_created_at (scope, email, ip, created_at)` instead, which serves **both** the plain email `COUNT` (as a prefix scan ignoring `ip`) and the new per-IP `EXISTS` check (as a full equality-prefix lookup) with a single index, rather than adding a second, narrower one on top of OBJ-013's still-pending recommendation. If `database-architect` has already applied OBJ-013's narrower version by the time this lands, widening it in a follow-up migration is preferable to stacking a third index on the same table.

## §5 — OpenAPI contract impact: none

Same reasoning as `docs/api/obj-013-design-notes.md` §5, re-confirmed for this design:

- **Status code:** still `429` whichever band/dimension triggers it.
- **Body:** still the generic `{"detail": "Too many requests. Please try again later."}` — no differentiation between "main pool exhausted" and "reserved pool refused, IP already seen." Differentiating would leak information about internal bucket state to the caller, a new oracle adjacent to the anti-enumeration property (OBJ-007 finding #6) and to the no-oracle guarantee OBJ-013 Gate 3 already confirmed (§2 of that Gate 3 section) — deliberately not introduced here either.
- **`Retry-After` header:** still `window_seconds`, unchanged.
- New fields (`distinct_ip_count_for_email`, and the fact that a 429 came from the reserved band specifically, if `developer` chooses to log that too) are **audit-log-only**, per `app/core/audit_log.py`'s existing `**fields` pass-through — never reach the `HTTPException`.

No `openapi.yaml` edit made for this objective.

## §6 — Residual risk, backlog, and the Gate-1 tradeoff flagged for the user

Stated plainly, per this project's `honesty_candor` posture:

- **Not a complete fix.** An attacker who controls `1 + RATE_LIMIT_EMAIL_RESERVED_SLOTS` distinct IPs (2, at the default of 1) can still fully deny every fresh IP for a given email in a given window: exhaust the main pool from one IP (or several), then also burn the `reserved` slot(s) from `reserved` additional, previously-unused-this-window IPs before the real victim's IP gets there. This raises the attacker's required infrastructure from "one fixed IP, indefinitely" to "at least two distinct IPs, reusable window over window once each has aged out of the prior window's tally" — a real, quantifiable increase in cost, not a full close. Consistent with this project's already-accepted stance on distributed attackers (`obj-013-design-notes.md` §6): a keying/banding fix narrows a gap, it does not solve a problem that fundamentally requires a harder-to-rotate third signal (proof of identity/CAPTCHA/proof-of-work).
- **Backlog candidates, not part of this objective:**
  1. CAPTCHA/proof-of-work hook on the 6 endpoints (§2.5) — the actual close for the residual risk above; deliberately out of scope here, already tracked (audit-report.md finding #2).
  2. Escalating delay/backoff for repeat-same-(ip,email) hits specifically (§2.6) — an orthogonal enhancement layerable on top of the reserved-pool mechanism, not evaluated in depth here.
  3. CIDR/subnet-bucketed IP keying (`obj-013-design-notes.md` §2) — would also raise the distinct-source cost of defeating the *reserved* band specifically (a "distinct IP" requirement becomes a "distinct subnet" requirement), compounding with this fix rather than replacing it. Not adopted here to keep this objective's diff scoped to the email-tally banding.
  4. A per-email alternate recovery channel bypassing the rate limiter under active attack (audit-report.md §3d mitigation #3) — bigger product change, out of scope.
- **Gate-1 tradeoff flagged for user visibility:** `RATE_LIMIT_EMAIL_RESERVED_SLOTS` default of `1`. Reasoning parallel to `RATE_LIMIT_IP_MULTIPLIER` in OBJ-013 — this is a genuine judgment call with no derived-from-first-principles correct value:
  - **Smaller (or 0, which disables the mitigation entirely — `main_pool_limit` becomes `limit`, identical to pre-OBJ-014 behavior):** maximizes the main pool's brute-force-facing headroom (no reduction at all from today's `limit`), at the cost of a lower bar for a single-IP attacker to fully deny the victim (0 reserved = no mitigation; #20 stays fully open at the original triviality).
  - **Larger:** guarantees the victim more fresh-IP attempts per window and forces the attacker to control more distinct IPs to fully deny them, at the cost of shrinking the main pool (`limit - reserved`) that absorbs single-IP brute-force volume — e.g. at `reserved=3` for a `limit=5` scope (`/register`, `/forgot-password`, `/resend-verification-email`), the main pool drops to 2, a much more aggressive reduction in brute-force headroom than the default's drop to 4.
  - **`1` is recommended** as the smallest value that provides *any* guarantee (at least one fresh-IP request always gets through) while leaving brute-force-facing headroom nearly untouched (`limit - 1` instead of `limit`, a single-unit reduction regardless of scope). The user may want a larger value for the higher-`limit` scopes (`verify_otp`/`verify_email`/`reset_password`, `limit=10`) where a 1-unit reduction is proportionally smaller and more headroom is available to spend on the reserved pool without meaningfully weakening brute-force protection — flagging explicitly rather than silently deciding, per this project's Gate 1 convention.

## §7 — Finding #21: `RATE_LIMIT_IP_MULTIPLIER` validator spec

`app/core/config.py` currently has 4 `field_validator`s (`ENVIRONMENT`, `SECRET_KEY`, `POSTGRES_SSL_MODE`, `ALGORITHM`) plus one cross-field `model_validator` (`EMAIL_PROVIDER`/`ENVIRONMENT`) — `RATE_LIMIT_IP_MULTIPLIER` has none, confirmed via the field list at `app/core/config.py:111-119`. Add, next to the existing single-field validators, following the exact same fail-closed-at-startup convention (raise `ValueError` with a message that names the finding and the concrete failure mode, same style as `validate_algorithm`/`validate_postgres_ssl_mode`):

```python
# Security audit finding #21 (docs/security/audit-report.md, "Gate 3 --
# Verificacion OBJ-013" section 3b): a 0 or negative multiplier makes
# `resolved_ip_limit` (rate_limit.py) 0 or negative, and a COUNT() result is
# never negative -- `ip_hits.scalar_one() >= resolved_ip_limit` becomes
# unconditionally true, self-denying the FIRST request from ANY IP on ALL 6
# rate-limited endpoints. Not attacker-reachable (this is a deploy-time
# setting, not request input) but a cheap fail-closed guardrail, same
# posture as every other validated field in this class.
@field_validator("RATE_LIMIT_IP_MULTIPLIER")
@classmethod
def validate_rate_limit_ip_multiplier(cls, value: int) -> int:
    if value < 1:
        raise ValueError(
            f"RATE_LIMIT_IP_MULTIPLIER must be >= 1, got {value!r}. A value "
            "of 0 or negative makes the IP-keyed rate limit unreachable "
            "(0) or nonsensical (negative), which self-denies every request "
            "on all 6 rate-limited endpoints -- see audit-report.md finding #21."
        )
    return value
```

**Proactive addition, same treatment for the new setting this doc introduces** (not itself a numbered audit finding — added here so it doesn't become one later): `RATE_LIMIT_EMAIL_RESERVED_SLOTS` gets an analogous validator requiring `>= 0` (0 is a legitimate, explicit opt-out — see §6 — negative is not):

```python
@field_validator("RATE_LIMIT_EMAIL_RESERVED_SLOTS")
@classmethod
def validate_rate_limit_email_reserved_slots(cls, value: int) -> int:
    if value < 0:
        raise ValueError(
            f"RATE_LIMIT_EMAIL_RESERVED_SLOTS must be >= 0, got {value!r}. "
            "0 explicitly disables the reserved-fresh-IP-slot mitigation "
            "(obj-014-design-notes.md section 2/6) and is allowed; a "
            "negative value has no defined meaning."
        )
    return value
```

Both are single-field, no cross-field dependency needed (the `reserved < limit` clamp is handled defensively at call time in `rate_limit.py`, §3, since `limit` is a call-site constant, not a `Settings` field — there is nothing to cross-validate against in `config.py` itself).

## §8 — Architectural boundaries

Unchanged by this objective — restated per this role's convention:

- `app/core/rate_limit.py` remains the single owner of rate-limit enforcement logic and the `RateLimitHit` read/write path. This objective adds banding logic inside the existing email-only check; no endpoint handler gains rate-limit-related logic of its own.
- `app/models/rate_limit.py`'s `RateLimitHit` table shape is unchanged (no new columns) — only its indexing needs, flagged for `database-architect` (§4).
- `app/core/audit_log.py` remains the single owner of the structured auth-event log shape; this design adds fields to the existing `auth.rate_limit.exceeded` event type (per §2.7/§3), not a new event type.
- `app/core/config.py` remains the single owner of runtime-tunable settings; this design adds one new setting (`RATE_LIMIT_EMAIL_RESERVED_SLOTS`) following the existing `RATE_LIMIT_IP_MULTIPLIER`/`TRUSTED_PROXY_COUNT` convention, plus the two validators in §7.
- `docs/api/openapi.yaml` is unchanged (§5) — no new architectural surface.

## §9 — Implementation note (developer, 2026-08-25/26)

Implemented exactly per §3/§7 pseudocode, on branch `obj-014-developer-impl`
(based on `origin/obj-010-013-residual-hardening`). Files: `app/core/rate_limit.py`
(reserved-band logic inside `enforce_rate_limit`, `distinct_ip_count_for_email`
observability addition to `_raise_rate_limited` per §2.7), `app/core/config.py`
(`RATE_LIMIT_EMAIL_RESERVED_SLOTS: int = 1` + both field_validators from §7).
Zero call-site diffs at any of the 6 endpoints, as designed.

New tests (TDD, red confirmed before implementation via a `git stash` of the
two source files, then green after): `tests/api/test_rate_limit_reserved_slots.py`
(10 tests — victim-fresh-IP protection, total-ceiling-unchanged/bounded-ness,
the reserved=0 opt-out, the defensive clamp via a direct `enforce_rate_limit`
call, and an explicit single-IP-brute-force regression guard) and
`tests/unit/test_rate_limit_settings_validators.py` (15 tests — both new
field_validators' invalid/valid boundaries via the same subprocess technique
`test_secret_key_startup.py` established, plus the `RATE_LIMIT_EMAIL_RESERVED_SLOTS`
default-value check). Confirmed the two explicitly-rejected approaches (§2.2's
flat per-IP cap, §2.3's unconditional first-time-IP bypass) do NOT pass: a flat
cap below the main pool would fail `TestVictimFreshIpProtectedAfterAttackerExhaustsMainPool`'s
first assertion (4 uncapped hits from one IP); an unconditional bypass would fail
`TestTotalCeilingPerEmailUnchanged` (a third fresh IP is still blocked once the
total ceiling is reached).

**Significant, wider-than-anticipated blast radius found and handled:** applying
the reserved-band mechanism via the centralized default (§3/§4's "zero call-site
diffs" design) means ANY single, non-rotating (ip, email) pair — not just an
attacker's — can now only ever claim `limit - RATE_LIMIT_EMAIL_RESERVED_SLOTS`
requests, never the full `limit`, because by the time its own tally reaches the
reserved band its own IP has necessarily already been recorded and is therefore
ineligible for it. This is a correct, direct consequence of the §2/§6 mechanism
as specified (not an implementation bug) — the total ceiling per email is still
bounded at `limit` and never exceeded, and this file's own tests confirm that
bound holds — but it silently broke 8 pre-existing regression tests across 4
files that all happen to share the suite's "one real IP per test" shape
(`tests/api/test_rate_limit.py`, `test_rate_limit_ip_spoofing.py`,
`test_rate_limit_keying.py` ×2, `test_register_rate_limit.py` ×3,
`test_resend_verification_email.py`), spanning OBJ-001/OBJ-004/OBJ-009/OBJ-013 —
a materially larger footprint than the dispatch's explicit "OBJ-013's existing
rate-limit-keying tests" framing anticipated. Each of those 8 was updated (not
weakened) to assert the new, correct threshold (`limit - 1` at the default),
with an inline comment tracing to this section — same "deliberately turn a
previously-green test red for a documented reason" precedent this project
already established in OBJ-003 (see `tests/README.md`). Flagged here explicitly
per this project's `honesty_candor` posture, for `qa-engineer`/`security-specialist`
Gate 3 review to confirm this trade-off (every non-rotating actor loses exactly
one slot of headroom, forever, unless a second IP appears) is acceptable at the
current default, or whether a future objective should reconsider it.

Full suite: **325 passed, 0 failed** (`tests/unit` + `tests/api` combined,
disposable Postgres 16 on port 5433, per-worktree `.venv`) — zero regressions
once the 8 tests above were updated to the new, documented threshold.
