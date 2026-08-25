# OBJ-013 — Rate Limiter Keying Hardening — Design Notes

> **Summary (read this, skip the rest unless you need detail):**
> - **Status:** Gate 1 (design only) — no red tests written yet, no implementation. `rate_limit.py` itself is untouched by this doc; `qa-engineer` (red phase) and `developer` (green phase) pick up next.
> - **Finding closed:** audit-report.md **#17** (LOW, filed Gate 3 OBJ-009) — `enforce_rate_limit`'s `(scope, ip, email)` key is an AND, not independent counters, so rotating either `ip` or `email` alone resets the attacker to a fresh zero-count bucket every request.
> - **Fix shape (Option (a) chosen):** replace the single combined `(scope, ip, email)` COUNT with **two independent COUNT queries** per call — one keyed on `(scope, ip)`, one keyed on `(scope, email)` — both against the trailing window; either one reaching its own limit is a 429. An attacker now needs to defeat BOTH dimensions simultaneously (unique IP *and* unique email on every single request) to evade throttling, not just one.
> - **Signature change:** `limit: int` is kept (no rename) and now means the **email-keyed** threshold, unchanged in value from today, at all 6 call sites. A new optional `ip_limit: int | None = None` defaults to `limit * settings.RATE_LIMIT_IP_MULTIPLIER` (new setting, default `5`) when omitted. **Zero call-site diffs required** — all 6 existing `enforce_rate_limit(...)` calls keep compiling and keep their current behavior for the email dimension; the IP-only check is added automatically and centrally.
> - **Gate 1 decision flagged for user visibility (§2):** the IP-keyed limit is deliberately **more generous** than the email-keyed limit (5× by default) to avoid globally throttling legitimate users behind shared/NAT'd/corporate-proxy IPs. The exact multiplier is a product judgment call with no "correct" answer from first principles — recommend `5`, but this is the one number in this doc the user may want to weigh in on before `developer` implements it.
> - **Residual risk, stated plainly (§6):** this fix does **not** close the underlying vulnerability class completely — a genuinely distributed attacker (unique IP *and* unique email per request, e.g. a botnet with disposable-email generation) still evades both independent checks, because neither dimension repeats for them either. That was never in scope for a keying fix; it needs a third signal (CAPTCHA, ASN/subnet aggregation, proof-of-work) tracked separately.
> - **OpenAPI impact: none.** The `429` response body/`Retry-After` header shape is unchanged — see §5 for why; no `openapi.yaml` edit made.
> - **DB follow-up flagged for `database-architect` (§4):** the existing `ix_rate_limit_hits_scope_ip_email_created_at` index doesn't efficiently serve the new email-only query (it's not a leading-column prefix). Recommend adding `ix_rate_limit_hits_scope_email_created_at (scope, email, created_at)`. Not applied here — index changes are `database-architect`'s artifact, not `solution-architect`'s.

## Jump-to index

- [§1 — The finding, restated with evidence](#1--the-finding-restated-with-evidence) — what's actually exploitable today, confirmed against the current query.
- [§2 — Design decision: two independent checks, and the threshold tradeoff](#2--design-decision-two-independent-checks-and-the-threshold-tradeoff) — Option (a) vs. alternatives considered, and the multiplier decision flagged for the user.
- [§3 — Exact signature / query-shape change](#3--exact-signature--query-shape-change) — the centralized change, pseudocode-level detail for `developer`.
- [§4 — Call-site impact across all 6 endpoints](#4--call-site-impact-across-all-6-endpoints) — confirms zero per-endpoint changes needed, plus the NAT/shared-IP semantics check and the index follow-up.
- [§5 — OpenAPI contract impact: none](#5--openapi-contract-impact-none) — why the `429` shape is unchanged and no spec edit was made.
- [§6 — Residual risk and backlog](#6--residual-risk-and-backlog) — what this fix does NOT solve, stated explicitly.
- [§7 — Architectural boundaries](#7--architectural-boundaries) — unchanged by this objective; restated for completeness.

---

## §1 — The finding, restated with evidence

`app/core/rate_limit.py:45-54` (current, unchanged as of this doc):

```python
result = await db.execute(
    select(func.count())
    .select_from(RateLimitHit)
    .where(
        RateLimitHit.scope == scope,
        RateLimitHit.ip == ip,
        RateLimitHit.email == email,
        RateLimitHit.created_at > window_start,
    )
)
```

All four `.where()` conditions are ANDed. The counter for a given `scope` only increments when the **exact same** `(ip, email)` pair repeats within the window. Confirmed exploitable at each of the two endpoints where one field needs zero validity:

- `/register`, `/forgot-password`, `/resend-verification-email`: `email` is caller-supplied free text, never checked against an existing account before this call runs (that's the whole point of anti-enumeration, OBJ-007 finding #6) — an attacker can send a unique never-used email string on every request and never repeat a key.
- Any endpoint, from a residential/mobile connection or simple proxy rotation: `ip` is equally trivial to rotate per request.

Rotating **either one** alone is sufficient — the attacker doesn't need both. This was filed as finding #17 (LOW, non-blocking) during OBJ-009's Gate 3 security review (`docs/security/audit-report.md`, "Gate 3 — Verificación OBJ-009" section, filed against `rate_limit.py:42-52`), explicitly noted there as pre-existing since OBJ-001 across the other five endpoints, not introduced by OBJ-009 — OBJ-009 just made it newly reachable at a 6th endpoint (`/register`) and prompted flagging it as a dedicated objective rather than a 6th point-fix.

## §2 — Design decision: two independent checks, and the threshold tradeoff

**Chosen: Option (a) — two independent limits, both must pass.** Run an IP-only sliding-window count and an email-only sliding-window count as two separate queries; reject (429) if *either* has reached its own limit. This directly closes the AND-defeats-with-one-rotation gap: an attacker rotating only `email` still accumulates against the same `ip` count (and vice versa), so a real single-source or single-identity flood is still capped by whichever dimension the attacker isn't bothering to rotate.

**Alternatives considered and rejected:**

| Alternative | Why rejected |
|---|---|
| Keep AND, but hash `(ip, email)` into one opaque key — cosmetic only | Doesn't change the semantics at all; still trivially defeated by rotating either input to the hash. Rejected as a non-fix. |
| Single limit keyed on `ip` only (drop `email` from the key) | Stops nothing that rotating IP already defeats today, AND actively regresses: a single attacker IP could exhaust the whole limit against many *different* victim emails in `/forgot-password`/`/reset-password` in one window — turns a per-target throttle into a shared budget across unrelated users. Rejected. |
| Single limit keyed on `email` only (drop `ip` from the key) | Symmetric problem: an attacker rotating email per request (trivial, as established in §1) faces no throttle at all; legitimate concurrent users of the *same* email (e.g. a shared support/ops account) would be over-throttled globally. Rejected. |
| CIDR/subnet-bucketed IP keying (e.g. `/24`) instead of exact IP | A real orthogonal hardening (catches an attacker rotating within one rented /24) but adds complexity (subnet math, IPv6 prefix-length choice) not needed to close #17 specifically, which is about the AND-vs-independent structure, not IP granularity. Deferred to backlog (§6) — can be layered onto the design here later without another signature change. |
| CAPTCHA / proof-of-work on the affected endpoints | Bigger product/UX change, already tracked separately in the audit report's original finding #2 fix recommendations (`docs/security/audit-report.md` §2, "CAPTCHA en forgot-password"). Out of scope for a rate-limiter keying fix. |
| A third "global, scope-only" circuit-breaker ceiling (no ip/email key at all) as defense-in-depth | Considered as a cheap addition (catches a fully-distributed attacker who rotates both dimensions AND still exceeds some absolute scope-wide ceiling). Not adopted here to keep this objective's diff minimal and single-purpose; noted as a candidate backlog item in §6 rather than folded in silently. |

**Threshold decision — flagged for user visibility:** should the IP-only limit equal the email-only limit, or be more generous? **Recommendation: more generous, via a configurable multiplier — default 5×.**

Reasoning:
- The email-only limit protects a specific target identity. A legitimate user essentially never calls `/forgot-password`, `/verify-otp`, `/resend-verification-email`, `/reset-password`, or `/register` (for the *same* email) more than a handful of times per minute — today's values (5 or 10/min depending on scope, see §4 table) were already sized for this and don't need to change.
- The IP-only limit protects against volumetric abuse from one source, but "one source" in production is not always "one person": NAT'd offices, mobile carrier CGNAT, corporate VPN egress, and campus networks routinely put many legitimate, unrelated users behind one observed IP. Setting the IP limit equal to the (tight) email limit risks a false-positive denial-of-service against all of them the moment a handful of legitimate users behind the same IP happen to use the endpoint within the same 60s window — e.g. several employees on a corporate VPN registering accounts during an onboarding session, or several members of a household resetting passwords after a shared-password-manager breach notice.
- A flat multiplier (`ip_limit = limit * RATE_LIMIT_IP_MULTIPLIER`, new `settings.RATE_LIMIT_IP_MULTIPLIER: int = 5`) keeps the two dimensions coupled to the same per-scope source of truth (no risk of the two drifting out of sync as scope limits are tuned later) while giving IP headroom for shared-IP legitimate traffic. At the default `5`, `/register` and `/forgot-password` (email limit 5) get an IP limit of 25/min; `/verify-otp`/`/verify-email`/`/reset-password` (email limit 10) get 50/min.
- **This is a genuine judgment call, not a derived number** — there's no traffic data from this template's actual deployments to size it empirically yet (it's a reusable starter service, not a single running product with observed NAT-density). `5` is a reasonable starting default (generous enough that a small/medium shared-IP legitimate burst passes, tight enough that it still means something as a backstop), but the user may have a specific deployment shape in mind (e.g. "we know most traffic is direct-to-residential, tighten it" or "we're behind a campus network, loosen it further") that should override this default before `developer` implements it. **Flagging explicitly rather than silently deciding**, per this objective's Gate 1 instructions.

## §3 — Exact signature / query-shape change

All changes are confined to `app/core/rate_limit.py`; not applied by this doc (Gate 1 design only).

```python
async def enforce_rate_limit(
    db: AsyncSession,
    *,
    scope: str,
    ip: str,
    email: str,
    limit: int,                       # UNCHANGED name/meaning per call site: the email-keyed threshold
    ip_limit: int | None = None,      # NEW, optional: defaults to limit * settings.RATE_LIMIT_IP_MULTIPLIER
    window_seconds: int = DEFAULT_WINDOW_SECONDS,
) -> None:
    """Raise 429 if EITHER the IP-only or the email-only sliding-window
    count for `scope` within `window_seconds` has reached its own
    independent limit; otherwise record the current request (one row,
    same shape as today -- both `ip` and `email` still stored for
    forensics) and let the caller proceed.

    Two independent counts, not one combined (scope, ip, email) count --
    closes audit finding #17 (obj-013-design-notes.md): an attacker who
    rotates only ONE of (ip, email) must still contend with the OTHER
    dimension's own limit, instead of resetting to a fresh zero-count
    bucket on every request.
    """
    resolved_ip_limit = ip_limit if ip_limit is not None else limit * settings.RATE_LIMIT_IP_MULTIPLIER

    now = datetime.now(timezone.utc)
    window_start = now - timedelta(seconds=window_seconds)

    ip_hits = await db.execute(
        select(func.count()).select_from(RateLimitHit).where(
            RateLimitHit.scope == scope,
            RateLimitHit.ip == ip,
            RateLimitHit.created_at > window_start,
        )
    )
    if ip_hits.scalar_one() >= resolved_ip_limit:
        await _raise_rate_limited(scope=scope, ip=ip, email=email, window_seconds=window_seconds, dimension="ip")

    email_hits = await db.execute(
        select(func.count()).select_from(RateLimitHit).where(
            RateLimitHit.scope == scope,
            RateLimitHit.email == email,
            RateLimitHit.created_at > window_start,
        )
    )
    if email_hits.scalar_one() >= limit:
        await _raise_rate_limited(scope=scope, ip=ip, email=email, window_seconds=window_seconds, dimension="email")

    db.add(RateLimitHit(scope=scope, ip=ip, email=email, created_at=now))
    await db.commit()
```

Notes for `developer`:

- `_raise_rate_limited(...)` is a small private helper factoring out the existing `audit_log.log_auth_event(...)` + `raise HTTPException(429, ...)` block (today's lines 61-68), with one addition: a `dimension="ip"|"email"` field passed into the audit log call (safe — not PII, `audit_log.log_auth_event` already accepts arbitrary `**fields`, see `app/core/audit_log.py:27`). This gives security monitoring a way to distinguish "one source hammering us" from "one target being hammered from many sources" in the logs, which today's single combined check couldn't distinguish either. **The `dimension` value must NOT appear in the HTTP response** (see §5 — keeping it audit-log-only is what keeps the wire contract unchanged).
- `RateLimitHit` row shape is **unchanged** — still one row per accepted request, still recording both the real `ip` and `email`. Only the read-side query logic changes (two narrower COUNTs instead of one four-way-ANDed COUNT); the write-side INSERT is identical to today.
- New setting, `app/core/config.py` (same section as `TRUSTED_PROXY_COUNT`):
  ```python
  # OBJ-013 (obj-013-design-notes.md section 2): multiplier applied to a
  # scope's email-keyed `limit` to derive the default IP-keyed threshold
  # when a call site doesn't override it via `ip_limit`. Deliberately more
  # generous than the email-keyed limit -- shared/NAT'd/corporate-proxy
  # IPs are normal legitimate traffic; see design notes section 2 for why
  # this exact value needs user sign-off before changing.
  RATE_LIMIT_IP_MULTIPLIER: int = 5
  ```
- Order matters for audit-log clarity but not for correctness: checking `ip` before `email` (as above) is an arbitrary but reasonable choice (fail on the cheaper-to-reason-about dimension first); no functional difference either order.

## §4 — Call-site impact across all 6 endpoints

Confirmed via `grep -rn "enforce_rate_limit(" app/` (base: `main` @ `558fcf9`, plus the pending `obj-009-register-rate-limit` branch for the 6th site not yet merged):

| Endpoint | `scope` | Current `limit` (email-keyed, unchanged) | New default `ip_limit` (5×) | Call-site diff needed |
|---|---|---|---|---|
| `POST /auth/register` | `"register"` | 5/min | 25/min | **None** (pending merge via OBJ-009; this design applies automatically once merged) |
| `POST /auth/forgot-password` | `"forgot_password"` | 5/min | 25/min | None |
| `POST /auth/verify-otp` | `"verify_otp"` | 10/min | 50/min | None |
| `POST /auth/verify-email` | `"verify_email"` | 10/min | 50/min | None |
| `POST /auth/resend-verification-email` | `"resend_verification_email"` | 5/min | 25/min | None |
| `POST /auth/reset-password` | `"reset_password"` | 10/min | 50/min | None |

All 6 keep calling `enforce_rate_limit(db, scope=..., ip=ip, email=payload.email, limit=X_RATE_LIMIT_PER_MINUTE)` exactly as today — this is the centralization the objective asked for (CLAUDE.md task: "so all 6 call sites benefit automatically, no per-endpoint changes needed"). Confirmed no call site currently passes anything resembling an `ip_limit` keyword that would collide with the new optional parameter.

**Semantics check requested in the task (shared-NAT concern):** covered by the §2 multiplier decision — the IP-only check is deliberately looser than the email-only check specifically so that this app's expected deployment shape (a reusable auth-service template with no fixed assumption about client topology — could be consumer-facing direct traffic, could be behind an enterprise VPN/NAT) doesn't get legitimate concurrent multi-user traffic globally throttled by IP alone. If a specific downstream deployment is known to be, e.g., 100% enterprise-NAT traffic, `RATE_LIMIT_IP_MULTIPLIER` (or a per-call `ip_limit` override) is the intended tuning knob — no code change needed, just config.

**Anti-enumeration invariant (OBJ-007 finding #6) — re-checked, still holds:** both new queries use only request-supplied `ip`/`email` and `scope`/`created_at` — no information about whether an account exists is read or branches on. The 429 response body/headers stay identical regardless of which dimension (`ip` or `email`) tripped (§5) — an attacker cannot use response shape to learn whether they were throttled for the IP or the email dimension, let alone whether the target email exists. `/register`'s single-shared-call-site-before-branch-decision invariant (`obj-009-design-notes.md` §2) is unaffected — this design changes what happens *inside* `enforce_rate_limit`, not where or how many times it's called from `register()`.

**Index follow-up flagged for `database-architect` (not applied here):** the existing index `ix_rate_limit_hits_scope_ip_email_created_at (scope, ip, email, created_at)` (`app/models/rate_limit.py:24-32`) serves the new IP-only query reasonably well (`scope`, `ip` are still a usable equality-prefix bound before the `created_at` range filter). It does **not** serve the new email-only query efficiently — `email` is the 3rd column, behind the unconstrained `ip` column, so Postgres can only bound the scan on `scope` alone for that query, scanning across all IPs within the scope before filtering on `email`/`created_at`. Recommend a second index, `ix_rate_limit_hits_scope_email_created_at (scope, email, created_at)`, added via a versioned migration in `database-architect`'s domain — cheap to add (append-only table, no existing large backfill expected in this template's typical deployment size) and not required for correctness, only for query efficiency as traffic grows.

## §5 — OpenAPI contract impact: none

The `RateLimited` response component (`docs/api/openapi.yaml:747-763`) is unchanged by this design:

- **Status code:** still `429` on any throttle, regardless of which dimension (`ip` or `email`) triggered it.
- **Body:** still the generic `{"detail": "Too many requests. Please try again later."}` — deliberately, not differentiated by dimension (see §3's note that `dimension` is audit-log-only). Differentiating the message would create a new oracle (an attacker could learn whether they're being throttled by IP or by email, which for `/register`/`/forgot-password` leaks information adjacent to the anti-enumeration property OBJ-007 closed) and would itself be a wire contract change requiring a spec update — deliberately avoided.
- **`Retry-After` header:** still `window_seconds` (the existing `DEFAULT_WINDOW_SECONDS = 60`, unchanged) — both the IP check and the email check use the *same* window, so there's no scenario where the two dimensions imply different `Retry-After` values needing reconciliation.

No `openapi.yaml` edit made for this objective. `info.version` stays at whatever it is when this branch is rebased onto `main` (currently `"0.7.0-obj-007"` there, pending the still-unmerged `obj-009` bump) — this objective doesn't touch the HTTP contract at all, so it doesn't need its own version bump.

## §6 — Residual risk and backlog

Stated plainly, per this project's `honesty_candor` posture — this fix narrows the gap finding #17 identified, it does not close the underlying vulnerability class entirely:

- **Fully distributed attacker still evades both checks.** An attacker with a large pool of unique source IPs (botnet, residential proxy network) AND a unique email string per request (trivial to generate, as established in §1) will never repeat either key, so neither independent counter ever reaches its limit. This was true before this fix and remains true after — a keying fix cannot solve a problem that requires a third, harder-to-rotate signal. Not a regression introduced by this design; explicitly out of scope for "fix the AND-vs-independent keying structure," which is what finding #17 asked for.
- **Backlog candidates, not part of this objective:**
  1. CIDR/subnet-bucketed IP keying (§2 alternatives table) — raises the cost of the "unique IP per request" half of the evasion by requiring a unique subnet, not just a unique address.
  2. A third global, scope-only circuit-breaker ceiling (§2) — catches volumetric spikes even from a fully distributed source, at the cost of a shared budget across unrelated legitimate users in a true traffic surge (would need careful sizing to avoid becoming its own false-positive source).
  3. CAPTCHA/proof-of-work on `/register` and `/forgot-password` specifically — already tracked in the audit report's original finding #2 recommendations, not duplicated here.
  4. `rate_limit_hits` TTL/purge (audit-report.md, tracked toward OBJ-006) — orthogonal (storage hygiene, not a security gap) but touches the same table; worth doing in the same migration pass as §4's new index if OBJ-006 and this objective's implementation land close together in time.

## §7 — Architectural boundaries

Unchanged by this objective — restated for completeness, per this role's convention:

- `app/core/rate_limit.py` remains the single owner of rate-limit enforcement logic and the `RateLimitHit` read/write path. No endpoint handler in `app/api/v1/endpoints/auth.py` gains any rate-limit-related logic of its own — the centralization property this objective was explicitly raised to preserve (CLAUDE.md task description, point 3).
- `app/models/rate_limit.py` remains the single owner of the `RateLimitHit` table shape. This design does not change its columns, only (via `database-architect`'s follow-up, §4) its indexes.
- `app/core/audit_log.py` remains the single owner of the structured auth-event log line shape; this design adds one new field (`dimension`) to an existing event type (`auth.rate_limit.exceeded`), not a new event type or a new logging mechanism.
- `app/core/config.py` remains the single owner of runtime-tunable settings; this design adds one new setting (`RATE_LIMIT_IP_MULTIPLIER`) following the existing `TRUSTED_PROXY_COUNT`/`LOG_LEVEL` convention (safe default, live-read at call time, no startup-fail-closed requirement — a misconfigured multiplier affects rate-limit generosity, not security posture in the fail-open/fail-closed sense `SECRET_KEY`/`POSTGRES_SSL_MODE` are held to).
- `docs/api/openapi.yaml` is unchanged (§5) — no new architectural surface, this is an internal hardening of an existing mechanism.
