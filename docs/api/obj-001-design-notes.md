# OBJ-001 — Critical Auth Hardening: API Design Notes

**Author:** solution-architect
**Input:** `docs/security/audit-report.md` findings #1, #2, #4 (reused as Phase 1 threat-model
input per `dependency_graph.md` — not re-audited here). Companion artifact:
`docs/api/openapi.yaml`.

This document covers architectural decisions the OpenAPI spec can't express on its own: the
JWT claim schema, the split between rate limiting and OTP lockout, module ownership boundaries,
and the SECRET_KEY startup contract (finding #4, which is config/process-level, not an HTTP
route — intentionally excluded from `openapi.yaml`).

**Quick index:** explicit `type` claim on both token types, fail-closed, no legacy-format
grandfathering (§1) · rate limiting and OTP lockout kept as two separate mechanisms on purpose,
not merged (§2) · `SECRET_KEY` startup contract, no HTTP surface (§3) · new `GET /auth/me`
endpoint proposed to give finding #1 a real HTTP path to test against (§4) · thresholds
(`MAX_OTP_ATTEMPTS=5`, rate limits, cooldown) left as non-blocking open decisions (§5) · Phase 3
addendum: OTP lockout invalidates via `expires_at=now()` not delete, rate limiter uses a
row-per-request + `COUNT()` pattern (bottom). Jump to: "1. JWT claim schema", "2. Rate limiting
vs. OTP lockout", "3. Startup config contract", "4. New endpoint", "5. Open decisions", "Phase 3
implementation addendum".

---

## 1. JWT claim schema (finding #1)

**Decision:** both token types get an explicit `type` claim. The legacy `"refresh": true` claim
(`app/core/security.py:34`) is retired, not kept alongside the new claim — one source of truth,
no dual-format window to keep in sync.

```jsonc
// access token
{ "sub": "<email>", "exp": <unix ts>, "iat": <unix ts>, "type": "access" }

// refresh token
{ "sub": "<email>", "exp": <unix ts>, "iat": <unix ts>, "type": "refresh" }
```

`iat` is a minor addition beyond what the audit asked for — cheap to add now, useful later for
OBJ-002's reuse-detection/rotation logic. Not load-bearing for OBJ-001's fix; drop it if
`qa-engineer`/`developer` want to keep this tranche minimal.

**Validation points (both must check, independently — no shared "trust" shortcut):**

| Call site | Module | Expected `type` | On mismatch / missing |
|---|---|---|---|
| `get_current_user` | `app/api/deps.py` | `"access"` | 401, `detail: "Could not validate credentials"` |
| `verify_refresh_token` | `app/core/security.py` | `"refresh"` | 401, `detail: "Invalid or expired refresh token"` (changed from 400 — see spec `/auth/refresh`) |

**Fail-closed rule:** a missing `type` claim is treated identically to a wrong one — reject. Do
not special-case "no `type` claim = old-format access token" for backward compatibility. This is
a from-scratch reusable template with no production tokens in flight anywhere yet; there is no
migration population to protect, so there's no reason to weaken the check for one.

**Why one message for `/auth/me` (401) instead of a type-specific one:** telling the caller
*why* their bearer token was rejected (wrong type vs. expired vs. bad signature) doesn't help a
legitimate client recover any faster than "log in again," and it hands an attacker probing with
a stolen refresh token a free signal about what they're holding. Same generic-error philosophy
the existing code already applies to `/login` and `/forgot-password`.

**Module ownership:** `app/core/security.py` is the single place that encodes/decodes the `type`
claim. `deps.py` and the `/auth/refresh` handler call into it rather than re-deriving the check —
this is exactly the bug that shipped finding #1 (`get_current_user` reimplemented token
validation instead of reusing `verify_refresh_token`'s logic, and diverged). Any new protected
endpoint added later must depend on `deps.get_current_user`, never decode a JWT inline.

---

## 2. Rate limiting vs. OTP lockout (finding #2) — two separate mechanisms, deliberately

These solve different problems and must not be merged into one counter:

| | Rate limiting | OTP attempt lockout |
|---|---|---|
| Layer | Transport/infra (IP-based) | Domain/business rule |
| Scope | Per client IP (+ optionally IP+email) | Per `(email, purpose)` — one `Verification` row |
| Applies to | `/forgot-password`, `/verify-otp`, `/reset-password` | `/verify-otp`, `/reset-password` only |
| Trigger | Request *volume* | Failed OTP *match* attempts |
| Response | `429` + `Retry-After` | Same `400` as "invalid/expired OTP" (no new status) |
| Resets when | Sliding/fixed window elapses | A new OTP is issued via `/forgot-password` |

Collapsing these (e.g. treating "5 failed OTP checks" as a rate-limit event) would mean a
distributed attacker — many IPs, one target email — sails past a per-IP rate limiter but still
needs the lockout to stop brute force. Keeping them separate means each does the one job it's
actually good at.

**Lockout mechanics:**
- `Verification` gains an `attempts` counter (int, default 0) — schema change for
  `database-architect`, not designed here.
- Both `/verify-otp` and `/reset-password` increment the **same** counter on any failed check
  against the active row for that `(email, purpose)` — including a check that finds no matching
  code at all, as long as *some* live (unexpired) row exists for that email+purpose. This closes
  the specific gap the audit called out: `/verify-otp` was a free, unlimited oracle against the
  row that `/reset-password` also checks (audit finding #2, "oráculo gratuito"). Sharing the
  counter means guesses via either endpoint burn the same budget.
- On reaching `MAX_OTP_ATTEMPTS`, the row is invalidated server-side (delete it, or set
  `expires_at` to the past — either satisfies "invalidated," pick whichever `developer` finds
  simpler against the existing delete-on-success pattern in `/reset-password`).
- After lockout, further calls against that `(email, purpose)` get the **identical** 400 used for
  "wrong code" and "expired code." No new response shape, no new status code. Recovery path is
  the same as expiry: call `/forgot-password` again.
- A request with no live row at all for that `(email, purpose)` (never requested, or already
  expired/locked) does **not** create tracking state — only `/forgot-password` creates
  `Verification` rows, and it already skips creation for nonexistent emails. Nothing here changes
  that; it's what keeps this from becoming a row-spam vector.

**`/forgot-password` cooldown (silent, no new status):** repeat requests for an email that
already has a live OTP should not rotate the code or reset `attempts` on every call — otherwise
an attacker who just got locked out could immediately request a fresh row and reset their budget.
Enforce a short cooldown per `(email, purpose)`: within the window, `/forgot-password` still
returns the same generic 200 but does not touch the existing row. No distinguishable signal is
introduced — same response either way, per the endpoint's existing anti-enumeration design.

**Implementation note, not contract (flagging per task instructions):** OTP generation
(`auth.py:86`) currently uses `random.choices` — not cryptographically secure. Should move to
`secrets` (e.g. `"".join(secrets.choice(string.digits) for _ in range(6))` or
`f"{secrets.randbelow(1_000_000):06d}"`). This doesn't change the OpenAPI contract at all (still
a 6-digit string), so it's `developer`'s concern at implementation time, noted here only because
the task asked for it to be flagged.

**Module ownership:** rate limiting is infrastructure middleware/dependency (new module, e.g.
`app/core/rate_limit.py`), decoupled from endpoint business logic. OTP lockout state lives on
`Verification` itself (`app/models/verification.py`) — the endpoint handlers in `auth.py` read
and mutate it, same as they already do for expiry. Don't let the rate limiter reach into
`Verification`, and don't let lockout logic depend on the rate limiter's storage.

---

## 3. Startup config contract (finding #4) — not part of `openapi.yaml`

This has no HTTP surface — it's a process-startup invariant, not a route, so it stays out of the
OpenAPI spec entirely and is documented here instead.

**Requirement:** `app/core/config.Settings` must refuse to construct (raise at import/startup
time, before `app/main.py` builds the `FastAPI()` instance or the lifespan handler runs) if
`SECRET_KEY`:
- has length `< 32`, or
- matches a known-placeholder blocklist — at minimum the literal value currently shipped in
  `.env.example:9` (`your_secret_key_here`), plus common throwaway values worth blocking
  defensively: `secret`, `changeme`, `change_me`, `CHANGE_ME`, empty string, and
  `insert_secret_key_here`-style variants. Case-insensitive compare.

**Mechanism:** a Pydantic `field_validator` on `SECRET_KEY` in `Settings` (`app/core/config.py`).
Because `settings = get_settings()` already executes at module import time (`config.py:39`), this
validator failing raises during import — the app process never reaches a listening state. No
HTTP response code applies because no server starts; this is a hard crash-on-boot, which is the
correct fail-closed behavior for "the app is about to sign every JWT with a public string."

**Documentation requirement:** the fix should also update `.env.example`'s comment to
recommend generating the value with `secrets.token_urlsafe(64)`, so the blocklist and the
example file don't silently drift apart again.

**Test implication for `qa-engineer`:** this needs a process-level test (import `app.core.config`
with a monkeypatched/env-overridden weak `SECRET_KEY` and assert it raises), not an `httpx`
request-level test — there's no request to make if the process won't start.

---

## 4. New endpoint: `GET /auth/me` — flagged for confirmation

Not in the original codebase. Proposed because `deps.get_current_user` currently has zero real
callers (`test-gap-analysis.md` §2.7 already flags this), which means finding #1's fix has no
HTTP path to contract-test end-to-end — only a unit test against `deps.py` directly, exercised
without ever going through FastAPI's dependency-injection/`OAuth2PasswordBearer` header parsing.
A minimal protected `GET /auth/me` (returns `UserResponse` for the bearer token's subject) gives:
- `qa-engineer` a real request to send "refresh token as Bearer access token" against, matching
  the audit's actual exploitation scenario (`Authorization: Bearer <refresh_token>` against a
  protected endpoint).
- Every project forking this template a canonical example of a protected route, which is
  arguably part of what "hiperseguro starter" should ship with in the first place.

This is the one addition in this spec that goes beyond "remediate the three cited findings" —
everything else is a behavior change to an existing route. Flagged explicitly per task
instructions; drop it from scope if the preference is to keep OBJ-001 strictly to the three
findings and defer a protected-route example to a later objective.

---

## 5. Open decisions needing confirmation (not architectural — thresholds/infra choices)

These don't change the contract shape in `openapi.yaml` (still `429`/shared `400`), only the
numbers and backing store, so they're listed here rather than blocking the spec:

1. **`MAX_OTP_ATTEMPTS`** — recommend **5**. Caps brute force at 5 guesses per issued code
   instead of the current unlimited (audit's 10⁶-combination/10-minute-window math).
2. **Rate limit thresholds** — recommend **5 req/min per IP** on `/forgot-password` (it triggers
   an email-send side effect), **10 req/min per IP** on `/verify-otp` and `/reset-password`.
3. **`/forgot-password` per-email cooldown** — recommend **60s** between issuances for the same
   `(email, purpose)` while a live OTP exists.
4. **Rate-limit/lockout storage backend** — Redis vs. a Postgres table. `Verification.attempts`
   is a plain column either way (already relational), but the IP-based rate limiter's counters
   are a separate question: Redis is the conventional choice for this (TTL-native, no write
   amplification on a hot path), but this project currently has no Redis dependency at all —
   introducing one is a real infra decision (devops-engineer: new service in docker-compose/CI),
   not a spec detail. A Postgres-table fallback (e.g. `slowapi`'s in-memory/Redis backends, or a
   hand-rolled `rate_limit_hits` table) avoids the new dependency at the cost of more DB writes on
   every request to these three endpoints. Recommend deferring to `security-specialist` +
   `devops-engineer` before `developer` picks a library.
5. **`GET /auth/me`** — see §4 above; confirm in/out of OBJ-001 scope.

None of these block `qa-engineer` from writing contract tests against `openapi.yaml` as it
stands — the tests can assert "a 429 is returned after N+1 requests" and "the same 400 is
returned after the configured max attempts" parametrized on whatever value `developer` ends up
wiring into settings, without the exact number being fixed at the architecture layer.

---

## Phase 3 implementation addendum (developer, 2026-08-21)

Two independent decisions taken where this document deliberately left the choice open:
- **OTP lockout invalidation**: chose "set `expires_at = now()`" over "delete the row" — deleting
  would break the resend-cooldown's stated purpose (nothing would remain for the cooldown check to
  find), letting an attacker immediately reset their budget after lockout.
- **Rate limiter storage**: one row per accepted request + `COUNT(...)` sliding window, not a
  per-key counter+bucket — simpler and consistent with the freezegun no-server-side-`now()`
  requirement; accepted the extra row growth (tracked as a cleanup item in OBJ-006).
- Thresholds wired as module-level constants in `auth.py`, not `Settings` fields (`MAX_OTP_ATTEMPTS
  = 5`, `OTP_RESEND_COOLDOWN_SECONDS = 60`, etc.) — matches the values `qa-engineer` hardcoded in
  the test files, kept scope minimal.

Full Gate 3 verification: `docs/testing/obj-001-test-report.md`. Schema review:
`docs/database/obj-001-schema-review.md`.
