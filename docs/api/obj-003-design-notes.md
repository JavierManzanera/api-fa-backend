# OBJ-003 — Data & Transport Hardening: API Design Notes

**Author:** solution-architect
**Input:** `docs/security/audit-report.md` findings #5, #7, #8 (see §0 below — the objective's own
citation of these numbers, both in `dependency_graph.md`'s OBJ-003 row and in the task brief this
pass was dispatched with, does **not** match the actual numbering in `audit-report.md` itself; this
document uses the audit report's real numbers throughout and flags the mismatch for correction).
Also folds in one new residual finding surfaced during `security-specialist`'s OBJ-002 Gate 3 SAST
pass (`audit-report.md` "Gate 3 — Verificación OBJ-002", the `/auth/logout` timing side-channel),
which that pass explicitly recommended routing into this objective rather than opening a new one.
Companion artifacts: current `app/api/v1/endpoints/auth.py`, `app/core/config.py`,
`app/core/database.py`, `app/models/verification.py` (read in full for this pass — no business-
analyst input, per `dependency_graph.md`'s agent chain for this objective:
`solution-architect → database-architect ∥ qa-engineer → developer`).

No `openapi.yaml` schema/response-shape changes are needed for any of the three findings below —
all three are either non-HTTP-surface (data-at-rest format, DB transport) or latency-only (no
status code, header, or body change). `openapi.yaml` gets description-text updates only; see §4.

---

## 0. Finding-number mismatch — read this before citing a number elsewhere

`dependency_graph.md`'s OBJ-003 row, and the task brief this pass was given, cite the three
findings as **#5 = OTP plaintext, #7 = no TLS, #8 = timing side-channel**. Reading
`docs/security/audit-report.md` directly, the actual numbering is:

| # in `audit-report.md` | Actual finding |
|---|---|
| **#5** | Timing side-channel / user enumeration via response latency on `/login` and `/forgot-password` |
| **#7** | OTP code stored in plaintext at rest (`verifications.code`) |
| **#8** | No enforced TLS/SSL on the PostgreSQL connection |

This is a straight transposition (5↔7 swapped relative to what's needed, 8 stayed put by
coincidence of being the third item either way — 5 and 7 are the ones actually swapped). It
doesn't change the objective's scope (all three findings are still in scope, correctly identified
by their *description* in both `dependency_graph.md` and the task brief), but it would cause real
confusion if propagated into `qa-engineer`'s or `security-specialist`'s later passes, which will
naturally search `audit-report.md` by number. **This document, and the `openapi.yaml` edits made
alongside it, use the correct #5/#7/#8 mapping above.** Recommend `dependency_graph.md`'s OBJ-003
row be corrected to match (flagged in the Phase 1 deliverables section added to that file — see
task item 6's output).

---

## 1. OTP hashing at rest (finding #7)

**Evidence (current code):** `app/models/verification.py:14` — `code: Mapped[str]`, no hashing.
`app/api/v1/endpoints/auth.py:236-241` writes the plaintext 6-digit OTP straight into
`Verification.code`; `_check_and_consume_otp` (`auth.py:42-80`) compares it with a plain `!=` at
line 73.

**Decision: HMAC-SHA256, keyed by a value derived from `SECRET_KEY`, stored as a hex digest in the
existing `Verification.code` column** (no rename — see the schema-change flag below for why the
column keeps its current name for now).

### 1.1 Key: derive, don't reuse raw, don't add a new required secret

Three options were weighed:

| Option | Mechanism | Pro | Con |
|---|---|---|---|
| **A — reuse `SECRET_KEY` raw** | `hmac.new(SECRET_KEY.encode(), code, sha256)` | Zero new config | No key separation: the same secret signs JWTs *and* hashes OTPs — compromising one context (e.g. a JWT-signing bug leaking `SECRET_KEY` in an error message) compromises the other too, for no benefit |
| **B — derive a sub-key from `SECRET_KEY` (recommended)** | `otp_key = HMAC(SECRET_KEY, b"api-fa-backend:otp-hmac:v1", sha256)`, computed once at import; then `hash_otp(code) = HMAC(otp_key, code, sha256).hexdigest()` | Key separation (the derived key is cryptographically independent of the raw `SECRET_KEY` bytes) with **zero new required env var** — one secret to provision/back up/rotate, consistent with this template's goal of staying easy to fork | Still transitively tied to `SECRET_KEY`'s rotation (see §1.2) |
| **C — dedicated new secret** (`OTP_HMAC_KEY`) | Fully independent required `Settings` field | True independence — compromising `SECRET_KEY` alone doesn't also expose a mechanism to forge/verify OTP hashes | One more required secret every deployment must generate, store, and eventually rotate; more `.env.example` surface for a template whose stated goal is a lean, easy-to-fork auth block |

**Decision: Option B.** This is the "decide and document which" the task asked for. Rationale:
finding #7's threat scenario is "unauthorized read of the `verifications` table" (leaked backup,
misconfigured replica, insider) — the attacker in that scenario doesn't have `SECRET_KEY` either;
Option B's key separation already defeats that scenario (a raw-`code`-column dump is useless
without the derived key, which lives only in application memory, never in the DB). Option C's
*additional* independence only matters in a strictly worse scenario (attacker has both DB read
*and* `SECRET_KEY`) where finding #4's JWT-forgery consequences already dominate — Option C's
marginal security gain over Option B is real but small, and not proportional to a MEDIO-severity,
config-surface-sensitive finding on a "keep it simple to fork" template. Not a Gate-1 blocker;
documented here as a decided design choice with the alternative visible if the user wants Option C
instead.

**Module ownership:** lives in `app/core/security.py`, alongside `get_password_hash`/
`verify_password`/JWT encode-decode — that module is already this codebase's single owner of
crypto primitives (established in `obj-001-design-notes.md` §1's "module ownership" rule).
Illustrative shape (not implemented — `developer`'s Phase 3 concern):

```python
_OTP_HMAC_CONTEXT = b"api-fa-backend:otp-hmac:v1"
_OTP_HMAC_KEY = hmac.new(settings.SECRET_KEY.encode("utf-8"), _OTP_HMAC_CONTEXT, hashlib.sha256).digest()

def hash_otp(code: str) -> str:
    return hmac.new(_OTP_HMAC_KEY, code.encode("utf-8"), hashlib.sha256).hexdigest()

def verify_otp_hash(code: str, stored_hash: str) -> bool:
    return hmac.compare_digest(hash_otp(code), stored_hash)
```

### 1.2 Key-rotation implication (ties into OBJ-001 Scenario 3.8, still TBD)

Because the OTP key is derived from `SECRET_KEY` at import time, any future `SECRET_KEY` rotation
(mechanism still undecided per OBJ-001's Scenario 3.8) also silently rotates the OTP key. Any
`Verification` row created before the rotation will no longer verify against the new key — its
`code` hash was computed under the old derived key. **Consequence, explicitly weighed:** this is a
much smaller blast radius than the same rotation's effect on live JWTs (sessions up to 7 days,
still unresolved by 3.8) — OTPs already expire in 10 minutes, so the worst case is a user who
requested a reset OTP in the seconds/minutes immediately before a rotation has to request a new
one, indistinguishable (same generic 400) from any other wrong/expired code. **This does not block
OBJ-003 on Scenario 3.8 being resolved** — the OTP side of key rotation is self-healing within one
TTL window regardless of what mechanism 3.8 eventually adopts.

### 1.3 Comparison mechanism (verify-time)

`_check_and_consume_otp` (`auth.py:73`) changes from `if verification.code != otp:` to
`if not security.verify_otp_hash(otp, verification.code):`. `hmac.compare_digest` is constant-time
over the hash comparison itself — this closes a (much smaller, secondary) digest-comparison timing
concern as a side effect, though it is not what finding #7 is about. **No other change to
`_check_and_consume_otp`'s control flow**: the existing attempt-increment / `MAX_OTP_ATTEMPTS`
lockout / generic-400 logic (`auth.py:74-78`) is untouched — this is purely a data-shape and
comparison-primitive swap underneath the same lockout mechanism OBJ-001 built. `/forgot-password`'s
OTP creation (`auth.py:235-241`) changes to store `security.hash_otp(otp)` in `code=`, while the
plaintext `otp` variable is still what's printed by the (already-flagged-for-removal-in-OBJ-004)
email mock and would be what a real email sender (OBJ-005) sends — hashing happens only at the
storage boundary, never affecting what the user actually receives.

### 1.4 Schema change surfaced (for `database-architect`, same convention as OBJ-001/002)

`Verification.code` changes from "plaintext 6-digit string" to "64-char hex HMAC digest" — same
column, same type (`String`, already unbounded — no length-constraint migration needed), different
*semantic content*. Lands via `Base.metadata.create_all` today (OBJ-006 not started), same ordering
wrinkle already noted for `attempts`/`token_version`/`refresh_sessions`. Two things flagged for
`database-architect`'s Phase 1 pass specifically, not decided here:

1. **Naming.** Keeping the column named `code` (this doc's choice, to minimize diff against
   `auth.py`/`tests/factories.py`) vs. renaming to `code_hash` (clearer to future readers that it
   is not recoverable plaintext). Low-stakes bikeshed, same category as OBJ-002 §6.1's
   `refresh_sessions` naming flag — confirm with `database-architect` before Phase 3.
2. **No backfill needed, and this is a *self-resolving* format change, not a breaking migration** —
   worth confirming `database-architect` agrees: any `Verification` row that exists at deploy time
   with a still-plaintext `code` will simply fail every future comparison (hash-of-submitted-code
   vs. stored-plaintext never match) and fall through to the *existing* generic 400/eventual
   `attempts`-based expiry — same fail-closed-by-construction pattern already used for OBJ-001's
   `type` claim and OBJ-002's `jti`/`ver` claims on pre-existing tokens. Given the 10-minute TTL,
   any in-flight row is dead within minutes of deploy regardless; no explicit migration/backfill
   step is needed.

### 1.5 Impact on existing test infrastructure (flag for `qa-engineer`)

`tests/factories.py`'s `create_verification` currently "seeds a known OTP code directly" (per
`OBJ-000`'s delivery notes) — i.e., it writes the plaintext code straight into `Verification.code`
so a test can submit that same value over HTTP. Once this lands, the factory must instead write
`security.hash_otp(known_code)` into the column while still returning/exposing `known_code` to the
caller for the HTTP submission. **This is a required update, not optional** — every existing OTP
test (`test_otp_lockout.py`, `test_otp_resend_cooldown.py`, and any OBJ-001 test exercising
`/verify-otp`/`/reset-password`) will otherwise silently start failing every "correct code"
assertion (since the stored value stops matching a plaintext comparison) the moment `developer`
lands the hashing change, unless the factory is updated in the same pass. Flagging now so it isn't
a surprise regression during OBJ-003's Phase 3.

---

## 2. TLS to PostgreSQL (finding #8)

**Evidence:** `app/core/config.py`'s `SQLALCHEMY_DATABASE_URI` (`config.py:52-62`) builds the DSN
via `PostgresDsn.build()` with no `ssl`/`sslmode`; `app/core/database.py:5-9`'s
`create_async_engine(...)` passes no `connect_args` at all.

### 2.1 Mechanism — why this isn't just `sslmode=require` in the URL

The project uses `asyncpg` via SQLAlchemy's async dialect, not `psycopg2`. `asyncpg` does not parse
libpq-style `sslmode=` query strings; its `connect()` (and therefore SQLAlchemy's `connect_args`)
takes an `ssl` argument that is `False`, `True`, or an `ssl.SSLContext`. This distinction matters
concretely: `ssl=True` in `asyncpg` builds `ssl.create_default_context()`, which defaults to
`CERT_REQUIRED` + hostname checking — i.e. `ssl=True` in `asyncpg` already behaves like libpq's
`verify-full`, not its `require`. To get libpq's `require` semantics (encrypt the wire, but don't
verify the server's certificate — useful against a self-signed/local cert) under `asyncpg`, the
`SSLContext` must be built explicitly with `check_hostname = False` and `verify_mode =
ssl.CERT_NONE`. This is exactly the kind of driver-specific nuance worth pinning down at design
time rather than leaving to `developer` to discover.

**Decision:** a new `POSTGRES_SSL_MODE` `Settings` field, restricted to three values, translated in
`app/core/database.py` to an explicit `ssl` connect_arg — never omitted, so behavior never depends
on `asyncpg`'s own undocumented-to-us default:

```python
def _build_ssl_connect_arg(mode: str) -> bool | ssl.SSLContext:
    if mode == "disable":
        return False
    if mode == "require":
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx
    if mode == "verify-full":
        return ssl.create_default_context()  # CERT_REQUIRED + hostname check, the default posture
    raise ValueError(f"Unknown POSTGRES_SSL_MODE: {mode!r}")

engine = create_async_engine(
    str(settings.SQLALCHEMY_DATABASE_URI),
    connect_args={"ssl": _build_ssl_connect_arg(settings.POSTGRES_SSL_MODE)},
    echo=False,
    future=True,
)
```

`POSTGRES_SSL_MODE` itself should be validated the same way `SECRET_KEY` is (a `field_validator`
raising at import time on an unrecognized value) — fail closed on a typo rather than silently
falling through to an unintended mode.

**Field default: no default, required — matching this codebase's existing convention.** Every
other `POSTGRES_*`/`SECRET_KEY`/`ALGORITHM` field in `Settings` is required with no default; every
environment (`.env`, `tests/conftest.py`'s `os.environ.setdefault` block, CI) already declares
these explicitly. `POSTGRES_SSL_MODE` follows the same pattern rather than introducing this
objective's own silent default — every environment must say what it wants.

### 2.2 Does hard-enforcing TLS break the project's self-provisioned test-Postgres pattern? — Investigated, answer: no, but the escape hatch is still needed for other reasons

This was flagged in the task brief as a real risk to check, not assume. Traced it through
`tests/conftest.py`:

- The `db_engine` fixture (`conftest.py:112-127`) **does not use `app.core.database.engine` at
  all** — it builds its own, second, independent `create_async_engine(TEST_DATABASE_URL)` pointed
  at the real (throwaway, `initdb`/`pg_ctl`, port 5433, `trust` auth, no TLS configured) test
  Postgres. The comment at `conftest.py:116-119` confirms this is deliberate: "Deliberately does
  NOT reuse `app.core.database.engine`... that one is bound to the fake `POSTGRES_*` values above
  and is never meant to be connected to."
- `app.main`'s lifespan (the only code path that would exercise the *app's own* engine object) is
  confirmed to never run under the test suite either (`conftest.py:121-125`): `httpx.ASGITransport`
  doesn't send ASGI lifespan events unless explicitly wrapped, which this suite doesn't do.
- **Conclusion:** `app.core.database.engine` — the one place this design changes — is provably
  never connected to anywhere in the current pytest suite. Defaulting `POSTGRES_SSL_MODE` to
  `verify-full` (the strict end) would not break a single existing test, and needs **no change to
  `tests/conftest.py`'s `db_engine` fixture or `TEST_DATABASE_URL`**.
- It **does** still need one addition to `tests/conftest.py`'s existing `os.environ.setdefault(...)`
  block (§1's required-Settings bootstrap, `conftest.py:68-85`): a new line,
  `os.environ.setdefault("POSTGRES_SSL_MODE", "disable")`. This is not because the test *database
  connection* needs it (per the point above, it doesn't) — it's because `Settings()` is
  instantiated eagerly at `app.core.config` import time (`config.py:68`, same singleton pattern
  that makes `SECRET_KEY` validation work), and that import happens during test collection
  regardless of which engine ever gets used. Without this line, `Settings()` construction itself
  raises `ValidationError` for a missing required field, and the entire suite fails at collection,
  before any test runs. One line, not a design compromise — flagged so `qa-engineer`/`developer`
  don't get surprised by an unrelated-looking collection-time failure.

### 2.3 Open decision (Gate 1): enforcement level — genuinely a product/deployment tradeoff, not decided here

The task instructions were explicit that this should not be picked silently, and unlike §1's key
question, this one is a real tradeoff between two legitimate positions, not a "which is
marginally better" call:

**Option A — safe default, operator escape hatch (recommended).** `POSTGRES_SSL_MODE` is a normal
`Settings` field, defaults-free (required, per §2.1), with `.env.example` recommending
`verify-full` for anything beyond local dev and `disable` documented as the explicit local/test
opt-out. No code-level block on `disable` in any environment — whoever deploys is trusted to set it
correctly, the same trust model this template already extends to every other `POSTGRES_*` value.
*Pro:* doesn't hard-couple this objective to `ENVIRONMENT`-gating, which doesn't exist yet
(that's OBJ-004's scope, not started, and OBJ-003 doesn't depend on it) — no premature coupling
between unrelated objectives. Also correctly handles legitimate topologies where TLS to Postgres
genuinely doesn't apply (e.g. app and DB on the same host over a Unix socket). *Con:* nothing stops
a real production deployment from shipping with `disable` by operator mistake — it's a config
convention, not a fail-closed guarantee.

**Option B — hard-enforce like `SECRET_KEY` (finding #4's precedent), no override possible at
all.** Remove `disable` as a valid value entirely (or gate it behind a not-yet-existing
`ENVIRONMENT != production` check, pulling in a dependency on OBJ-004). *Pro:* matches this
template's existing "fail closed, no silent weak config" posture for `SECRET_KEY`. *Con:* actively
breaks any same-host/Unix-socket deployment topology that has no TLS layer to enforce in the first
place (TLS doesn't apply to a Unix socket at all — there'd be no way to satisfy "enforced" without
special-casing that transport too, which is scope creep for this objective), and would require
`OBJ-004`'s `ENVIRONMENT` field to exist first if the "only in production" carve-out is wanted —
introducing an inter-objective dependency (`OBJ-003 → OBJ-004`) that doesn't currently exist and
that `dependency_graph.md`'s graph would need to be updated to reflect.

**Recommendation: Option A**, but this is exactly the kind of call the task said should go to the
user at Gate 1 rather than be picked unilaterally — listed again in the dependency-graph update
(task item 6) as an explicit open decision.

---

## 3. Timing side-channel: constant-time `/login` and `/forgot-password` (finding #5)

**Evidence:** `auth.py:176` — `if not user or not security.verify_password(...)`. Python
short-circuits: when `user` is `None`, `verify_password` (bcrypt, ~100-300ms) never executes. This
is the dominant, most exploitable signal — orders of magnitude larger than ordinary request-latency
jitter, and remotely measurable. `/forgot-password` has an analogous, smaller asymmetry: a bare
`SELECT` (line 202-203) when the email doesn't exist, vs. `SELECT` + cooldown check + `DELETE` +
`INSERT` + `COMMIT` (lines 213-243) when it does.

**Explicit framing per task instructions — what "best-effort, not strictly testable" means here:**
`docs/requirements/obj-001-critical-auth-hardening.md`'s own AC (Scenario 2.6) already concedes
"exact latency parity is not strictly enforceable at the acceptance-criteria level." This design
deliberately does **not** chase that unenforceable goal (perfectly equal wall-clock time is not
achievable or sensibly testable — network jitter, GC pauses, and OS scheduling noise dwarf any
sub-millisecond residual once the dominant bcrypt-vs-no-bcrypt gap is closed). Instead, the design
below produces a **structural guarantee**: the expensive operation (a bcrypt verify) executes
exactly once per request on every code path, regardless of whether the target record exists. That
guarantee is unit-testable via call-count/mock assertions on `security.verify_password`, not via
timing measurement — this is the concrete answer to "how should `qa-engineer` approach Phase 2
test design later" that the task asked this pass to be explicit about.

### 3.1 `/login` and `/forgot-password` — shared mechanism

**Decision:** a precomputed dummy bcrypt hash, computed once at process startup, and a shared
helper in `app/core/security.py` that always performs exactly one `verify_password` call:

```python
# app/core/security.py, module scope — computed once at import, not per-request
DUMMY_PASSWORD_HASH = get_password_hash(secrets.token_urlsafe(32))

def verify_password_or_dummy(plain_password: str, hashed_password: Optional[str]) -> bool:
    """Always performs exactly one bcrypt verify (audit finding #5) -- callers
    must not skip this call based on whether a matching record exists.
    Returns False unconditionally when `hashed_password` is None, regardless
    of what the dummy verify happens to return."""
    target = hashed_password if hashed_password is not None else DUMMY_PASSWORD_HASH
    result = verify_password(plain_password, target)
    return result if hashed_password is not None else False
```

Computing the dummy hash via `get_password_hash(...)` at import time (rather than a hardcoded
constant string) keeps it automatically consistent with whatever bcrypt cost factor `passlib` is
configured with — no risk of the dummy silently becoming cheaper/more expensive than a real hash
if that setting ever changes. One-time ~100-300ms cost at process startup, not per-request — not
user-facing.

`/login` (`auth.py:173-180`) restructures to:

```python
result = await db.execute(select(User).filter(User.email == form_data.username))
user = result.scalars().first()

credentials_valid = security.verify_password_or_dummy(
    form_data.password, user.hashed_password if user is not None else None
)
if not credentials_valid:
    raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Incorrect email or password")
if not user.is_active:
    raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Inactive user")
```

Status codes, messages, and the `is_active` check's position are all unchanged from current
behavior — this is purely a reordering so the bcrypt call always happens before the branch, not a
contract change. **No `openapi.yaml` change needed for `/login`'s response shape.**

### 3.2 `/forgot-password` — genuine tradeoff, surfaced rather than picked silently

`/forgot-password` has no password to verify, so `verify_password_or_dummy` doesn't apply directly
— there's a real design choice about *what* dummy work to pad the not-found branch with. The audit
finding's own "Fix" text is written generically enough to cover both endpoints under one
recommendation ("ejecutar siempre `verify_password` contra un hash bcrypt dummy... cuando el
usuario no existe"), which points toward Option A below, but this pass surfaces both because the
cost profile is different enough to be worth the user's eyes on it:

**Option A — reuse the same bcrypt-dummy mechanism unconditionally (recommended, matches the
audit's literal fix text).** Every `/forgot-password` call — found or not-found — calls
`security.verify_password_or_dummy(payload.email, None)` and discards the result, purely for its
constant-cost side effect. *Pro:* same well-tested mechanism as `/login`, one code path to reason
about and test, closes the gap with a large safety margin (a 100-300ms floor dwarfs the DB-query-
count asymmetry it's replacing). *Con:* adds a **permanent** ~100-300ms tax to every
`/forgot-password` call, including the common "email exists" case that's fast today — a real,
ongoing latency cost, not a one-time one. (Throughput impact is bounded by the existing 5 req/min
per-IP rate limit from OBJ-001, so this isn't a DoS-amplification concern, just a UX-latency one.)

**Option B — equalize DB work only, no bcrypt tax.** When the user doesn't exist, still execute an
equivalent-shaped no-op query (e.g. a `SELECT` against `Verification` for that email+purpose,
mirroring the cooldown check's query shape) so query *count* is equalized, without adding bcrypt
latency. *Pro:* no latency cost added to the legitimate "email exists" path — proportionate to a
MEDIO-severity, explicitly best-effort finding. *Con:* weaker guarantee (DB round-trip latency is
itself noisier/more environment-dependent than a fixed bcrypt cost) and higher maintenance burden
— every time the "found" branch's DB work shape changes, the dummy branch must be manually kept in
sync, with nothing enforcing that at compile time.

**Recommendation: Option A**, for consistency with `/login`'s mechanism and because it's what the
audit's fix text literally describes for both endpoints — but flagged as a Gate-1-visible choice
per task instructions, since "add 100-300ms to every legitimate forgot-password call, forever" is
a real, user-facing product tradeoff, not a pure architecture call.

### 3.3 Fold-in: `/auth/logout`'s timing side-channel (new, from OBJ-002 Gate 3 SAST review)

`security-specialist`'s OBJ-002 Gate 3 pass (`audit-report.md`, "Gate 3 — Verificación OBJ-002",
§"[NUEVO — BAJO] Canal lateral de timing en `/auth/logout`") found a related, lower-severity timing
gap introduced by OBJ-002 and explicitly recommended folding its fix into this objective rather
than opening a new one ("mismo endpoint objetivo conceptual (canales de timing), no amerita un
objetivo nuevo"). Picked up here since it wasn't yet reflected in `dependency_graph.md`'s OBJ-003
summary row.

**Evidence:** `logout` (`auth.py:389-411`) only touches the database when `jti is not None` (a
validly-signed JWT was presented) — an invalid/malformed/unsigned token returns immediately with no
DB round-trip. This leaks a much narrower signal than #5 proper: not "does this email/session
exist," but "is this string a validly-signed JWT from this server." Low severity (an attacker still
needs `SECRET_KEY` to forge a valid signature regardless, which is finding #4's already-closed
concern) but same class of gap, same fix shape.

**Decision:** the `jti is None` branch performs an equivalent-shaped no-op DB round trip instead of
returning immediately — matching **both** the query call and the commit call the real branch makes
(not just the query), for the strongest structural symmetry:

```python
jti = _parse_jti(security.extract_jti_if_present(refresh_token))
if jti is not None:
    await _revoke_active_sessions(db, RefreshSession.id == jti, now=datetime.now(timezone.utc))
else:
    await db.execute(select(1))  # latency-parity no-op; audit-report.md Gate 3 OBJ-002 finding
await db.commit()
return None
```

(Note the restructure: `commit()` moves outside the `if`, executed unconditionally in both
branches, rather than only inside the `jti is not None` branch as today — this is what makes the
two paths structurally identical: one `db.execute(...)` call, one `db.commit()` call, either way.)
Still `204` always, still no oracle over session validity — this only changes the *shape* of the
no-signature branch's DB interaction, not any response content.

### 3.4 Testability guidance for `qa-engineer`'s future Phase 2 pass (task-mandated, explicit)

Per the task's instruction to avoid designing something that forces flaky wall-clock assertions:
recommend testing the **structural** guarantee, not response latency. Concretely — mock or spy on
`app.core.security.verify_password` (for §3.1/3.2) and on the `AsyncSession.execute`/`commit`
methods (for §3.3), and assert **call count and call shape**, e.g.:

- `/login` with a nonexistent email: assert `verify_password` (or `verify_password_or_dummy`) is
  called exactly once, with `DUMMY_PASSWORD_HASH` as the target hash.
- `/login` with an existing email/wrong password: assert the same call happens once, with the
  real user's `hashed_password` as the target.
- `/forgot-password` (if Option A is adopted): same pattern, both branches.
- `/auth/logout` with an invalid/unsigned token: assert `db.execute` and `db.commit` are each
  called exactly once (matching the valid-`jti` branch's call counts), not zero times.

None of this requires `freezegun`, wall-clock timers, or statistical latency sampling — it directly
asserts the mechanism this design relies on, which is what actually closes the finding (a
best-effort *structural* guarantee), not a number this pass or a later one would have to promise
and then fail to reliably reproduce in CI.

---

## 4. `openapi.yaml` impact

No schema, status-code, or response-shape changes anywhere in this objective — all three findings
are either non-HTTP-surface (§1 data format, §2 DB transport) or latency-only with unchanged
response contracts (§3). Updated (see the file itself for the actual diff):

- **`info.version`** bumped to `0.4.0-obj-003`; `info.description` gains a short pointer to this
  document and the corrected #5/#7/#8 mapping from §0.
- **`/auth/login`** description updated from "Timing side-channel on this endpoint is audit finding
  #5, scoped to OBJ-003 — unaffected by this change" to reflect closure, with an explicit note that
  this is a best-effort, structurally-guaranteed mitigation, not a response-time SLA (deliberately
  **not** expressed as an OpenAPI-level timing constraint, per task instructions — that belongs in
  this design doc, not the contract).
- **`/auth/forgot-password`** description gains an equivalent closure note (previously had none).
- **`/auth/verify-otp`** and **`/auth/reset-password`** each gain a one-line, purely informational
  note that OTP storage is now hashed at rest (finding #7) — not a contract change, no new response
  shape, consistent with how OBJ-001 flagged the `random` → `secrets` OTP-generation change as
  "implementation detail, not a contract change."
- **`/auth/logout`** description gains a note on the §3.3 fold-in, same "informational, no contract
  change" treatment.
- No changes to any `components/schemas` — `Verification` and its `code` field were never part of
  the public API surface to begin with (no endpoint returns a `Verification` object), so the §1
  data-shape change has literally nothing to update there.

---

## 5. Open decisions needing Gate 1 confirmation

Mirrors OBJ-001 §5 / OBJ-002 §6's pattern:

1. **TLS enforcement level (§2.3)** — Option A (safe default + operator escape hatch, recommended)
   vs. Option B (hard-enforce, no override, couples OBJ-003 to a not-yet-built `ENVIRONMENT` field
   from OBJ-004). Genuinely product/deployment-policy shaped, not decided here.
2. **`/forgot-password`'s dummy-work mechanism (§3.2)** — Option A (bcrypt-dummy tax on every call,
   recommended, matches audit's literal fix text) vs. Option B (DB-work-only parity, no added
   latency, weaker/harder-to-maintain guarantee).
3. **`Verification.code` column naming (§1.4)** — keep `code` (this doc's default) vs. rename to
   `code_hash`. Low-stakes, routed to `database-architect`'s Phase 1 pass, not blocking.
4. **OTP HMAC key derivation (§1.1)** — Option B (derive from `SECRET_KEY`, decided here) vs.
   Option C (dedicated new secret). Decided, not blocking, but the alternative is real enough to
   flag if the user's threat model wants full key independence.
5. **`dependency_graph.md`'s OBJ-003 finding-number citation (§0)** — recommend correcting the
   Active Objectives Status row to cite #5/#7/#8 with the mapping in §0's table, so future passes
   don't inherit the transposition.

None of these block `database-architect`'s or `qa-engineer`'s Phase 1 passes from starting — items
1 and 2 affect *which* of two already-fully-specified mechanisms lands, not whether one exists;
items 3-5 are non-blocking flags/corrections.
