# OBJ-008 — Test Report (qa-engineer, Gate 3 verification)

**Summary:** OBJ-008 (`python-jose` → `PyJWT[crypto]`, commits `99a0749`+`0371df8` on
`obj-008-pyjwt-migration`) is a pure library swap with no API contract change, so this pass had no
red phase of its own — it is Gate-3 independent re-verification of the developer's self-reported
result, per this project's Gate discipline (self-reports are never trusted). Full suite
(`tests/unit`+`tests/api`) re-run against a throwaway, self-provisioned Postgres 16: **279 passed,
0 failed** (274 pre-existing + 5 new, see below), collect-only clean (279 collected, 0 errors). One
real coverage gap found and closed: no existing test exercised a JWT with an *unexpected header
`alg`* against a live endpoint (as opposed to `ALGORITHM`-setting startup validation, which is
already covered). Added `tests/api/test_jwt_algorithm_confusion.py` (5 tests) to close it — all
pass. `ecdsa`/`python-jose` confirmed genuinely absent from the resolved dependency closure, not
just the diff. **Verdict: PASS.**

**Jump to:** "Environment" — how the disposable test Postgres and Python env were built for this
pass · "Full suite result" — exact pass count and collect-only confirmation · "Exception-mapping
review" — line-by-line trace of every JWT decode/except site in `app/core/security.py` and
`app/api/deps.py`, and the 6 forgery cases proven to raise a `PyJWTError` subclass · "New test file
— algorithm-confusion gap" — what was missing, what was added, why · "`python-ecdsa` removal
confirmation" — `pip list` + lock-file grep against a clean install, not the diff · "Out of scope /
risk notes".

## Environment

No Docker on this machine (consistent with every prior pass in `tests/README.md`). Self-provisioned
via `initdb`/`pg_ctl` (`C:\Program Files\PostgreSQL\16\bin`), own data directory inside this
worktree (`.pgdata-verify/`, gitignored — not committed), **port 5434, not the documented 5433** —
5433 was already bound by a concurrent Gate-3 run on a different branch/worktree at the time of this
pass (`netstat -ano` confirmed a live listener on 5433 before provisioning), so this instance
deliberately used a different port to avoid colliding with it. `test`/`test`/`api_fa_test`,
otherwise identical to the documented convention. Torn down (`pg_ctl stop`, data dir removed) after
this pass.

Python: a fresh venv (`.venv-verify/`, gitignored — not committed) built strictly from
`requirements.lock.txt` + `requirements-dev.lock.txt` (not the developer's own environment, not the
global interpreter's pre-existing packages) — the point being to prove what the *committed lock
files* actually resolve to, independent of whatever else happens to be installed globally. Confirmed
`greenlet` imports cleanly in this environment (`greenlet==3.5.5`) — the native-DLL/Windows
Application Control blocker documented in `tests/README.md`'s OBJ-006 section for a *different*
authoring session does not apply here; `tests/api/**` ran without issue.

## Full suite result

```
TEST_DATABASE_URL=postgresql+asyncpg://test:test@localhost:5434/api_fa_test
pytest --collect-only -q   -> 279 tests collected, 0 errors
pytest -q                  -> 279 passed in 111.90s
```

274 tests pre-existed on this branch (unchanged pass count from the developer's own reported
baseline); +5 new (`tests/api/test_jwt_algorithm_confusion.py`, added this pass — see below). Zero
failures, zero errors, zero skips. No regressions against any prior objective's recorded pass count.

## Exception-mapping review

Read both call sites end to end (`app/core/security.py` lines 131–180, `app/api/deps.py` lines
22–54). Both import `from jwt import PyJWTError` (PyJWT's common base exception, matching
`python-jose`'s single `JWTError` the code used to catch) and both call `jwt.decode(token, key,
algorithms=[ALGORITHM])` — the explicit `algorithms=` allow-list argument is preserved from the
`jose` version and is what makes the "unexpected alg" case fail closed (see below).

- `app/core/security.py::_decode_refresh_payload` (used by both `verify_refresh_token` and
  `decode_refresh_token_claims`, i.e. `/auth/refresh`): `except PyJWTError: raise
  credentials_exception` → `HTTPException(401, "Invalid or expired refresh token")`. The two
  in-`try` `raise credentials_exception` calls (missing/wrong `type`, missing `sub`) raise an
  `HTTPException` directly, which is *not* a `PyJWTError` subclass, so it correctly propagates
  through the `except` clause unmodified rather than being double-wrapped — same shape this
  function already had before the swap.
- `app/core/security.py::extract_jti_if_present` (used by `/auth/logout`'s best-effort revoke path):
  `except PyJWTError: return None` — deliberately swallows rather than raising, per its own
  docstring's "no-oracle" contract; not a regression risk since it never raises 500 either way.
- `app/api/deps.py::get_current_user` (used by `/auth/me` and every other protected endpoint):
  `except (PyJWTError, ValidationError): raise credentials_exception` →
  `HTTPException(401, "Could not validate credentials")`. `ValidationError` (pydantic, from
  `TokenData(email=email)`) is unrelated to the OBJ-008 swap and was already in this tuple.

Confirmed empirically (standalone script against this pass's exact venv, then re-confirmed via the
new test file's live HTTP assertions below) that every one of these raises a `PyJWTError` subclass,
never an unhandled exception:

| Case | Exception raised | `PyJWTError` subclass? |
|---|---|---|
| Expired token | `ExpiredSignatureError` | yes |
| Malformed/garbage token (`"not.a.jwt"`) | `DecodeError` | yes |
| Wrong-signature token (right alg, different secret) | `InvalidSignatureError` | yes |
| Unexpected `alg` — `alg=none` unsigned | `InvalidAlgorithmError` | yes |
| Unexpected `alg` — HS384, signed with the *real* secret | `InvalidAlgorithmError` | yes |
| Unexpected `alg` — fabricated RS256 header | `InvalidAlgorithmError` | yes |

The three `InvalidAlgorithmError` rows are the important confirmation for this migration
specifically: PyJWT enforces the `algorithms=[...]` allow-list against the token's own header *alg*
before it ever attempts a signature check, so a forged token cannot use a different algorithm to
route around signature verification (the classic algorithm-confusion / `alg=none` attack shape) —
this is preserved, not weakened, by the swap.

All six rows above are exercised at the live HTTP layer, not just in isolation: the first three
already had pre-existing coverage (`tests/unit/test_security.py`, `tests/api/test_me_endpoint.py`,
`tests/api/test_legacy_token_fail_closed.py`, `tests/api/test_token_type_enforcement.py` — all still
270+ green). **The three "unexpected alg" rows had zero pre-existing endpoint-level coverage** —
`tests/unit/test_algorithm_startup.py` covers a different thing (the app's *own* `ALGORITHM` config
value being validated at startup, i.e. an operator can't set `ALGORITHM=ES256`), not "what happens
when a client presents a token whose own header says a different alg than the app is configured
for." Closed this gap — see next section.

## New test file — algorithm-confusion gap

`tests/api/test_jwt_algorithm_confusion.py` (5 tests, all passing): crafts three forged-token shapes
(`alg=none` unsigned, HS384 signed with the *real* `SECRET_KEY`, and a fabricated RS256 header) and
sends each to `GET /auth/me` (2 of the 3 shapes) and `POST /auth/refresh` (the other 2, covering
`_decode_refresh_payload` independently since OBJ-008 touched both call sites), asserting 401 in
every case — never 500 (an unhandled `InvalidAlgorithmError` escaping to FastAPI's default handler)
and never 200. This is a regression guard specifically for the migration: if a future change to
either decode call ever dropped the `algorithms=[...]` argument (silently accepting whatever `alg` a
token's header claims), these are the tests that would catch it — the pre-existing suite would not,
since none of it varies the header `alg`.

Out of scope, deliberately: a *real* RS256-confusion exploit (asymmetric public key mistakenly
accepted as an HMAC secret) — this app has no RSA keypair anywhere in its config, so there is no
real public key to attempt that against; the fabricated-header test proves the allow-list check
happens before any key-material handling is even reached, which is the relevant guarantee for an
HS256-only app.

## `python-ecdsa` removal confirmation

Not trusted from the diff — checked directly against the clean lock-file venv built for this pass:

```
pip list | grep -iE "jose|ecdsa|jwt|cryptography"
  cryptography            50.0.0
  PyJWT                   2.13.0
  (no jose, no ecdsa)
```

`pip show ecdsa python-jose` against the same venv: `WARNING: Package(s) not found`. Grepped
`requirements.txt`/`requirements.lock.txt`/`requirements-dev.txt`/`requirements-dev.lock.txt` for
`jose`/`ecdsa` — zero matches outside a comment in `requirements.txt` documenting the swap itself.
Grepped `app/` and `tests/` for `from jose`/`import jose`/`python-jose` — zero live imports; the only
remaining textual mentions are historical (`docs/security/audit-report.md`'s finding #15 writeup,
`docs/test-gap-analysis.md`, and prior objectives' own `docs/testing/obj-00{1,2}-test-report.md`,
all describing the pre-OBJ-008 state, correctly left as-is since they're dated records, not live
documentation). `.github/workflows/ci.yml`'s `pip-audit` step no longer carries the
`--ignore-vuln PYSEC-2026-1325` suppression (confirmed by reading the step directly) — consistent
with the CVE's root package being gone from the tree entirely rather than merely suppressed.

## Out of scope / risk notes

- Did not re-verify OBJ-006's Alembic-mode (`TEST_DB_SCHEMA_SOURCE=alembic`) suite variant — this
  pass used the default `create_all` mode only, consistent with every objective's Gate-3 pass since
  OBJ-006 landed; that specific re-verification is still an open item tracked under OBJ-006, not
  this objective.
- Did not attempt a real RS256/asymmetric-key confusion exploit (no RSA key exists anywhere in this
  app's config to target) — see the "New test file" section above for why the fabricated-header test
  is the right-shaped proof for an HS256-only app instead.
- Concurrency note for whoever runs this next: this pass's Postgres instance ran on port 5434, not
  the documented 5433, specifically because another Gate-3 run was occupying 5433 at the time —
  check `netstat` before assuming 5433 is free during a period with multiple concurrent objective
  branches in flight.
