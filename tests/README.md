# Test suite -- api-fa-backend

## Running

```
pip install -r requirements-dev.txt
docker compose -f docker-compose.test.yml up -d   # starts Postgres on localhost:5433
pytest
```

`tests/unit/` needs no database at all. `tests/api/` needs a real
PostgreSQL reachable at `TEST_DATABASE_URL` (defaults to
`postgresql+asyncpg://test:test@localhost:5433/api_fa_test`, matching
`docker-compose.test.yml` at the repo root). SQLite is deliberately **not**
used as a substitute: `app/models/user.py` and `app/models/verification.py`
use `sqlalchemy.dialects.postgresql.UUID(as_uuid=True)`, a dialect-specific
type not guaranteed to behave identically on SQLite
(`docs/test-gap-analysis.md` section 4).

Port 5433 (not 5432) is deliberate, to avoid colliding with a developer's
own local/system PostgreSQL already on the default port.

## Status of this pass (2026-08-21, qa-engineer, OBJ-000 + OBJ-001 Phase 2)

Both `tests/unit/` and `tests/api/` were executed and verified end-to-end
during authoring, using a disposable, self-provisioned Postgres 16 instance
(`initdb`/`pg_ctl` from the already-installed Postgres binaries, own data
directory, port 5433, `trust` auth, torn down afterward) -- **not** the
existing local Postgres Windows service on port 5432, and **not** any
guessed credentials. `docker-compose.test.yml` is the documented,
reproducible equivalent of that ad hoc setup for anyone else running the
suite (developer, CI).

Full result: **39 failed, 10 passed** (`tests/unit` + `tests/api`
combined). Every failure was inspected and traces to a specific missing
piece of OBJ-001 (no `type` claim, wrong status codes, `/auth/me` missing
-> 404, no rate limiting, no OTP lockout, OTP generation still uses
`random`, no `SECRET_KEY` startup validation). Every pass documents
genuinely-already-correct current behavior that must not regress (e.g.
OTP TTL expiry already works; a refresh token already works on
`/auth/refresh`; a consumed OTP already can't be reused on
`/auth/reset-password`).

### Environment note for whoever runs this next

The authoring sandbox had no Docker (`docker --version` -> command not
found), which is why a throwaway `initdb`-provisioned instance was used
instead of `docker-compose.test.yml` for this verification pass. Two
independent attempts to instead use the *existing* local Postgres 16
Windows service on port 5432 (trying common default credentials; reading
`pg_hba.conf` to find its auth method) were both correctly blocked by the
harness's safety classifier as credential-discovery behavior -- neither
was worked around, and that service was never touched. `docker compose -f
docker-compose.test.yml up -d` is the intended, supported path going
forward.

### Per-worktree/per-checkout venv (2026-08-25, devops-engineer)

This project runs concurrent subagents on separate branches via `git
worktree` (Claude Code's Agent tool `isolation: "worktree"` option). Until
now everything (main checkout + every worktree) installed straight into
the one global Python 3.11 interpreter's site-packages -- there was no
per-project venv at all. That broke `obj-009-register-rate-limit` (cut
before `obj-008-pyjwt-migration` merged, so its code still imports
`python-jose`): a concurrent OBJ-008 install had uninstalled
`python-jose` globally in favor of `PyJWT`, so every test on the
`obj-009` branch errored with `ModuleNotFoundError: No module named
'jose'` -- an environment artifact, not a real test failure.

**Going forward: each checkout (main working dir, and each
`.claude/worktrees/<agent-id>` worktree) gets its own `.venv`, built from
that checkout's own `requirements.lock.txt` / `requirements-dev.lock.txt`**,
not a shared/global interpreter:

```
python -m venv .venv
.venv/Scripts/pip install -r requirements-dev.lock.txt   # Linux/Mac: .venv/bin/pip
.venv/Scripts/python -m pytest --collect-only -q         # sanity check before running anything
```

`.venv/` is already covered by this repo's existing `.gitignore` pattern
(`.venv/`, matches at any depth via git's relative-path matching, verified
with `git check-ignore`); a worktree's `.venv` is additionally covered
wholesale by the `.claude/worktrees/` ignore entry. No new gitignore
entries were needed. This is a convention, not a CI change -- CI still
builds its own single ephemeral environment per run from whichever
branch's lockfiles, which was never affected by this issue.

## OBJ-002 pass (2026-08-21, qa-engineer, red phase)

`tests/api/test_logout.py`, `test_refresh_rotation.py`,
`test_password_reset_invalidation.py`, `test_legacy_token_fail_closed.py`
(22 tests total) translate the 16 Gherkin scenarios in
`docs/requirements/obj-002-session-token-lifecycle.md` against
`docs/api/openapi.yaml` v0.3.0-obj-002 / `docs/api/obj-002-design-notes.md`.
Verified against the same kind of throwaway self-provisioned Postgres as
every prior pass: **20 failed, 2 passed** in isolation; **20 failed, 51
passed** for the full suite (zero regressions against OBJ-001's 49). Full
breakdown, scope boundaries, and risk notes for `developer` are in
`.ai-context/dependency_graph.md` under "OBJ-002 — Phase 2 (red phase)" —
not duplicated here to avoid the two documents drifting out of sync.

## OBJ-003 pass (2026-08-23, qa-engineer, red phase)

No Gherkin/AC doc exists for OBJ-003 (backend/infra hardening, no
business-analyst pass in this objective's agent chain) -- scenarios were
derived directly from `docs/api/obj-003-design-notes.md`, with the
derivation documented explicitly in each new file's own docstring (a new
pattern for this project; every prior objective translated a Gherkin doc
instead).

Five new files, 47 tests, covering audit findings #7 (OTP hashed at rest),
#8 (TLS to PostgreSQL), and #5 (timing side-channel on
login/forgot-password/logout):
- `tests/unit/test_otp_hashing.py` (11 tests) + `tests/api/
  test_otp_hashing_integration.py` (5 tests) -- finding #7.
- `tests/unit/test_database_ssl.py` (11 tests) + `tests/unit/
  test_postgres_ssl_mode_startup.py` (11 tests) -- finding #8.
- `tests/api/test_timing_side_channel.py` (9 tests) -- finding #5, plus the
  OBJ-002 Gate 3 SAST fold-in on `/auth/logout`.

**Required, non-optional factory fix landed in this pass** (design notes
section 1.5): `tests/factories.py`'s `create_verification` now seeds
`security.hash_otp(code)` instead of plaintext `code`. Full breakdown,
including the **17 previously-green OBJ-001/OBJ-002 tests this deliberately
turns red** (all `AttributeError`, all tracing to the single missing
`app.core.security.hash_otp`, not broken tests), is in
`.ai-context/dependency_graph.md`'s "OBJ-003 -- Phase 2 (red phase)"
section -- not duplicated here to avoid the two documents drifting out of
sync, same convention as the OBJ-002 pass above.

Verified against the same throwaway self-provisioned Postgres pattern as
every prior pass: full suite (`tests/unit` + `tests/api`, OBJ-000/001/002/003
combined) -- **57 failed, 61 passed** (118 total).

## OBJ-006 pass (2026-08-23/24, database-architect, Alembic migration authorship)

`alembic/versions/0001_baseline_current_schema.py` through
`0008_refresh_sess_partial_uniq.py` (8 migrations) now exist, replacing
`Base.metadata.create_all` as the schema source of truth going forward.
Full write-up, verification results, and the handoff to `devops-engineer`
are in `.ai-context/dependency_graph.md`'s "OBJ-006 -- database-architect
migration authorship" section. Two things that affect how you run this
suite:

### Running against real Alembic migrations instead of `create_all`

By default (`TEST_DB_SCHEMA_SOURCE` unset, or `create_all`), `db_engine` in
`tests/conftest.py` behaves exactly as before: `drop_all` then `create_all`
against `TEST_DATABASE_URL`, no setup beyond an empty/owned Postgres.

To instead run the suite against a schema built by real Alembic migrations
(the actual proof the migrations are equivalent to `create_all`, not just
that `alembic upgrade head` runs without erroring):

```
# 1. Provision the schema via Alembic (NOT create_all) against your test DB.
#    Use 0007, not head -- see the CRITICAL warning below.
MIGRATOR_DATABASE_URL=postgresql+psycopg2://test:test@localhost:5433/api_fa_test \
  alembic upgrade 0007_grant_dml_role_privileges

# 2. Point pytest at the same database and tell db_engine not to
#    drop_all/create_all over it.
TEST_DATABASE_URL=postgresql+asyncpg://test:test@localhost:5433/api_fa_test \
TEST_DB_SCHEMA_SOURCE=alembic \
  pytest
```

**CRITICAL -- do not migrate to `head` (i.e. do not include migration
0008) before running the suite this way, or your own app.** Migration
0008 (the partial unique index defense on `refresh_sessions`) is
confirmed, empirically, to break the current `/auth/refresh` rotation
handler's insert-then-revoke ordering -- see migration 0008's own
docstring and the OBJ-006 dependency_graph.md section for the full
reproduction. Stop at `0007_grant_dml_role_privileges` until `developer`
lands the handler reorder that migration flags as required.

`devops-engineer`: whether CI runs in `create_all` mode, `alembic` mode,
or both (e.g. a dedicated job that provisions via Alembic specifically to
catch model/migration drift) is your call -- flagged, not decided, in the
OBJ-006 dependency_graph.md section.

### KNOWN BLOCKER -- 2026-08-24 (database-architect, OBJ-006 verification pass)

This authoring environment's `greenlet` native extension (`_greenlet.pyd`,
a hard dependency of SQLAlchemy's `AsyncEngine`/`AsyncSession` -- used for
*every* async DB operation, not just asyncpg-specific ones) is blocked at
import time by a Windows Application Control policy:
`ImportError: DLL load failed while importing _greenlet: An Application
Control policy has blocked this file.` This is new as of this pass --
every prior objective's passes ran the full async suite successfully
against a self-provisioned Postgres, so this is an environment change, not
a code regression. It blocks `tests/api/**` and any other async-engine
code path entirely (confirmed via direct `import greenlet`, reproducible,
not intermittent); `tests/unit/**` that don't touch the DB are unaffected.
It does NOT block plain synchronous SQLAlchemy (`create_engine` +
`psycopg2`, no greenlet involved) or Alembic itself (migrations run
synchronously, confirmed working throughout the OBJ-006 pass).

Because of this, OBJ-006's own migration verification could not run this
repo's pytest suite end-to-end as originally intended. What was verified
instead, all against a self-provisioned throwaway Postgres 16 (same
`initdb`/`pg_ctl`-equivalent pattern as every prior pass -- see the OBJ-006
dependency_graph.md section for exact commands and results): the full
upgrade/downgrade/re-upgrade cycle for all 8 migrations; a byte-for-byte
`psql \d` diff proving migration 0001's baseline is schema-identical to
`Base.metadata.create_all`'s output (captured via a sync engine, sidestepping
greenlet); the documented `stamp`-then-`upgrade` cutover path against a
simulated pre-existing `create_all` database; migration 0006's validation
failure/success paths; migration 0007's grant/revoke behavior against real
`fa_app`/`fa_migrator` roles (including confirming `fa_app` genuinely
cannot ALTER or self-escalate GRANTs); and migration 0008's
rotation-handler incompatibility, reproduced deterministically via raw SQL
mirroring `/auth/refresh`'s exact operation order.

**Not yet re-verified because of this blocker: the actual pytest suite
(118+ tests) against a migrated schema.** Flagging explicitly for whoever
picks this up next (`qa-engineer` and/or `devops-engineer`) once the
Application Control policy is resolved or worked around through a
sanctioned channel (not something to route around from inside an agent
session) -- re-run both the `create_all`-mode suite (regression check) and
the `TEST_DB_SCHEMA_SOURCE=alembic` suite (schema-equivalence check, per
the section above, stopping at migration 0007) and confirm both match the
previously-recorded pass counts.

## Layout

- `tests/conftest.py` -- env-var bootstrap (must precede any `app.*`
  import), `db_engine` / `db_session` / `client` fixtures, `api_prefix`,
  `user_factory`, `verification_factory`. See its module docstring for the
  full rationale, including the Postgres blocker note above.
- `tests/factories.py` -- plain async helper functions for creating `User`
  / `Verification` rows with real password hashes / known OTP codes.
- `tests/unit/` -- no DB: `app/core/security.py` claim/verification logic,
  `SECRET_KEY` startup validation (subprocess-based, see file docstring for
  why), OTP-generation CSPRNG check (static introspection).
- `tests/api/` -- full HTTP contract tests via `httpx.AsyncClient` +
  `ASGITransport` against the real FastAPI app, `get_db` overridden to an
  isolated, rolled-back-per-test session. Traces to the 21 Gherkin
  scenarios in `docs/requirements/obj-001-critical-auth-hardening.md`.

## Explicitly out of scope for this pass

- **Scenario 2.6** (OTP timing side-channel / no timing oracle) -- the
  acceptance criteria themselves call this "best-effort... not strictly
  enforceable at the acceptance-criteria level." No automated test
  authored; `docs/test-gap-analysis.md` section 2.5 already flags the
  underlying timing asymmetry for `security-specialist` (deferred to
  OBJ-003).
- **Scenario 3.8** (SECRET_KEY rotation without restart) -- marked "(TBD)"
  in the business-analyst's own acceptance criteria; mechanism explicitly
  undecided. No test authored.
- **True concurrency / TOCTOU** (Scenario 2.7's "10 rapid parallel
  requests", and the `reset-password` race noted in
  `docs/test-gap-analysis.md` section 2.5) -- exercised here as
  *sequential* requests, which proves the business rule (budget exhausted
  = locked) but not race-freedom under real concurrent writes. Flagged as
  flaky/environment-dependent, consistent with the gap analysis.
- General (non-OBJ-001) endpoint coverage from `docs/test-gap-analysis.md`
  (e.g. full `/register` / `/login` validation matrix, password-strength
  validator unit tests, email-casing duplicate handling) -- that backlog
  spans OBJ-002 through OBJ-005 and was not re-scoped into this pass;
  only the 21 OBJ-001 Gherkin scenarios plus infra bootstrap were in
  scope.
- **(OBJ-003) An actually-TLS-enabled Postgres integration test** --
  `tests/unit/test_database_ssl.py` unit-tests `app.core.database`'s
  mode-to-connect_args translation function directly; it does not stand up
  a real TLS-terminated Postgres and connect to it. This sandbox's
  throwaway `initdb`/`pg_ctl` Postgres has no TLS certs configured.
- **(OBJ-003) Wall-clock timing measurement for finding #5** --
  `tests/api/test_timing_side_channel.py` deliberately asserts only the
  structural guarantee (call-count/mock assertions), per
  `obj-003-design-notes.md` section 3's explicit instruction and this
  project's own established Scenario-2.6 precedent that latency-based
  assertions are flaky by construction.

## Risk notes for `developer`

- **Rate limiter storage path** (`tests/api/test_rate_limit.py`): these
  tests assume the rate limiter reads/writes through the same overridable
  `deps.get_db` session as the rest of the app. If it's implemented as a
  fully separate module-level engine/session (plausible for a
  transport/infra-layer concern per `obj-001-design-notes.md` section 2),
  these tests will fail with a raw DB connection error instead of a clean
  assertion once the code lands -- that's a sign the implementation needs
  to be made testable this way, not that the test is wrong.
- **`MAX_OTP_ATTEMPTS` / rate-limit thresholds** are hardcoded in the test
  files (5 for OTP lockout; 5/min and 10/min for rate limits) per the
  Gate 1 decision recorded in `.ai-context/dependency_graph.md`. If
  `developer` wires these to settings with different defaults, update the
  constants at the top of `test_otp_lockout.py` and `test_rate_limit.py`
  accordingly.
- **(OBJ-003) 17 previously-green tests are currently red, on purpose** --
  see `.ai-context/dependency_graph.md`'s "OBJ-003 -- Phase 2 (red phase)"
  section for the full list/explanation. All 17 error with the exact same
  `AttributeError: module 'app.core.security' has no attribute 'hash_otp'`
  (from `tests/factories.py`'s `create_verification`, required per
  `obj-003-design-notes.md` section 1.5) -- implementing
  `security.hash_otp`/`verify_otp_hash` and wiring `_check_and_consume_otp`
  to use them should turn all 17 back green as a side effect, with no
  changes needed to the 17 tests themselves.
- **(OBJ-003) `tests/api/test_timing_side_channel.py`'s DB-call-count
  assertions on `/auth/logout`** assume the `jti is None` no-op branch
  performs its DB round trip through the SAME `AsyncSession` the `client`
  fixture overrides `deps.get_db` with (same testability requirement
  already established for the rate limiter in OBJ-001 -- see the risk note
  above). If implemented via a separate session/engine, these specific
  assertions will fail with an unexpected call count (0, not a raw
  connection error, since the request itself still returns 204 either way)
  rather than a clean pass -- treat that as the same class of testability
  signal, not a broken test.
- **(OBJ-003) `tests/api/test_otp_hashing_integration.py` depends on the
  debug `print(...)` mock email sender staying in place** to recover the
  real OTP value via `capsys` (no endpoint returns it). `OBJ-004`'s row in
  `.ai-context/dependency_graph.md` lists "remove OTP debug print" as
  in-scope. If OBJ-004 lands before this file is updated to use whatever
  replaces it (a pluggable email-sender abstraction is OBJ-005 scope), this
  file's `capsys`-based OTP capture will stop finding anything and every
  test in it will fail for an unrelated reason -- flagged explicitly in the
  file's own docstring too.
