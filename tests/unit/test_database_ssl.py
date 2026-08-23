"""
OBJ-003 finding #8 -- TLS to PostgreSQL, unit-level.

No Gherkin/AC doc exists for OBJ-003 (see tests/unit/test_otp_hashing.py's
docstring for the full explanation). Scenarios below are derived directly
from `docs/api/obj-003-design-notes.md` section 2:

  - section 2.1 ("`asyncpg`... takes an `ssl` argument that is `False`,
    `True`, or an `ssl.SSLContext`... the three modes are built explicitly")
    -> one test per POSTGRES_SSL_MODE value (disable/require/verify-full).
  - section 2.1's explicit driver nuance ("`ssl=True` in `asyncpg` already
    behaves like libpq's `verify-full`, not `require`... To get libpq's
    `require` semantics... the SSLContext must be built explicitly with
    `check_hostname = False` and `verify_mode = ssl.CERT_NONE`") ->
    test_require_mode_disables_hostname_check_and_cert_verification (this
    is the single most important assertion in this file -- the whole reason
    section 2.1 exists is that a naive `ssl=True`-style implementation would
    silently give `require` the WRONG semantics; a test that only checked
    "returns an SSLContext, not a bool" would miss exactly the bug this
    design note is warning against).
  - section 2.1 ("never omitted, so behavior never depends on asyncpg's own
    undocumented-to-us default") + the design's illustrative
    `raise ValueError(f"Unknown POSTGRES_SSL_MODE: {mode!r}")` ->
    test_unrecognized_mode_raises_value_error.

SCOPE BOUNDARY (explicit, per the task instructions and this project's
established "explicitly out of scope" convention): this file unit-tests
`app.core.database`'s mode-to-connect_args TRANSLATION FUNCTION directly,
mocking/inspecting nothing about an actual TLS-enabled Postgres connection.
It does NOT attempt an integration test against a real TLS-terminated
Postgres -- this sandbox's self-provisioned throwaway Postgres 16
(`initdb`/`pg_ctl`, port 5433, `trust` auth) has no TLS certificates
configured, and setting that up is out of scope for a red-phase test-writing
pass. `obj-003-design-notes.md` section 2.2 separately already investigated
(and confirmed safe) that `app.core.database.engine` -- the one object this
change touches -- is never connected to anywhere in this test suite
(`tests/conftest.py`'s `db_engine` fixture uses its own independent engine
against the real test database; `app.main`'s lifespan never runs under
`httpx.ASGITransport`). So there is no integration-level regression risk
here to begin with, independent of this scope boundary.

Function-name note: `_build_ssl_connect_arg` is not yet decided app
architecture (no `database-architect` OBJ-003 section existed in
`.ai-context/dependency_graph.md` at the time this pass was authored -- see
this file's sibling `test_otp_hashing.py` docstring for the same caveat re:
finding #7). This name is taken directly from
`obj-003-design-notes.md` section 2.1's illustrative code as the concrete
contract to test against, per the task's explicit instruction ("likely a
unit test against `app/core/database.py`'s translation function directly").
If `developer` picks a different function name with equivalent behavior,
that's an acceptable implementation deviation -- update the import below,
don't treat a naming mismatch alone as a behavioral regression.

Today (red phase): `app.core.database` has no such function at all --
every test below fails at the module-level import with
`ImportError`/`AttributeError`, the correct "missing implementation" signal
for a function that doesn't exist yet.

No DB, no HTTP, no network -- pure unit tests over a pure function.
"""

import ssl

import pytest


def _import_build_ssl_connect_arg():
    from app.core.database import _build_ssl_connect_arg

    return _build_ssl_connect_arg


class TestDisableMode:
    def test_disable_mode_returns_false(self):
        build = _import_build_ssl_connect_arg()
        assert build("disable") is False, (
            "POSTGRES_SSL_MODE='disable' must translate to connect_args={'ssl': False} "
            "-- asyncpg's own no-TLS sentinel (obj-003-design-notes.md section 2.1)"
        )


class TestRequireMode:
    def test_require_mode_returns_an_ssl_context(self):
        build = _import_build_ssl_connect_arg()
        result = build("require")
        assert isinstance(result, ssl.SSLContext), (
            f"POSTGRES_SSL_MODE='require' must translate to an ssl.SSLContext, "
            f"not {type(result)!r} ({result!r})"
        )

    def test_require_mode_disables_hostname_check_and_cert_verification(self):
        """The load-bearing assertion in this file -- see module docstring.
        libpq's `require` semantics (encrypt the wire, don't verify the
        server's cert) are NOT asyncpg's default for a bare `ssl=True`;
        obj-003-design-notes.md section 2.1 is explicit that the SSLContext
        for 'require' must be built with check_hostname=False and
        verify_mode=ssl.CERT_NONE. An implementation that just did
        `ssl.create_default_context()` for BOTH 'require' and 'verify-full'
        (the easy-to-write bug this design note exists to prevent) would
        fail this specific test even though test_require_mode_returns_an_
        ssl_context above would still pass."""
        build = _import_build_ssl_connect_arg()
        ctx = build("require")
        assert ctx.check_hostname is False, (
            "'require' mode must set check_hostname=False -- libpq's "
            "'require' does not verify the server's hostname"
        )
        assert ctx.verify_mode == ssl.CERT_NONE, (
            "'require' mode must set verify_mode=ssl.CERT_NONE -- libpq's "
            "'require' encrypts the wire but does not verify the server's "
            "certificate at all (that's what distinguishes it from "
            "'verify-full')"
        )


class TestVerifyFullMode:
    def test_verify_full_mode_returns_an_ssl_context(self):
        build = _import_build_ssl_connect_arg()
        result = build("verify-full")
        assert isinstance(result, ssl.SSLContext)

    def test_verify_full_mode_enforces_hostname_check_and_cert_verification(self):
        """The strict end of the spectrum -- default `ssl.create_default_
        context()` posture: CERT_REQUIRED + hostname checking. This is what
        distinguishes 'verify-full' from 'require' above."""
        build = _import_build_ssl_connect_arg()
        ctx = build("verify-full")
        assert ctx.check_hostname is True, (
            "'verify-full' mode must verify the server's hostname"
        )
        assert ctx.verify_mode == ssl.CERT_REQUIRED, (
            "'verify-full' mode must require and verify the server's "
            "certificate"
        )

    def test_require_and_verify_full_produce_distinguishable_contexts(self):
        """Direct regression guard against the exact bug obj-003-design-
        notes.md section 2.1 calls out: asyncpg's ssl=True already behaves
        like verify-full, so an implementation that (incorrectly) maps
        'require' to the same bare ssl.create_default_context() as
        'verify-full' would pass both single-mode tests above but produce
        two SEMANTICALLY IDENTICAL contexts -- this test catches that by
        comparing them directly."""
        build = _import_build_ssl_connect_arg()
        require_ctx = build("require")
        verify_full_ctx = build("verify-full")
        assert (require_ctx.check_hostname, require_ctx.verify_mode) != (
            verify_full_ctx.check_hostname,
            verify_full_ctx.verify_mode,
        ), (
            "'require' and 'verify-full' must produce SSLContexts with "
            "different (check_hostname, verify_mode) postures -- if they "
            "match, 'require' has silently collapsed into 'verify-full' "
            "semantics (the exact driver-nuance bug design notes section "
            "2.1 exists to prevent)"
        )


class TestUnrecognizedMode:
    @pytest.mark.parametrize("bad_mode", ["", "verify-ca", "allow", "REQUIRE", "yolo"])
    def test_unrecognized_mode_raises_value_error(self, bad_mode):
        build = _import_build_ssl_connect_arg()
        with pytest.raises(ValueError):
            build(bad_mode)
