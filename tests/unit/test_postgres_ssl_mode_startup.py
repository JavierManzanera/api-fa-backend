"""
OBJ-003 finding #8 -- POSTGRES_SSL_MODE Settings field, startup-validation
half. Companion to tests/unit/test_database_ssl.py (which tests the
mode-to-connect_args TRANSLATION function); this file tests the separate
"is this Settings FIELD itself valid" question, at the same layer/using the
same subprocess technique as tests/unit/test_secret_key_startup.py.

No Gherkin/AC doc exists for OBJ-003 -- see tests/unit/test_otp_hashing.py's
docstring for the full explanation of the derivation approach. Scenarios
here come from obj-003-design-notes.md section 2.1:

  - "`POSTGRES_SSL_MODE` itself should be validated the same way SECRET_KEY
    is (a `field_validator` raising at import time on an unrecognized
    value)... Fail closed on a typo rather than silently falling through to
    an unintended mode." -> the three classes below (valid modes permit
    startup; an unrecognized value blocks it; the field being required with
    NO default -- section 2.1 -- means a missing value also blocks it).

Same rationale as test_secret_key_startup.py for why this MUST be a
subprocess-per-case test rather than a request-level or even an in-process
test: `app.core.config.settings = get_settings()` is a module-level
`lru_cache`d singleton constructed at IMPORT time in the CURRENT process --
re-importing `app.core.config` within an already-running pytest process
would just hit that cache (or sys.modules), regardless of what env vars a
test tries to change. There is no request to make and nothing to assert on
in-process if the point being tested is "does constructing Settings raise/
does the process fail to start at all."

Today (red phase): app/core/config.py's Settings class has no
POSTGRES_SSL_MODE field at all. Every "startup must be blocked" test below
therefore currently FAILS (the subprocess exits 0 regardless of what -- or
whether -- POSTGRES_SSL_MODE is set, since pydantic-settings silently
ignores an env var with no matching field by default). The "valid modes
permit startup" tests currently PASS, but only vacuously (startup was never
at risk since the field doesn't exist to validate) -- not proof the field
works once developer adds it; kept as forward-looking regression anchors
matching this project's existing convention (see test_secret_key_startup.py
for prior art) rather than removed, since they'll be the same tests
verifying it later, for the right reason once the field lands.

PROACTIVE FIX, flagged explicitly: this pass also added
"POSTGRES_SSL_MODE": "disable" to test_secret_key_startup.py's own
BASE_ENV_FIELDS (see that file). Without it, the moment developer adds the
required POSTGRES_SSL_MODE field, EVERY test in test_secret_key_startup.py
-- including the ones proving a STRONG SECRET_KEY permits startup -- would
start failing for an unrelated reason (a second, now-also-required env var
missing), masking the actual SECRET_KEY behavior under test. Caught and
fixed now rather than left as a landmine for developer's Phase 3 run.
"""

import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]

BASE_ENV_FIELDS = {
    "PROJECT_NAME": "subprocess-test",
    "POSTGRES_USER": "test",
    "POSTGRES_PASSWORD": "test",
    "POSTGRES_SERVER": "localhost",
    "POSTGRES_PORT": "5433",
    "POSTGRES_DB": "api_fa_test_unused",
    "SECRET_KEY": "Kx9mP2vQ8zR4tL6wN1yB5cA3jH7fD0sG-Kx9mP2vQ8zR4tL6wN1yB5cA3jH7fD0sG",
    "ALGORITHM": "HS256",
    "ACCESS_TOKEN_EXPIRE_MINUTES": "30",
    "REFRESH_TOKEN_EXPIRE_DAYS": "7",
    # OBJ-004 finding #13 (obj-004-design-notes.md section 3): ENVIRONMENT is
    # a second new required-no-default field, added PROACTIVELY here for the
    # same reason this file's own docstring already explains for
    # POSTGRES_SSL_MODE's addition to test_secret_key_startup.py -- without
    # it, every test below (including the "valid ssl modes permit startup"
    # ones) would start failing for the unrelated reason of a second missing
    # required field the moment `developer` adds ENVIRONMENT, masking what's
    # actually under test in THIS file. See
    # tests/unit/test_environment_settings.py for the dedicated tests.
    "ENVIRONMENT": "development",
}


def _run_config_import_with_ssl_mode(ssl_mode) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    env.update(BASE_ENV_FIELDS)
    if ssl_mode is None:
        env.pop("POSTGRES_SSL_MODE", None)
    else:
        env["POSTGRES_SSL_MODE"] = ssl_mode
    return subprocess.run(
        [sys.executable, "-c", "import app.core.config"],
        cwd=str(REPO_ROOT),
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )


class TestValidSslModesPermitStartup:
    @pytest.mark.parametrize("valid_mode", ["disable", "require", "verify-full"])
    def test_valid_ssl_mode_permits_startup(self, valid_mode):
        result = _run_config_import_with_ssl_mode(valid_mode)
        assert result.returncode == 0, (
            f"POSTGRES_SSL_MODE={valid_mode!r} is one of the three modes "
            f"obj-003-design-notes.md section 2 defines and must permit "
            f"startup.\nstderr:\n{result.stderr}"
        )


class TestMissingSslModeBlocksStartup:
    def test_missing_postgres_ssl_mode_blocks_startup(self):
        """design notes section 2.1: 'Field default: no default, required
        -- matching this codebase's existing convention... every
        environment must say what it wants.'"""
        result = _run_config_import_with_ssl_mode(None)
        assert result.returncode != 0, (
            "startup must fail when POSTGRES_SSL_MODE is unset -- it is a "
            "required field with no default, same convention as every "
            "other POSTGRES_* field (design notes section 2.1)"
        )


class TestUnrecognizedSslModeBlocksStartup:
    @pytest.mark.parametrize(
        "bad_mode", ["", "verify-ca", "allow", "prefer", "REQUIRE", "Disable", "yolo"]
    )
    def test_unrecognized_ssl_mode_blocks_startup(self, bad_mode):
        """design notes section 2.1: 'Fail closed on a typo rather than
        silently falling through to an unintended mode.' Note this
        includes case-variants of valid modes (e.g. 'Disable') -- the
        design notes' three valid literal values are lowercase-exact, no
        case-insensitive matching is specified for this field (unlike
        SECRET_KEY's placeholder blocklist, which explicitly IS
        case-insensitive per obj-001-design-notes.md section 3)."""
        result = _run_config_import_with_ssl_mode(bad_mode)
        assert result.returncode != 0, (
            f"POSTGRES_SSL_MODE={bad_mode!r} is not one of disable/require/"
            f"verify-full and must block startup, not silently pass through"
        )
