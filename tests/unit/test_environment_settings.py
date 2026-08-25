"""
OBJ-004 finding #13 -- `ENVIRONMENT` Settings field, startup-validation half.
Companion to tests/api/test_docs_gating.py (which tests the field's actual
HTTP-level EFFECT: gating /docs, /redoc, /openapi.json); this file tests the
narrower "is this Settings FIELD itself valid" question, at the same
subprocess-per-case layer as tests/unit/test_secret_key_startup.py and
tests/unit/test_postgres_ssl_mode_startup.py (OBJ-003's established
precedent for this exact class of question).

No Gherkin/AC doc exists for OBJ-004 (backend/infra hardening, no
business-analyst pass in this objective's agent chain, same as OBJ-003) --
scenarios below are derived directly from docs/api/obj-004-design-notes.md
section 3, with the derivation documented here rather than translated from a
Gherkin doc, matching OBJ-003's established convention:

  - section 3's illustrative code: "ENVIRONMENT: str" (required, no
    default) + a field_validator raising ValueError for anything outside
    {"development", "staging", "production"} -> the three test classes
    below (valid values permit startup; a missing value blocks it; an
    unrecognized value blocks it).
  - section 3: "Case-sensitivity matches POSTGRES_SSL_MODE (exact lowercase
    match, no case-insensitive handling)" -> TestUnrecognizedEnvironmentBlocksStartup
    includes case-variants of valid values (e.g. "Production", "DEVELOPMENT")
    as cases that must ALSO block startup -- deliberately mirroring
    test_postgres_ssl_mode_startup.py's own case-variant parametrization,
    NOT test_secret_key_startup.py's case-INsensitive blocklist (different
    field, different design decision, explicitly noted in the design notes).

Same rationale as test_secret_key_startup.py / test_postgres_ssl_mode_startup.py
for why this MUST be a subprocess-per-case test: `app.core.config.settings =
get_settings()` is a module-level `lru_cache`d singleton constructed at
IMPORT time in the CURRENT process -- re-importing `app.core.config` within
an already-running pytest process just hits that cache/sys.modules,
regardless of what env vars a test tries to change.

Today (red phase): app/core/config.py's Settings class has no ENVIRONMENT
field at all (confirmed by direct read, matching obj-004-design-notes.md
section 3's own "confirmed via direct read... no ENVIRONMENT field exists
anywhere in Settings today" note). Every "startup must be blocked" test
below therefore currently FAILS (the subprocess exits 0 regardless of what
-- or whether -- ENVIRONMENT is set, since pydantic-settings silently
ignores an env var with no matching field by default). The "valid values
permit startup" tests currently PASS, but only vacuously (startup was never
at risk since the field doesn't exist to validate) -- kept as forward-looking
regression anchors, same convention as test_postgres_ssl_mode_startup.py's
own TestValidSslModesPermitStartup class.

REQUIRED, NON-OPTIONAL carry-over landed in this same pass (per this
project's established "proactive fix" convention from OBJ-003): both
tests/unit/test_secret_key_startup.py and
tests/unit/test_postgres_ssl_mode_startup.py had "ENVIRONMENT": "development"
added to their own BASE_ENV_FIELDS dicts, and tests/conftest.py gained
os.environ.setdefault("ENVIRONMENT", "development") -- without these,
`developer` adding this required field would break every other subprocess
test file in the suite (masking their own SECRET_KEY/POSTGRES_SSL_MODE
behavior under test) AND the entire tests/api/** suite (Settings() import
fails at collection).
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
    "POSTGRES_SSL_MODE": "disable",
    "SECRET_KEY": "Kx9mP2vQ8zR4tL6wN1yB5cA3jH7fD0sG-Kx9mP2vQ8zR4tL6wN1yB5cA3jH7fD0sG",
    "ALGORITHM": "HS256",
    "ACCESS_TOKEN_EXPIRE_MINUTES": "30",
    "REFRESH_TOKEN_EXPIRE_DAYS": "7",
    # PROACTIVE FIX (same convention this file's own docstring already
    # documents for POSTGRES_SSL_MODE/SECRET_KEY carry-overs): this file's
    # TestValidEnvironmentsPermitStartup parametrizes over all three
    # ENVIRONMENT values including "production", and the new EMAIL_PROVIDER/
    # ENVIRONMENT cross-field validator (tests/unit/test_email_provider_
    # startup.py, audit-report.md Gate 3 OBJ-005) now rejects
    # ENVIRONMENT=production + EMAIL_PROVIDER="console" (the default) at
    # import time -- without this, the production case here would fail for
    # an unrelated reason, masking this file's own ENVIRONMENT-field
    # validation under test.
    "EMAIL_PROVIDER": "smtp",
}


def _run_config_import_with_environment(environment) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    env.update(BASE_ENV_FIELDS)
    if environment is None:
        env.pop("ENVIRONMENT", None)
    else:
        env["ENVIRONMENT"] = environment
    return subprocess.run(
        [sys.executable, "-c", "import app.core.config"],
        cwd=str(REPO_ROOT),
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )


class TestValidEnvironmentsPermitStartup:
    @pytest.mark.parametrize("valid_env", ["development", "staging", "production"])
    def test_valid_environment_permits_startup(self, valid_env):
        result = _run_config_import_with_environment(valid_env)
        assert result.returncode == 0, (
            f"ENVIRONMENT={valid_env!r} is one of the three values "
            f"obj-004-design-notes.md section 3 defines and must permit "
            f"startup.\nstderr:\n{result.stderr}"
        )


class TestMissingEnvironmentBlocksStartup:
    def test_missing_environment_blocks_startup(self):
        """design notes section 3: 'new required field, no default --
        matching the exact convention already established by
        POSTGRES_SSL_MODE... every environment must say what it wants.'"""
        result = _run_config_import_with_environment(None)
        assert result.returncode != 0, (
            "startup must fail when ENVIRONMENT is unset -- it is a "
            "required field with no default, same convention as "
            "POSTGRES_SSL_MODE (design notes section 3)"
        )


class TestUnrecognizedEnvironmentBlocksStartup:
    @pytest.mark.parametrize(
        "bad_env",
        ["", "prod", "dev", "stage", "Production", "DEVELOPMENT", "Staging", "local"],
    )
    def test_unrecognized_environment_blocks_startup(self, bad_env):
        """design notes section 3: case-sensitivity matches
        POSTGRES_SSL_MODE (exact lowercase match, no case-insensitive
        handling) -- so case-variants of valid values ('Production',
        'DEVELOPMENT') must ALSO block startup, not silently normalize."""
        result = _run_config_import_with_environment(bad_env)
        assert result.returncode != 0, (
            f"ENVIRONMENT={bad_env!r} is not one of development/staging/"
            f"production (lowercase-exact) and must block startup, not "
            f"silently pass through or normalize"
        )
