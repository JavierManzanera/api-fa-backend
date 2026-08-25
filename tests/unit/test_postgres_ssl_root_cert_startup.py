"""
Audit finding #18 (docs/security/audit-report.md, OBJ-012 Gate 3 section;
full investigation: docs/database/obj-012-tls-dast-verification.md, Finding
1) -- `POSTGRES_SSL_ROOT_CERT` Settings field, startup-validation half.
Companion to tests/unit/test_database_ssl.py (which tests the
mode-to-connect_args TRANSLATION function's use of this value); this file
tests the narrower "does this field exist / get read correctly" question,
same subprocess-per-case technique as test_postgres_ssl_mode_startup.py --
required because `app.core.config.settings` is a module-level `lru_cache`d
singleton constructed at IMPORT time in the current process, so a different
env value can only be observed from a fresh process.

Finding 1's gap: `verify-full` (`app/core/database.py`'s
`_build_ssl_connect_arg`) called bare `ssl.create_default_context()`, which
trusts only the OS default CA store -- there was no app-level way to pin a
private/self-signed CA, pushing self-hosted/private-CA operators toward the
weaker, MITM-vulnerable `require` mode instead. `POSTGRES_SSL_ROOT_CERT` is
the fix: an OPTIONAL path to a CA cert file, unset by default (preserving
today's OS-trust-store-only behavior for every existing deployment), that an
operator can point at their own CA to make `verify-full` succeed against it.

Today (red phase, before developer's fix): `app.core.config.Settings` has no
`POSTGRES_SSL_ROOT_CERT` field at all -- setting the env var is silently
ignored (pydantic-settings ignores env vars with no matching field), so
`test_setting_it_is_read_back` fails (AttributeError intercepted below and
turned into an assertion failure, not a raised startup error -- there is no
validator to trigger, this field has no invalid values to reject).
"""

import os
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

BASE_ENV_FIELDS = {
    "PROJECT_NAME": "subprocess-test",
    "POSTGRES_USER": "test",
    "POSTGRES_PASSWORD": "test",
    "POSTGRES_SERVER": "localhost",
    "POSTGRES_PORT": "5433",
    "POSTGRES_DB": "api_fa_test_unused",
    "POSTGRES_SSL_MODE": "verify-full",
    "SECRET_KEY": "Kx9mP2vQ8zR4tL6wN1yB5cA3jH7fD0sG-Kx9mP2vQ8zR4tL6wN1yB5cA3jH7fD0sG",
    "ALGORITHM": "HS256",
    "ACCESS_TOKEN_EXPIRE_MINUTES": "30",
    "REFRESH_TOKEN_EXPIRE_DAYS": "7",
    "ENVIRONMENT": "development",
}

_PRINT_ROOT_CERT_SCRIPT = (
    "import app.core.config as c; "
    "print('ROOT_CERT=' + repr(c.settings.POSTGRES_SSL_ROOT_CERT))"
)


def _run_with_root_cert(raw_value) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    env.update(BASE_ENV_FIELDS)
    if raw_value is None:
        env.pop("POSTGRES_SSL_ROOT_CERT", None)
    else:
        env["POSTGRES_SSL_ROOT_CERT"] = raw_value
    return subprocess.run(
        [sys.executable, "-c", _PRINT_ROOT_CERT_SCRIPT],
        cwd=str(REPO_ROOT),
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )


def _extract_root_cert_repr(result: subprocess.CompletedProcess) -> str:
    for line in result.stdout.splitlines():
        if line.startswith("ROOT_CERT="):
            return line[len("ROOT_CERT="):]
    raise AssertionError(
        f"subprocess did not print a ROOT_CERT= line -- import likely "
        f"failed or the field does not exist yet.\n"
        f"returncode={result.returncode}\nstdout={result.stdout!r}\n"
        f"stderr={result.stderr!r}"
    )


class TestUnsetDefaultsToNone:
    def test_unset_defaults_to_none(self):
        """Optional, no operator action required -- every existing
        deployment (verify-full against a publicly-trusted CA, or require/
        disable modes where this setting is irrelevant) keeps working
        unchanged."""
        result = _run_with_root_cert(None)
        assert result.returncode == 0, f"stderr:\n{result.stderr}"
        assert _extract_root_cert_repr(result) == "None", (
            "POSTGRES_SSL_ROOT_CERT must default to None when unset"
        )


class TestSettingItIsReadBack:
    def test_setting_it_is_read_back(self):
        result = _run_with_root_cert("/etc/ssl/certs/my-private-ca.pem")
        assert result.returncode == 0, f"stderr:\n{result.stderr}"
        assert (
            _extract_root_cert_repr(result) == "'/etc/ssl/certs/my-private-ca.pem'"
        ), (
            "POSTGRES_SSL_ROOT_CERT must be read back exactly as set -- a "
            "plain path string, no transformation/validation applied"
        )


class TestOptionalFieldDoesNotBlockStartupInOtherModes:
    def test_unset_root_cert_still_permits_require_mode_startup(self):
        """POSTGRES_SSL_ROOT_CERT is verify-full-specific; it must not
        become an accidentally-required field that blocks 'require' or
        'disable' mode startup."""
        env = dict(os.environ)
        env.update(BASE_ENV_FIELDS)
        env["POSTGRES_SSL_MODE"] = "require"
        env.pop("POSTGRES_SSL_ROOT_CERT", None)
        result = subprocess.run(
            [sys.executable, "-c", "import app.core.config"],
            cwd=str(REPO_ROOT),
            env=env,
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result.returncode == 0, f"stderr:\n{result.stderr}"
