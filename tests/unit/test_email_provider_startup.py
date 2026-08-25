"""
OBJ-005 Gate 3 security finding -- `EMAIL_PROVIDER` cross-field startup
validation (docs/security/audit-report.md, "Gate 3 -- Verificacion
OBJ-005", "[NUEVO - MEDIO] EMAIL_PROVIDER por defecto ('console') sin gate
de entorno"). Same subprocess-per-case technique and rationale as
tests/unit/test_secret_key_startup.py / test_postgres_ssl_mode_startup.py /
test_environment_settings.py: `app.core.config.settings = get_settings()`
is a module-level `lru_cache`d singleton constructed at IMPORT time, so
re-importing `app.core.config` within an already-running pytest process
would just hit that cache/sys.modules regardless of env vars a test tries
to change -- this MUST be a subprocess-per-case test.

Scenarios derived directly from the audit finding's "Fix recomendado":
"validador cruzado en Settings (mismo mecanismo que ENVIRONMENT/SECRET_KEY)
que rechace el arranque si ENVIRONMENT == 'production' and EMAIL_PROVIDER
== 'console'":

  - production + EMAIL_PROVIDER left unset (the actual default, 'console')
    -> startup MUST be blocked. This is the exact scenario the finding
    describes: "un despliegue que jamas toque esta variable arranca sin
    error... en cualquier ENVIRONMENT incluido production."
  - production + EMAIL_PROVIDER explicitly 'console' -> startup MUST be
    blocked, same as leaving it unset.
  - production + any OTHER EMAIL_PROVIDER value -> startup permitted. This
    validator only guards the one known-unsafe combination named by the
    finding; an unrecognized non-console provider is a separate,
    already-covered concern (deps.py's `_email_sender_singleton()` raises
    NotImplementedError at first USE, not at startup -- see
    tests/unit/test_email_sender.py::TestGetEmailSenderFactory::
    test_get_email_sender_raises_not_implemented_for_an_unconfigured_provider).
    Duplicating that check here would test the same behavior twice for the
    wrong reason.
  - development/staging + EMAIL_PROVIDER left unset ('console') -> startup
    permitted. This validator is production-only, matching config.py's own
    comment on EMAIL_PROVIDER's default ("a bad value here is an
    operational/delivery concern, not a security posture regression" --
    true for non-production, no longer true for production once this fix
    lands).

Today (red phase, before this pass's fix): `Settings` has no
`model_validator` guarding this combination at all, so
`_run_config_import("production", None)` and
`_run_config_import("production", "console")` both currently exit 0 --
i.e. TestProductionConsoleBlocksStartup's two tests currently FAIL. The
other two classes currently PASS (vacuously for TestProductionWith
RealProviderPermitsStartup, genuinely for TestNonProductionConsole
PermitsStartup since no such combination was ever blocked) -- kept as
forward-looking regression anchors, same convention as this file's sibling
startup-validation tests.
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
}


def _run_config_import(environment, email_provider) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    env.update(BASE_ENV_FIELDS)
    env["ENVIRONMENT"] = environment
    if email_provider is None:
        env.pop("EMAIL_PROVIDER", None)
    else:
        env["EMAIL_PROVIDER"] = email_provider
    return subprocess.run(
        [sys.executable, "-c", "import app.core.config"],
        cwd=str(REPO_ROOT),
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )


class TestProductionConsoleBlocksStartup:
    def test_production_with_default_email_provider_blocks_startup(self):
        result = _run_config_import("production", None)
        assert result.returncode != 0, (
            "ENVIRONMENT=production with EMAIL_PROVIDER left at its "
            "default ('console') must block startup -- ConsoleEmailSender "
            "would log OTP codes in plaintext to stdout in production "
            "(audit-report.md Gate 3 OBJ-005 finding, reintroducing "
            "finding #10)"
        )

    def test_production_with_explicit_console_blocks_startup(self):
        result = _run_config_import("production", "console")
        assert result.returncode != 0, (
            "ENVIRONMENT=production with EMAIL_PROVIDER explicitly set to "
            "'console' must block startup, same as leaving it unset"
        )


class TestProductionWithRealProviderPermitsStartup:
    @pytest.mark.parametrize("provider", ["sendgrid", "ses", "smtp"])
    def test_production_with_non_console_provider_permits_startup(self, provider):
        """This validator only guards the specific known-unsafe combination
        (production + console). A non-console value deps.py's factory
        doesn't actually implement is a separate, already-covered concern
        (NotImplementedError at first use) -- not this startup validator's
        job."""
        result = _run_config_import("production", provider)
        assert result.returncode == 0, (
            f"ENVIRONMENT=production with EMAIL_PROVIDER={provider!r} (not "
            f"'console') must permit startup -- unrecognized-provider "
            f"handling belongs to deps.py's factory at first use, not this "
            f"startup validator.\nstderr:\n{result.stderr}"
        )


class TestNonProductionConsolePermitsStartup:
    @pytest.mark.parametrize("environment", ["development", "staging"])
    def test_non_production_with_default_email_provider_permits_startup(self, environment):
        result = _run_config_import(environment, None)
        assert result.returncode == 0, (
            f"ENVIRONMENT={environment!r} with EMAIL_PROVIDER left at its "
            f"default ('console') must permit startup -- this validator is "
            f"production-only.\nstderr:\n{result.stderr}"
        )
