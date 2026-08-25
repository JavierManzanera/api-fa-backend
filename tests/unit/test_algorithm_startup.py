"""
Security finding #15 (docs/security/audit-report.md, "Auditoria puntual --
PYSEC-2026-1325 / python-ecdsa / ALGORITHM sin validar", 2026-08-25) --
`ALGORITHM` Settings field, startup-validation half. Same subprocess-per-case
layer as tests/unit/test_secret_key_startup.py,
tests/unit/test_postgres_ssl_mode_startup.py, and
tests/unit/test_environment_settings.py (this project's established
precedent for "is this Settings FIELD itself valid" questions).

Background (full analysis in the audit-report.md section above): runtime
exposure to PYSEC-2026-1325 (an unfixed side-channel advisory in the
pure-Python `ecdsa` package, pulled in transitively by `python-jose`) is
confirmed zero today -- this app only ever uses ALGORITHM=HS256 in practice.
But unlike every other security-adjacent Settings field (SECRET_KEY,
POSTGRES_SSL_MODE, ENVIRONMENT, EMAIL_PROVIDER), ALGORITHM had zero
validation -- "HS256-only" was an observed fact, not an enforced invariant.
This file proves the fail-closed guardrail the audit recommended.

Today (red phase): app/core/config.py's ALGORITHM field is a bare `str`
with no validator, so every "startup must be blocked" test below currently
FAILS (the subprocess exits 0 no matter what ALGORITHM is set to). The
"HS256 permits startup" test currently PASSES, but only vacuously.

Same rationale as the sibling files for why this MUST be a subprocess-per-
case test: `app.core.config.settings = get_settings()` is a module-level
`lru_cache`d singleton constructed at IMPORT time in the CURRENT process --
re-importing `app.core.config` within an already-running pytest process
would just hit that cache (or sys.modules), regardless of what env vars a
test tries to change.
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
    "ACCESS_TOKEN_EXPIRE_MINUTES": "30",
    "REFRESH_TOKEN_EXPIRE_DAYS": "7",
    "ENVIRONMENT": "development",
}


def _run_config_import_with_algorithm(algorithm) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    env.update(BASE_ENV_FIELDS)
    if algorithm is None:
        env.pop("ALGORITHM", None)
    else:
        env["ALGORITHM"] = algorithm
    return subprocess.run(
        [sys.executable, "-c", "import app.core.config"],
        cwd=str(REPO_ROOT),
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )


class TestHs256PermitsStartup:
    def test_hs256_permits_startup(self):
        """HS256 is the only algorithm this app exercises today (app +
        tests) -- audit-report.md finding #15 section 1."""
        result = _run_config_import_with_algorithm("HS256")
        assert result.returncode == 0, (
            f"ALGORITHM='HS256' must permit startup.\nstderr:\n{result.stderr}"
        )


class TestNonHs256AlgorithmsBlockStartup:
    """audit-report.md finding #15: ALGORITHM must fail closed, same
    convention as SECRET_KEY/POSTGRES_SSL_MODE/ENVIRONMENT/EMAIL_PROVIDER --
    every other security-adjacent Settings field in this file already does.
    Includes EC algorithms specifically (the ones that would eventually
    reach the vulnerable ecdsa arithmetic if the cryptography backend were
    ever unavailable), plus RS256/none/typos/case-variants/empty."""

    @pytest.mark.parametrize(
        "bad_algorithm",
        [
            "ES256",
            "ES384",
            "ES512",
            "RS256",
            "none",
            "None",
            "hs256",
            "Hs256",
            "",
            "yolo",
        ],
    )
    def test_non_hs256_algorithm_blocks_startup(self, bad_algorithm):
        result = _run_config_import_with_algorithm(bad_algorithm)
        assert result.returncode != 0, (
            f"ALGORITHM={bad_algorithm!r} is not HS256 and must block "
            f"startup, not silently pass through (audit-report.md finding #15)"
        )


class TestMissingAlgorithmBlocksStartup:
    def test_missing_algorithm_blocks_startup(self):
        result = _run_config_import_with_algorithm(None)
        assert result.returncode != 0, (
            "startup must fail when ALGORITHM is unset -- it is a required "
            "field with no default"
        )
