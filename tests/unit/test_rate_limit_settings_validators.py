"""
OBJ-014 (obj-014-design-notes.md section 7) -- Finding #21 fix + proactive
companion validator:

  - `RATE_LIMIT_IP_MULTIPLIER` (existing field, previously unvalidated --
    audit-report.md "Gate 3 -- Verificacion OBJ-013" section 3b, finding
    #21) now requires >= 1. A 0 or negative multiplier makes
    `resolved_ip_limit` 0 or negative, and a SQL COUNT() result is never
    negative, so the IP-only check in `enforce_rate_limit` would
    unconditionally 429 the FIRST request from any IP on all 6
    rate-limited endpoints.
  - `RATE_LIMIT_EMAIL_RESERVED_SLOTS` (new field, introduced by this same
    objective) gets the analogous >= 0 validator proactively, so it never
    becomes a future finding of the same shape. 0 is a legitimate, explicit
    opt-out (disables the reserved-fresh-IP-slot mitigation); negative has
    no defined meaning.

Same fail-closed-at-startup convention as SECRET_KEY/POSTGRES_SSL_MODE/
ALGORITHM/ENVIRONMENT in app/core/config.py, and the same subprocess-based
testing approach as tests/unit/test_secret_key_startup.py: `Settings` is a
module-level `lru_cache`d singleton constructed at import time
(`app.core.config.settings = get_settings()`), so re-importing
`app.core.config` within the current test process would just hit that
cache/`sys.modules` regardless of env changes -- each scenario below runs
`import app.core.config` in a FRESH subprocess with a controlled
environment, the only way to genuinely exercise "does constructing Settings
raise" per input.

RED-PHASE EXPECTATION: today, `app/core/config.py` has no
`field_validator` for `RATE_LIMIT_IP_MULTIPLIER` at all, and no
`RATE_LIMIT_EMAIL_RESERVED_SLOTS` field exists yet -- every
"invalid value blocks startup" test below is expected to fail (the
subprocess exits 0 regardless of the value, or errors for the unknown-field
case in a way distinct from the intended ValueError-driven validation
failure).
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
    "SECRET_KEY": "pytest-suite-fixed-secret-key-do-not-use-in-production-0123456789",
    "ALGORITHM": "HS256",
    "ACCESS_TOKEN_EXPIRE_MINUTES": "30",
    "REFRESH_TOKEN_EXPIRE_DAYS": "7",
    "POSTGRES_SSL_MODE": "disable",
    "ENVIRONMENT": "development",
}


def _run_config_import(env_overrides: dict) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    env.update(BASE_ENV_FIELDS)
    env.update(env_overrides)
    return subprocess.run(
        [sys.executable, "-c", "import app.core.config"],
        cwd=str(REPO_ROOT),
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )


class TestRateLimitIpMultiplierValidator:
    """Finding #21: RATE_LIMIT_IP_MULTIPLIER must be >= 1."""

    @pytest.mark.parametrize("value", ["0", "-1", "-5"])
    def test_zero_or_negative_multiplier_blocks_startup(self, value):
        result = _run_config_import({"RATE_LIMIT_IP_MULTIPLIER": value})
        assert result.returncode != 0, (
            f"RATE_LIMIT_IP_MULTIPLIER={value!r} must block startup -- a 0 or "
            "negative multiplier makes the IP-keyed rate limit unreachable or "
            "nonsensical, self-denying every request (audit-report.md finding "
            f"#21).\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )

    @pytest.mark.parametrize("value", ["1", "5", "10"])
    def test_valid_multiplier_permits_startup(self, value):
        result = _run_config_import({"RATE_LIMIT_IP_MULTIPLIER": value})
        assert result.returncode == 0, (
            f"RATE_LIMIT_IP_MULTIPLIER={value!r} is valid (>= 1) and must "
            f"permit startup.\nstderr:\n{result.stderr}"
        )

    def test_unset_multiplier_uses_default_and_permits_startup(self):
        """No override -- Settings' own default (5) applies and must pass
        its own validator."""
        result = _run_config_import({})
        assert result.returncode == 0, (
            f"the default RATE_LIMIT_IP_MULTIPLIER must satisfy its own "
            f"validator.\nstderr:\n{result.stderr}"
        )


class TestRateLimitEmailReservedSlotsValidator:
    """OBJ-014 proactive validator: RATE_LIMIT_EMAIL_RESERVED_SLOTS must be >= 0."""

    @pytest.mark.parametrize("value", ["-1", "-5"])
    def test_negative_reserved_slots_blocks_startup(self, value):
        result = _run_config_import({"RATE_LIMIT_EMAIL_RESERVED_SLOTS": value})
        assert result.returncode != 0, (
            f"RATE_LIMIT_EMAIL_RESERVED_SLOTS={value!r} must block startup -- "
            "negative has no defined meaning (design notes section 7)."
            f"\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )

    @pytest.mark.parametrize("value", ["0", "1", "3"])
    def test_zero_or_positive_reserved_slots_permits_startup(self, value):
        """0 is a legitimate, explicit opt-out (disables the mitigation
        entirely) -- design notes section 6 -- and must NOT be rejected."""
        result = _run_config_import({"RATE_LIMIT_EMAIL_RESERVED_SLOTS": value})
        assert result.returncode == 0, (
            f"RATE_LIMIT_EMAIL_RESERVED_SLOTS={value!r} is valid (>= 0) and "
            f"must permit startup.\nstderr:\n{result.stderr}"
        )

    def test_unset_reserved_slots_uses_default_and_permits_startup(self):
        result = _run_config_import({})
        assert result.returncode == 0, (
            f"the default RATE_LIMIT_EMAIL_RESERVED_SLOTS must satisfy its "
            f"own validator.\nstderr:\n{result.stderr}"
        )


class TestRateLimitEmailReservedSlotsDefault:
    def test_default_is_one(self):
        """design notes section 3/6: default 1 -- the smallest value that
        provides any guarantee while leaving brute-force-facing headroom
        nearly untouched. Direct in-process check (no subprocess needed --
        same as test_rate_limit_ip_multiplier_setting.py's own convention),
        since tests/conftest.py deliberately does not set this env var."""
        from app.core.config import settings

        assert settings.RATE_LIMIT_EMAIL_RESERVED_SLOTS == 1
