"""
OBJ-001 Story 3 -- SECRET_KEY validated at startup.
Traces to docs/requirements/obj-001-critical-auth-hardening.md Scenarios
3.1-3.7 and obj-001-design-notes.md section 3.

Per the design notes: "this needs a process-level test ... not an httpx
request-level test -- there's no request to make if the process won't
start." `app.core.config.settings = get_settings()` is a module-level
`lru_cache`d singleton constructed at IMPORT time, so re-importing
`app.core.config` within the current test process would just hit that
cache (or Python's own sys.modules cache) regardless of env changes. Each
scenario below therefore runs `import app.core.config` in a **fresh
subprocess** with a controlled environment -- the only way to genuinely
exercise "does constructing Settings raise" per input.

Today (red phase): app/core/config.py's SECRET_KEY field is a bare `str`
with no validator, so EVERY "startup fails" test below currently fails
(the subprocess exits 0 no matter what SECRET_KEY is set to).
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
    "ALGORITHM": "HS256",
    "ACCESS_TOKEN_EXPIRE_MINUTES": "30",
    "REFRESH_TOKEN_EXPIRE_DAYS": "7",
}


def _run_config_import_with_secret_key(secret_key) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    env.update(BASE_ENV_FIELDS)
    if secret_key is None:
        env.pop("SECRET_KEY", None)
    else:
        env["SECRET_KEY"] = secret_key
    return subprocess.run(
        [sys.executable, "-c", "import app.core.config"],
        cwd=str(REPO_ROOT),
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )


class TestValidSecretKeyPermitsStartup:
    def test_strong_random_secret_key_permits_startup(self):
        """Scenario 3.1: e.g. a value shaped like secrets.token_urlsafe(64) output."""
        strong_key = "Kx9mP2vQ8zR4tL6wN1yB5cA3jH7fD0sG-Kx9mP2vQ8zR4tL6wN1yB5cA3jH7fD0sG"
        result = _run_config_import_with_secret_key(strong_key)
        assert result.returncode == 0, (
            f"a strong, non-placeholder SECRET_KEY (len={len(strong_key)}) "
            f"must permit startup.\nstderr:\n{result.stderr}"
        )


class TestMissingOrWeakSecretKeyBlocksStartup:
    def test_missing_secret_key_blocks_startup(self):
        """Scenario 3.2."""
        result = _run_config_import_with_secret_key(None)
        assert result.returncode != 0, "startup must fail when SECRET_KEY is unset"

    def test_empty_secret_key_blocks_startup(self):
        """Scenario 3.2 ('or is an empty string')."""
        result = _run_config_import_with_secret_key("")
        assert result.returncode != 0, "startup must fail when SECRET_KEY is empty"

    def test_short_secret_key_blocks_startup(self):
        """Scenario 3.3: length < 32."""
        result = _run_config_import_with_secret_key("short_key")
        assert result.returncode != 0, (
            "SECRET_KEY shorter than 32 characters must block startup"
        )


class TestKnownPlaceholdersBlockStartup:
    """Scenarios 3.4 and 3.7. obj-001-design-notes.md section 3's blocklist:
    'your_secret_key_here' (the literal .env.example value), plus 'secret',
    'changeme', 'change_me', 'CHANGE_ME', empty string, and
    'insert_secret_key_here'-style variants."""

    @pytest.mark.parametrize(
        "placeholder",
        [
            "your_secret_key_here",  # exact .env.example value
            "change_me",
            "changeme",
            "secret",
            "insert_secret_key_here",
        ],
    )
    def test_known_placeholder_blocks_startup(self, placeholder):
        result = _run_config_import_with_secret_key(placeholder)
        assert result.returncode != 0, (
            f"known placeholder {placeholder!r} must block startup "
            "(design notes section 3 blocklist)"
        )


class TestPlaceholderDetectionIsCaseInsensitive:
    """Scenario 3.5 + design notes section 3 explicit instruction: 'Case-insensitive compare.'"""

    @pytest.mark.parametrize(
        "placeholder_variant",
        ["YOUR_SECRET_KEY_HERE", "Your_Secret_Key_Here", "CHANGE_ME", "SECRET"],
    )
    def test_case_variant_of_placeholder_blocks_startup(self, placeholder_variant):
        result = _run_config_import_with_secret_key(placeholder_variant)
        assert result.returncode != 0, (
            f"{placeholder_variant!r} is a case variant of a known placeholder; "
            "design notes section 3 mandates case-insensitive matching"
        )


# Scenario 3.6 (forged JWT with a known-weak SECRET_KEY) is a direct
# consequence of 3.4 holding, not an independently testable behavior
# (there's no HTTP surface to hit once startup never happens) -- not
# duplicated here.
#
# Scenario 3.8 (SECRET_KEY rotation without restart) is marked "(TBD)" in
# the business-analyst's own acceptance criteria, with the mechanism
# explicitly undecided ("file watch, manual reload endpoint, next
# restart"). Out of scope for this red-phase pass; no test authored.
