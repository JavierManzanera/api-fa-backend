"""
OBJ-004 finding #9, part 1 -- `BACKEND_CORS_ORIGINS` Settings field
parsing/validation half. Companion to tests/api/test_cors_middleware.py
(which tests the field's actual HTTP-level EFFECT via CORSMiddleware); this
file tests the narrower "does this field parse/validate correctly" question,
subprocess-per-case, same technique as test_postgres_ssl_mode_startup.py /
test_environment_settings.py -- required here because `Settings` is a
module-level `lru_cache`d singleton constructed at import time, so a
different env value can only be observed from a fresh process.

Scenario derivation (no Gherkin/AC doc for OBJ-004, same convention as
OBJ-003 -- see test_environment_settings.py's docstring for the full
rationale), from obj-004-design-notes.md section 1.1:

  - "new Settings field BACKEND_CORS_ORIGINS: List[AnyHttpUrl] = [],
    populated from a comma-separated env var... defaulting to an empty
    list" -> test_unset_defaults_to_empty_list,
    test_comma_separated_origins_parse_into_a_list,
    test_whitespace_around_comma_separated_origins_is_stripped,
    test_trailing_comma_does_not_produce_an_empty_entry.
  - "AnyHttpUrl cannot parse the literal string '*' -- it fails URL
    validation and blocks app startup... This closes the audit's exact
    named fear at the type-validation level" -> test_wildcard_origin_blocks_startup,
    plus a same-shape check that a bare hostname (no scheme) also can't be
    expressed -- AnyHttpUrl requires a scheme.
  - design notes section 0 / the task's own instruction to verify findings
    rather than trust citations blindly: audit-report.md finding #9's own
    fear text ("es probable que el siguiente proyecto añada
    allow_origins=['*']") is the literal thing test_wildcard_origin_blocks_startup
    proves can no longer happen even by accident.

Today (red phase): app/core/config.py's Settings class has no
BACKEND_CORS_ORIGINS field at all (confirmed by direct read). Every test
below that expects VALIDATION (wildcard-blocks-startup, parsing shape)
currently either passes vacuously (the field doesn't exist to reject
anything) or fails outright depending on how the printed marker is checked --
see each test's own assertion for how "field doesn't exist yet" is
distinguished from "field exists but doesn't validate correctly."
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
    "ENVIRONMENT": "development",
}

_PRINT_ORIGINS_SCRIPT = (
    "import app.core.config as c; "
    "print('ORIGINS=' + repr([str(o) for o in c.settings.BACKEND_CORS_ORIGINS]))"
)


def _run_with_cors_origins(raw_value) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    env.update(BASE_ENV_FIELDS)
    if raw_value is None:
        env.pop("BACKEND_CORS_ORIGINS", None)
    else:
        env["BACKEND_CORS_ORIGINS"] = raw_value
    return subprocess.run(
        [sys.executable, "-c", _PRINT_ORIGINS_SCRIPT],
        cwd=str(REPO_ROOT),
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )


def _extract_origins_repr(result: subprocess.CompletedProcess) -> str:
    for line in result.stdout.splitlines():
        if line.startswith("ORIGINS="):
            return line[len("ORIGINS="):]
    pytest.fail(
        f"subprocess did not print an ORIGINS= line -- import likely failed.\n"
        f"returncode={result.returncode}\nstdout={result.stdout!r}\nstderr={result.stderr!r}"
    )


class TestDefaultIsEmptyList:
    def test_unset_defaults_to_empty_list(self):
        """design notes section 1.1 / Gate 1 APPROVED Option A: 'defaulting
        to an empty list -- not a hardcoded origin, and not a wildcard.'"""
        result = _run_with_cors_origins(None)
        assert result.returncode == 0, f"stderr:\n{result.stderr}"
        origins_repr = _extract_origins_repr(result)
        assert origins_repr == "[]", (
            f"BACKEND_CORS_ORIGINS must default to an empty list when unset "
            f"(Gate 1 Option A) -- got {origins_repr}"
        )


class TestCommaSeparatedParsing:
    def test_comma_separated_origins_parse_into_a_list(self):
        result = _run_with_cors_origins(
            "https://app.example.com,https://admin.example.com"
        )
        assert result.returncode == 0, f"stderr:\n{result.stderr}"
        origins_repr = _extract_origins_repr(result)
        assert "app.example.com" in origins_repr
        assert "admin.example.com" in origins_repr
        # Exactly two entries parsed, not one merged string.
        assert origins_repr.count("http") == 2, (
            f"expected exactly 2 parsed origins, got {origins_repr}"
        )

    def test_single_origin_parses_into_a_one_item_list(self):
        result = _run_with_cors_origins("https://solo.example.com")
        assert result.returncode == 0, f"stderr:\n{result.stderr}"
        origins_repr = _extract_origins_repr(result)
        assert origins_repr.count("http") == 1, (
            f"expected exactly 1 parsed origin, got {origins_repr}"
        )

    def test_whitespace_around_comma_separated_origins_is_stripped(self):
        """design notes section 1.1's illustrative validator: 'origin.strip()
        for origin in value.split(",")'."""
        result = _run_with_cors_origins(
            " https://a.example.com , https://b.example.com "
        )
        assert result.returncode == 0, f"stderr:\n{result.stderr}"
        origins_repr = _extract_origins_repr(result)
        assert origins_repr.count("http") == 2, (
            f"whitespace-padded comma-separated origins must still parse "
            f"into exactly 2 entries, got {origins_repr}"
        )

    def test_trailing_comma_does_not_produce_an_empty_entry(self):
        """design notes section 1.1: 'if origin.strip()' filters out empty
        segments -- a trailing comma must not attempt to parse '' as a URL
        (which would raise) or produce a spurious third entry."""
        result = _run_with_cors_origins("https://a.example.com,https://b.example.com,")
        assert result.returncode == 0, f"stderr:\n{result.stderr}"
        origins_repr = _extract_origins_repr(result)
        assert origins_repr.count("http") == 2, (
            f"a trailing comma must not produce an empty/invalid third "
            f"entry, got {origins_repr}"
        )


class TestWildcardAndMalformedOriginsBlockStartup:
    """VACUOUS-PASS CAVEAT, confirmed during this pass's verification run
    (same "forward-looking anchor" convention already established for
    test_postgres_ssl_mode_startup.py's TestValidSslModesPermitStartup):
    today, BEFORE BACKEND_CORS_ORIGINS exists on Settings,
    `_PRINT_ORIGINS_SCRIPT` itself raises AttributeError on
    `c.settings.BACKEND_CORS_ORIGINS` regardless of what value the env var
    holds -- an unhandled exception, which ALSO produces a non-zero
    subprocess exit code. So every test in this class currently passes,
    but for the WRONG reason (the field not existing at all, not AnyHttpUrl
    correctly rejecting "*"). Once `developer` adds the field, these tests
    start passing for the RIGHT reason -- kept as-is rather than weakened,
    same rationale as the OBJ-003 precedent."""

    def test_wildcard_origin_blocks_startup(self):
        """The audit's own named fear (audit-report.md finding #9: 'es
        probable que el siguiente proyecto añada allow_origins=["*"]
        apresuradamente') closed at the type-validation level: the literal
        string '*' cannot parse as an AnyHttpUrl (design notes section
        1.1)."""
        result = _run_with_cors_origins("*")
        assert result.returncode != 0, (
            "BACKEND_CORS_ORIGINS='*' must fail Settings construction -- "
            "AnyHttpUrl cannot express a wildcard, closing audit finding "
            "#9's named fear at the type level, not just by convention"
        )

    def test_wildcard_among_valid_origins_blocks_startup(self):
        result = _run_with_cors_origins("https://good.example.com,*")
        assert result.returncode != 0, (
            "a wildcard mixed in with otherwise-valid origins must still "
            "block startup -- one bad entry cannot be silently dropped in "
            "favor of the good ones (fail closed, not partial-accept)"
        )

    def test_schemeless_host_blocks_startup(self):
        """AnyHttpUrl requires a scheme -- a bare hostname is exactly the
        kind of 'nearly valid' entry a rushed .env edit could produce."""
        result = _run_with_cors_origins("app.example.com")
        assert result.returncode != 0, (
            "a schemeless value ('app.example.com', no http(s)://) must "
            "not silently parse -- AnyHttpUrl requires an explicit scheme"
        )
