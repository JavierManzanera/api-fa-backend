"""
OBJ-013 (obj-013-design-notes.md section 3) -- new `Settings.RATE_LIMIT_IP_MULTIPLIER`
field, same section/convention as `TRUSTED_PROXY_COUNT`/`LOG_LEVEL`: a safe
default (5), live-read at call time by `enforce_rate_limit`, no startup-fail-
closed requirement (misconfiguration affects rate-limit generosity, not
security posture in the fail-open/fail-closed sense SECRET_KEY/
POSTGRES_SSL_MODE are held to -- design notes section 7).

Pure settings-value check, no DB/HTTP -- same category as
tests/unit/test_client_ip.py's own TestTrustedProxyCountSettingsDefault.

RED-PHASE EXPECTATION: `Settings` has no `RATE_LIMIT_IP_MULTIPLIER` field
yet, so `settings.RATE_LIMIT_IP_MULTIPLIER` below is expected to raise
AttributeError today (pydantic-settings does not synthesize undeclared
attributes) -- a test ERROR, not a clean assertion failure, but still red
for the right reason (the field doesn't exist yet), same as this file's
sibling tests/api/test_rate_limit_keying.py notes for its own red cases.
"""


def test_rate_limit_ip_multiplier_setting_defaults_to_five():
    from app.core.config import settings

    assert settings.RATE_LIMIT_IP_MULTIPLIER == 5, (
        "design notes section 2/3: default multiplier applied to a scope's "
        "email-keyed `limit` to derive the IP-keyed threshold when a call "
        "site doesn't override it via `ip_limit` -- recommended default 5, "
        "flagged as a Gate 1 decision the user may want to tune before "
        "developer implements it, but this IS the shipped default absent "
        "an explicit override."
    )
