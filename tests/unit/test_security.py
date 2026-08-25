"""
Unit tests for app/core/security.py -- no DB, no HTTP.

Traces to OBJ-001 Story 1 (docs/requirements/obj-001-critical-auth-hardening.md)
and obj-001-design-notes.md section 1 (JWT claim schema). These are the "pure logic"
counterpart to tests/api/test_token_type_enforcement.py, isolating the
encode/decode rules from FastAPI's dependency-injection layer per
test-gap-analysis.md section 2.8.
"""

from datetime import timedelta

import pytest
from fastapi import HTTPException
from freezegun import freeze_time
import jwt

from app.core import security
from app.core.config import settings


def _decode(token: str) -> dict:
    return jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])


class TestPasswordHashing:
    def test_hash_differs_from_plaintext_and_verifies(self):
        hashed = security.get_password_hash("SomeValidPass1!")
        assert hashed != "SomeValidPass1!"
        assert security.verify_password("SomeValidPass1!", hashed) is True

    def test_verify_rejects_wrong_password(self):
        hashed = security.get_password_hash("SomeValidPass1!")
        assert security.verify_password("WrongPass1!", hashed) is False


class TestTokenClaimSchema:
    """obj-001-design-notes.md section 1: both token types must carry an explicit
    `type: "access"|"refresh"` claim; the legacy `refresh: true` claim on
    refresh tokens is retired, not kept alongside it."""

    def test_access_token_has_explicit_type_access_claim(self):
        token = security.create_access_token("someone@example.com")
        payload = _decode(token)
        assert payload.get("type") == "access", (
            "access tokens must carry an explicit type=access claim "
            "(design notes section 1) -- not implemented yet"
        )

    def test_refresh_token_has_explicit_type_refresh_claim(self):
        token = security.create_refresh_token("someone@example.com")
        payload = _decode(token)
        assert payload.get("type") == "refresh", (
            "refresh tokens must carry an explicit type=refresh claim "
            "(design notes section 1) -- currently only sets the legacy "
            "`refresh: true` claim"
        )

    def test_refresh_token_legacy_claim_is_retired(self):
        """Design notes section 1: 'The legacy "refresh": true claim ... is
        retired, not kept alongside the new claim -- one source of truth.'
        """
        token = security.create_refresh_token("someone@example.com")
        payload = _decode(token)
        assert "refresh" not in payload, (
            "the legacy `refresh: true` claim must be removed once the "
            "explicit `type` claim replaces it (design notes section 1)"
        )


class TestVerifyRefreshToken:
    """obj-001-design-notes.md section 1: verify_refresh_token must reject with
    401 (changed from 400) for ALL token-validity failures: wrong type,
    bad signature, expired, malformed."""

    def test_accepts_a_genuine_refresh_token(self):
        token = security.create_refresh_token("someone@example.com")
        assert security.verify_refresh_token(token) == "someone@example.com"

    def test_rejects_an_access_token_with_401(self):
        access_token = security.create_access_token("someone@example.com")
        with pytest.raises(HTTPException) as exc_info:
            security.verify_refresh_token(access_token)
        assert exc_info.value.status_code == 401, (
            "an access token presented as a refresh token must be rejected "
            "with 401 per design notes section 1 (currently raises 400)"
        )

    def test_rejects_malformed_token_with_401(self):
        with pytest.raises(HTTPException) as exc_info:
            security.verify_refresh_token("not-a-jwt-at-all")
        assert exc_info.value.status_code == 401, (
            "malformed tokens must be rejected with 401, not 400 "
            "(design notes section 1: 'changed from 400 to 401 for all "
            "token-validity failures')"
        )

    def test_rejects_expired_refresh_token_with_401(self):
        with freeze_time("2026-01-01 00:00:00"):
            token = security.create_refresh_token(
                "someone@example.com", expires_delta=timedelta(seconds=1)
            )
        with freeze_time("2026-01-01 00:00:05"):
            with pytest.raises(HTTPException) as exc_info:
                security.verify_refresh_token(token)
        assert exc_info.value.status_code == 401

    def test_rejects_token_signed_with_wrong_secret_with_401(self):
        forged = jwt.encode(
            {"sub": "someone@example.com", "type": "refresh", "exp": 9999999999},
            "a-completely-different-secret-key-the-attacker-guessed",
            algorithm=settings.ALGORITHM,
        )
        with pytest.raises(HTTPException) as exc_info:
            security.verify_refresh_token(forged)
        assert exc_info.value.status_code == 401
