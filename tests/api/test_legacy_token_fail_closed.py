"""
OBJ-002 dispatch task item 6 / obj-002-design-notes.md section 5: any token
issued before OBJ-002 (no `ver` claim on access tokens, no `jti` claim on
refresh tokens) must fail CLOSED automatically, with no special-casing, at
every protected surface -- the same fail-closed precedent OBJ-001 already
established for the `type` claim (see
tests/api/test_token_type_enforcement.py's
test_forged_token_with_correct_secret_but_no_type_claim_rejected).

The refresh-endpoint half of this (a legacy refresh token with no `jti`) is
already covered by tests/api/test_refresh_rotation.py's
test_scenario_2_5_legacy_pre_obj002_refresh_token_rejected -- not
duplicated here. This file covers the protected-endpoint half: a legacy
ACCESS token (no `ver` claim) presented to GET /auth/me.

Requires Postgres -- see tests/README.md / tests/conftest.py module
docstring.
"""

from jose import jwt

from app.core.config import settings


async def test_legacy_access_token_without_ver_claim_rejected_at_me(
    client, api_prefix, user_factory
):
    user, _ = await user_factory(email="legacy-access@example.com")
    legacy_access_token = jwt.encode(
        {"sub": user.email, "type": "access", "exp": 9999999999, "iat": 0},
        settings.SECRET_KEY,
        algorithm=settings.ALGORITHM,
    )

    resp = await client.get(
        f"{api_prefix}/auth/me",
        headers={"Authorization": f"Bearer {legacy_access_token}"},
    )

    assert resp.status_code == 401, (
        "design notes section 5: payload.get('ver') is None, "
        "user.token_version defaults to an int (e.g. 0) -- None == 0 is "
        "False, so the missing claim alone must reject fail-closed, no "
        "backward-compat special case for 'old-format token = still valid'"
    )
    assert resp.json()["detail"] == "Could not validate credentials"


async def test_forged_access_token_with_correct_looking_ver_still_needs_real_signature(
    client, api_prefix, user_factory
):
    """Sanity check that the new `ver` check is layered ON TOP of (not a
    replacement for) OBJ-001's existing signature verification -- a token
    signed with the wrong key must still be rejected even if its claims,
    including a plausible `ver`, are otherwise well-formed. This is a
    regression guard for already-correct OBJ-001 behavior, expected to
    already pass -- not itself proof of any new OBJ-002 code."""
    user, _ = await user_factory(email="legacy-forged@example.com")
    forged = jwt.encode(
        {"sub": user.email, "type": "access", "ver": 0, "exp": 9999999999},
        "attacker-guessed-wrong-secret-key-0123456789",
        algorithm=settings.ALGORITHM,
    )

    resp = await client.get(
        f"{api_prefix}/auth/me",
        headers={"Authorization": f"Bearer {forged}"},
    )

    assert resp.status_code == 401
