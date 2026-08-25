"""
OBJ-001 Story 1 -- refresh tokens cannot be used as access tokens.
Traces to docs/requirements/obj-001-critical-auth-hardening.md Scenarios
1.1-1.5 and docs/api/openapi.yaml paths `/auth/me` and `/auth/refresh`.

Requires Postgres -- see tests/README.md / tests/conftest.py module
docstring for the environment blocker noted during this red-phase pass.
"""

import jwt

from app.core import security
from app.core.config import settings


async def test_scenario_1_1_access_token_accepted_on_protected_endpoint(
    client, api_prefix, user_factory
):
    user, _ = await user_factory(email="alice@example.com")
    token = security.create_access_token(user.email)

    resp = await client.get(
        f"{api_prefix}/auth/me", headers={"Authorization": f"Bearer {token}"}
    )

    assert resp.status_code == 200
    assert resp.json()["email"] == user.email


async def test_scenario_1_2_refresh_token_rejected_on_protected_endpoint(
    client, api_prefix, user_factory
):
    user, _ = await user_factory(email="bob@example.com")
    refresh_token = security.create_refresh_token(user.email)

    resp = await client.get(
        f"{api_prefix}/auth/me", headers={"Authorization": f"Bearer {refresh_token}"}
    )

    assert resp.status_code == 401, (
        "a refresh token used as a Bearer access token must be rejected -- "
        "this is audit finding #1's exact exploitation scenario"
    )
    assert resp.json()["detail"] == "Could not validate credentials"


async def test_scenario_1_3_refresh_token_accepted_on_refresh_endpoint(
    client, api_prefix, user_factory
):
    """OBJ-002 note: sourced via a real /auth/login call (not
    security.create_refresh_token() called directly) -- OBJ-002 backs every
    refresh token with a `refresh_sessions` row created at issuance
    (docs/api/obj-002-design-notes.md section 1-2), so a token minted
    without going through an actual issuance endpoint has no row to match
    and would 401 for a reason unrelated to what this scenario tests (token
    *type* acceptance, not session-table bookkeeping). Login is the
    realistic way any refresh token actually enters the system."""
    user, password = await user_factory(email="carol@example.com")
    login_resp = await client.post(
        f"{api_prefix}/auth/login",
        data={"username": user.email, "password": password},
    )
    assert login_resp.status_code == 200, login_resp.text
    refresh_token = login_resp.json()["refresh_token"]

    resp = await client.post(
        f"{api_prefix}/auth/refresh", json={"refresh_token": refresh_token}
    )

    assert resp.status_code == 200
    body = resp.json()
    assert "access_token" in body
    assert "refresh_token" in body
    assert body["token_type"] == "bearer"


async def test_scenario_1_4_access_token_rejected_on_refresh_endpoint(
    client, api_prefix, user_factory
):
    user, _ = await user_factory(email="dave@example.com")
    access_token = security.create_access_token(user.email)

    resp = await client.post(
        f"{api_prefix}/auth/refresh", json={"refresh_token": access_token}
    )

    assert resp.status_code == 401, (
        "an access token submitted to /auth/refresh must be rejected with "
        "401 (openapi.yaml: 'Rejection status changes from 400 to 401 ... "
        "including an access token being replayed here')"
    )


async def test_scenario_1_5_forged_token_with_tampered_type_claim_rejected(
    client, api_prefix, user_factory
):
    user, _ = await user_factory(email="eve@example.com")
    # Attacker doesn't know SECRET_KEY -- signs with a guessed one instead.
    # Must fail on signature verification before type is ever trusted.
    forged = jwt.encode(
        {"sub": user.email, "type": "access", "exp": 9999999999},
        "attacker-guessed-wrong-secret-key-0123456789",
        algorithm=settings.ALGORITHM,
    )

    resp = await client.get(
        f"{api_prefix}/auth/me", headers={"Authorization": f"Bearer {forged}"}
    )

    assert resp.status_code == 401


async def test_forged_token_with_correct_secret_but_no_type_claim_rejected(
    client, api_prefix, user_factory
):
    """Fail-closed rule (design notes section 1): a missing `type` claim is
    treated identically to a wrong one -- reject, no backward-compat
    special case for 'old-format token = access token'."""
    user, _ = await user_factory(email="mallory@example.com")
    token_without_type = jwt.encode(
        {"sub": user.email, "exp": 9999999999},
        settings.SECRET_KEY,
        algorithm=settings.ALGORITHM,
    )

    resp = await client.get(
        f"{api_prefix}/auth/me",
        headers={"Authorization": f"Bearer {token_without_type}"},
    )

    assert resp.status_code == 401, (
        "a token with the correct signature but no `type` claim at all "
        "must be rejected, not treated as an implicit access token"
    )
