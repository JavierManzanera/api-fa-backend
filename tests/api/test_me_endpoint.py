"""
GET /auth/me -- new endpoint proposed by solution-architect and confirmed
in scope at Gate 1 (dependency_graph.md). Traces to docs/api/openapi.yaml
path `/auth/me` and obj-001-design-notes.md section 4.

Story 1's cross-endpoint scenarios (access accepted / refresh rejected /
forged token rejected) live in test_token_type_enforcement.py. This file
covers the rest of the 401 surface listed in openapi.yaml for this
endpoint: missing header, malformed scheme, expired token, missing `sub`,
and unknown user.

Requires Postgres -- see tests/README.md for the environment blocker noted
during this red-phase pass.
"""

from datetime import timedelta

from freezegun import freeze_time
from jose import jwt

from app.core import security
from app.core.config import settings


async def test_me_returns_current_user_for_valid_access_token(
    client, api_prefix, user_factory
):
    user, _ = await user_factory(email="frank@example.com")
    token = security.create_access_token(user.email)

    resp = await client.get(
        f"{api_prefix}/auth/me", headers={"Authorization": f"Bearer {token}"}
    )

    assert resp.status_code == 200
    body = resp.json()
    assert body["email"] == user.email
    assert body["is_active"] is True
    assert body["is_verified"] is False
    assert "id" in body and "created_at" in body
    assert "hashed_password" not in body, "UserResponse must never leak the hash"


async def test_me_missing_authorization_header_rejected(client, api_prefix):
    resp = await client.get(f"{api_prefix}/auth/me")
    assert resp.status_code == 401


async def test_me_malformed_authorization_scheme_rejected(
    client, api_prefix, user_factory
):
    user, _ = await user_factory(email="grace@example.com")
    token = security.create_access_token(user.email)

    resp = await client.get(
        f"{api_prefix}/auth/me", headers={"Authorization": f"Basic {token}"}
    )

    assert resp.status_code == 401


async def test_me_expired_access_token_rejected(client, api_prefix, user_factory):
    user, _ = await user_factory(email="heidi@example.com")
    with freeze_time("2026-01-01 00:00:00"):
        token = security.create_access_token(
            user.email, expires_delta=timedelta(seconds=1)
        )
    with freeze_time("2026-01-01 00:00:05"):
        resp = await client.get(
            f"{api_prefix}/auth/me", headers={"Authorization": f"Bearer {token}"}
        )

    assert resp.status_code == 401


async def test_me_unknown_user_in_sub_rejected(client, api_prefix):
    # A syntactically valid, correctly-typed, correctly-signed token for an
    # email that was never registered.
    token = security.create_access_token("ghost-user-never-registered@example.com")

    resp = await client.get(
        f"{api_prefix}/auth/me", headers={"Authorization": f"Bearer {token}"}
    )

    assert resp.status_code == 401


async def test_me_token_missing_sub_claim_rejected(client, api_prefix):
    token = jwt.encode(
        {"type": "access", "exp": 9999999999},
        settings.SECRET_KEY,
        algorithm=settings.ALGORITHM,
    )

    resp = await client.get(
        f"{api_prefix}/auth/me", headers={"Authorization": f"Bearer {token}"}
    )

    assert resp.status_code == 401
