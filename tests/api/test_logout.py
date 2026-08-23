"""
OBJ-002 Story 1 -- POST /auth/logout. Traces to
docs/requirements/obj-002-session-token-lifecycle.md Scenarios 1.1-1.5 and
docs/api/openapi.yaml path `/auth/logout` / docs/api/obj-002-design-notes.md
section 4.

IMPORTANT divergence from the raw Gherkin AC, per the approved Gate 1
decisions (.ai-context/dependency_graph.md, 2026-08-21) and openapi.yaml's
finalized contract -- these tests assert the APPROVED design, not the AC's
original proposed status codes:

- Scenario 1.3 ("expired token") and Scenario 1.4 ("invalid/malformed
  token") both originally proposed 401 as one option. The approved design
  instead makes /auth/logout ALWAYS return 204 for any well-formed request
  body, regardless of token validity -- no oracle. Only a request body that
  fails schema validation (missing `refresh_token` field) is 422.
- Scenario 1.5 ("logout without credentials") originally proposed 401.
  Since /auth/logout authenticates purely via the JSON body (no
  Authorization header requirement -- design notes section 4), "without
  credentials" here means a request body missing `refresh_token` entirely,
  which is a 422 schema-validation failure, not a 401.

Requires Postgres -- see tests/README.md / tests/conftest.py module
docstring.
"""

from freezegun import freeze_time


async def _login(client, api_prefix, email, password):
    resp = await client.post(
        f"{api_prefix}/auth/login",
        data={"username": email, "password": password},
    )
    assert resp.status_code == 200, resp.text
    return resp.json()


async def test_scenario_1_1_logout_with_valid_refresh_token_returns_204(
    client, api_prefix, user_factory
):
    user, password = await user_factory(email="logout-happy@example.com")
    tokens = await _login(client, api_prefix, user.email, password)

    resp = await client.post(
        f"{api_prefix}/auth/logout",
        json={"refresh_token": tokens["refresh_token"]},
    )

    assert resp.status_code == 204
    assert resp.content == b""


async def test_scenario_1_2_refresh_token_revoked_by_logout_rejected_on_refresh(
    client, api_prefix, user_factory
):
    """Logging out a session must make its refresh token unusable on a
    subsequent /auth/refresh call -- the actual point of the endpoint."""
    user, password = await user_factory(email="logout-then-refresh@example.com")
    tokens = await _login(client, api_prefix, user.email, password)

    logout_resp = await client.post(
        f"{api_prefix}/auth/logout",
        json={"refresh_token": tokens["refresh_token"]},
    )
    assert logout_resp.status_code == 204

    refresh_resp = await client.post(
        f"{api_prefix}/auth/refresh",
        json={"refresh_token": tokens["refresh_token"]},
    )

    assert refresh_resp.status_code == 401
    assert "access_token" not in refresh_resp.json()


async def test_scenario_1_3_logout_with_naturally_expired_refresh_token_is_204(
    client, api_prefix, user_factory
):
    user, password = await user_factory(email="logout-expired@example.com")
    with freeze_time("2026-01-01 00:00:00"):
        tokens = await _login(client, api_prefix, user.email, password)

    with freeze_time("2026-01-08 00:00:01"):  # past REFRESH_TOKEN_EXPIRE_DAYS=7
        resp = await client.post(
            f"{api_prefix}/auth/logout",
            json={"refresh_token": tokens["refresh_token"]},
        )

    assert resp.status_code == 204, (
        "an expired refresh token must still be accepted idempotently by "
        "/auth/logout -- the caller's desired end state already holds "
        "(openapi.yaml /auth/logout description)"
    )


async def test_scenario_1_4_logout_with_malformed_token_is_204(client, api_prefix):
    resp = await client.post(
        f"{api_prefix}/auth/logout",
        json={"refresh_token": "not-a-jwt-at-all"},
    )

    assert resp.status_code == 204, (
        "a malformed/garbage token is not a schema-validation failure (the "
        "field IS present, it's just not a valid JWT) -- must still be "
        "idempotent 204, per design notes section 4"
    )


async def test_logout_with_wrong_type_token_is_204(client, api_prefix, user_factory):
    """A well-formed, correctly-signed ACCESS token submitted as the
    refresh_token body field is still 204, not 401/422 -- design notes
    section 4 explicitly lists 'a well-formed JWT of the wrong type' among
    the cases sharing the idempotent 204."""
    user, password = await user_factory(email="logout-wrong-type@example.com")
    tokens = await _login(client, api_prefix, user.email, password)

    resp = await client.post(
        f"{api_prefix}/auth/logout",
        json={"refresh_token": tokens["access_token"]},
    )

    assert resp.status_code == 204


async def test_scenario_1_5_logout_missing_refresh_token_field_is_422(
    client, api_prefix
):
    resp = await client.post(f"{api_prefix}/auth/logout", json={})
    assert resp.status_code == 422


async def test_logout_is_idempotent_across_repeated_calls(
    client, api_prefix, user_factory
):
    user, password = await user_factory(email="logout-idempotent@example.com")
    tokens = await _login(client, api_prefix, user.email, password)

    first = await client.post(
        f"{api_prefix}/auth/logout", json={"refresh_token": tokens["refresh_token"]}
    )
    second = await client.post(
        f"{api_prefix}/auth/logout", json={"refresh_token": tokens["refresh_token"]}
    )

    assert first.status_code == 204
    assert second.status_code == 204, "a repeated logout call must not error"


async def test_logout_only_revokes_the_submitted_session_not_other_devices(
    client, api_prefix, user_factory
):
    """OBJ-002 dispatch task item 7 / design notes section 4: logout
    invalidates exactly one refresh_sessions row (the submitted jti), not
    the whole family and not sibling device sessions."""
    user, password = await user_factory(email="logout-multisession@example.com")
    device_a = await _login(client, api_prefix, user.email, password)
    device_b = await _login(client, api_prefix, user.email, password)

    logout_resp = await client.post(
        f"{api_prefix}/auth/logout",
        json={"refresh_token": device_a["refresh_token"]},
    )
    assert logout_resp.status_code == 204

    # Device A's session is dead...
    a_refresh = await client.post(
        f"{api_prefix}/auth/refresh",
        json={"refresh_token": device_a["refresh_token"]},
    )
    assert a_refresh.status_code == 401

    # ...but Device B's independent session (a separate family from a
    # separate login) is untouched.
    b_refresh = await client.post(
        f"{api_prefix}/auth/refresh",
        json={"refresh_token": device_b["refresh_token"]},
    )
    assert b_refresh.status_code == 200, (
        "logging out one device's session must not affect an independent "
        "session from a second login (different family_id)"
    )
