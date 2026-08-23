"""
OBJ-002 Story 3 -- /auth/reset-password bulk token invalidation. Traces to
docs/requirements/obj-002-session-token-lifecycle.md Scenarios 3.1-3.4, 3.6
and docs/api/obj-002-design-notes.md section 3 (`ver` claim design) / the
Gate 1 decision that bulk `refresh_sessions` revocation on reset is
MANDATORY, not merely a recommendation (.ai-context/dependency_graph.md,
2026-08-21).

Scenario 3.5 (forging a `ver` claim equal to a FUTURE token_version,
exploiting the fact that `ver`-only comparison can't by itself distinguish
a legitimately-reissued token from a lucky/guessed claim without an
additional `iat > password_reset_at` check) is EXPLICITLY OUT OF SCOPE for
this pass. obj-002-design-notes.md section 3 documents only the plain
`ver`-vs-`token_version` comparison (piggybacked on the existing
`get_current_user` DB read) and does NOT introduce an `iat`/
`password_reset_at` check anywhere -- the requirements doc's own Scenario
3.5 explicitly defers that decision ("This decision is deferred to
solution-architect in Phase 1 -- do not implement without clarifying the
iat-based validation strategy"), and solution-architect's Phase 1 output did
not pick it up. Testing it now would test a mechanism nobody committed to
building. Flagged here, not silently dropped -- pick up if this residual
gap is ever prioritized in a future objective.

Requires Postgres -- see tests/README.md / tests/conftest.py module
docstring.
"""


async def _login(client, api_prefix, email, password):
    resp = await client.post(
        f"{api_prefix}/auth/login",
        data={"username": email, "password": password},
    )
    assert resp.status_code == 200, resp.text
    return resp.json()


async def _reset_password(
    client, api_prefix, verification_factory, email, otp, new_password
):
    await verification_factory(email=email, code=otp)
    resp = await client.post(
        f"{api_prefix}/auth/reset-password",
        json={"email": email, "otp": otp, "new_password": new_password},
    )
    assert resp.status_code == 200, resp.text
    return resp


async def test_scenario_3_1_token_version_increments_on_reset(
    client, api_prefix, user_factory, verification_factory, db_session
):
    user, _ = await user_factory(email="reset-version@example.com")
    assert getattr(user, "token_version", 0) == 0

    await _reset_password(
        client, api_prefix, verification_factory, user.email, "111111", "NewValidPass123!"
    )

    await db_session.refresh(user)
    assert user.token_version == 1, (
        "Scenario 3.1: a successful /auth/reset-password must increment "
        "User.token_version"
    )


async def test_scenario_3_2_old_access_token_rejected_after_reset(
    client, api_prefix, user_factory, verification_factory
):
    user, password = await user_factory(email="reset-old-access@example.com")
    old_access_token = (await _login(client, api_prefix, user.email, password))[
        "access_token"
    ]

    await _reset_password(
        client, api_prefix, verification_factory, user.email, "222222", "NewValidPass123!"
    )

    resp = await client.get(
        f"{api_prefix}/auth/me",
        headers={"Authorization": f"Bearer {old_access_token}"},
    )
    assert resp.status_code == 401, (
        "an access token issued before the reset carries the OLD "
        "token_version and must be rejected even though it hasn't "
        "naturally expired yet"
    )


async def test_scenario_3_3_old_refresh_token_rejected_after_reset(
    client, api_prefix, user_factory, verification_factory
):
    user, password = await user_factory(email="reset-old-refresh@example.com")
    old_refresh_token = (await _login(client, api_prefix, user.email, password))[
        "refresh_token"
    ]

    await _reset_password(
        client, api_prefix, verification_factory, user.email, "333333", "NewValidPass123!"
    )

    resp = await client.post(
        f"{api_prefix}/auth/refresh", json={"refresh_token": old_refresh_token}
    )
    assert resp.status_code == 401
    assert "access_token" not in resp.json()


async def test_scenario_3_4_all_active_sessions_invalidated_by_one_reset(
    client, api_prefix, user_factory, verification_factory
):
    user, password = await user_factory(email="reset-multisession@example.com")
    device_a = await _login(client, api_prefix, user.email, password)
    device_b = await _login(client, api_prefix, user.email, password)
    device_c = await _login(client, api_prefix, user.email, password)

    await _reset_password(
        client, api_prefix, verification_factory, user.email, "444444", "NewValidPass123!"
    )

    for device in (device_a, device_b, device_c):
        me_resp = await client.get(
            f"{api_prefix}/auth/me",
            headers={"Authorization": f"Bearer {device['access_token']}"},
        )
        assert me_resp.status_code == 401

        refresh_resp = await client.post(
            f"{api_prefix}/auth/refresh",
            json={"refresh_token": device["refresh_token"]},
        )
        assert refresh_resp.status_code == 401

    # And the user really can re-authenticate to get fresh V+1 tokens.
    relogin = await client.post(
        f"{api_prefix}/auth/login",
        data={"username": user.email, "password": "NewValidPass123!"},
    )
    assert relogin.status_code == 200


async def test_scenario_3_6_logout_then_reset_both_devices_end_up_invalidated(
    client, api_prefix, user_factory, verification_factory
):
    """Story 3.6: token_A (Device A) is revoked via /auth/logout (the
    revocation-store path); token_B (Device B) is only ever revoked later,
    via reset-password's bulk revoke + version bump. Both must end up
    unusable, and the reset call must not error over token_A already being
    revoked (no duplicate-revocation conflict)."""
    user, password = await user_factory(email="reset-after-logout@example.com")
    device_a = await _login(client, api_prefix, user.email, password)
    device_b = await _login(client, api_prefix, user.email, password)

    logout_resp = await client.post(
        f"{api_prefix}/auth/logout",
        json={"refresh_token": device_a["refresh_token"]},
    )
    assert logout_resp.status_code == 204

    await _reset_password(
        client, api_prefix, verification_factory, user.email, "666666", "NewValidPass123!"
    )

    a_resp = await client.post(
        f"{api_prefix}/auth/refresh",
        json={"refresh_token": device_a["refresh_token"]},
    )
    assert a_resp.status_code == 401, (
        "token_A: doubly revoked (logout AND reset) -- still just a plain "
        "401, no crash from acting on an already-revoked row twice"
    )

    b_resp = await client.post(
        f"{api_prefix}/auth/refresh",
        json={"refresh_token": device_b["refresh_token"]},
    )
    assert b_resp.status_code == 401, "token_B: only ever revoked via reset's bulk path"


async def test_rapid_successive_resets_each_increment_version_not_idempotently(
    client, api_prefix, user_factory, verification_factory, db_session
):
    """Edge case section of the requirements doc: two /auth/reset-password
    calls in sequence, each with its own valid OTP, must each increment
    token_version -- not collapse into a single bump."""
    user, _ = await user_factory(email="reset-rapid@example.com")

    await _reset_password(
        client, api_prefix, verification_factory, user.email, "777777", "NewValidPass123!"
    )
    await db_session.refresh(user)
    assert user.token_version == 1

    await _reset_password(
        client, api_prefix, verification_factory, user.email, "888888", "AnotherValidPass123!"
    )
    await db_session.refresh(user)
    assert user.token_version == 2, (
        "a second, independent reset-password call must increment the "
        "counter again, not leave it at 1"
    )
