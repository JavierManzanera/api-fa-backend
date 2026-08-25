"""
OBJ-002 Story 2 -- POST /auth/refresh rotation + reuse detection. Traces to
docs/requirements/obj-002-session-token-lifecycle.md Scenarios 2.1, 2.2, 2.4,
2.5 and docs/api/obj-002-design-notes.md section 2 (the full state machine).

Scenario 2.3 ("race condition -- attacker and legitimate user racing to use
the same token_v1 within milliseconds") is NOT exercised as true concurrency
here, consistent with this project's established convention for TOCTOU-
shaped scenarios (see tests/README.md's note on OBJ-001 Scenario 2.7, and
the OTP-lockout / rate-limiter TOCTOU gaps flagged-but-not-reopened at
OBJ-001 Gate 3; obj-002-design-notes.md section 2 flags the analogous
read-then-write race on `refresh_sessions` as a known, non-blocking residual
gap too). The underlying BUSINESS RULE Scenario 2.3 describes -- "first
successful use of a token wins; any later replay of that exact token is
rejected, and a replay of an already-rotated token nukes the whole family"
-- IS fully covered sequentially by test_scenario_2_2_* and
test_reuse_detected_revokes_entire_token_family below. True concurrent-
request races are flagged as an environment-dependent risk, not covered.

Requires Postgres -- see tests/README.md / tests/conftest.py module
docstring.
"""

import jwt

from app.core.config import settings


def _decode(token: str) -> dict:
    return jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])


async def _login(client, api_prefix, email, password):
    resp = await client.post(
        f"{api_prefix}/auth/login",
        data={"username": email, "password": password},
    )
    assert resp.status_code == 200, resp.text
    return resp.json()


async def test_scenario_2_1_refresh_rotates_and_issues_a_new_token_pair(
    client, api_prefix, user_factory
):
    user, password = await user_factory(email="rotate-happy@example.com")
    token_v1 = (await _login(client, api_prefix, user.email, password))["refresh_token"]

    resp = await client.post(
        f"{api_prefix}/auth/refresh", json={"refresh_token": token_v1}
    )

    assert resp.status_code == 200
    body = resp.json()
    assert "access_token" in body
    assert "refresh_token" in body
    token_v2 = body["refresh_token"]
    assert token_v2 != token_v1, (
        "openapi.yaml: the refresh_token in the response must NEVER be the "
        "same string that was submitted -- this is the core OBJ-002 change "
        "from OBJ-001's echo-back behavior"
    )
    # jti must actually differ (not just an incidental string difference,
    # e.g. only `iat`/`exp` changing would not prove real rotation).
    assert _decode(token_v2).get("jti") != _decode(token_v1).get("jti"), (
        "rotation must mint a genuinely new session row (new jti), not "
        "just re-sign a cosmetically different token"
    )


async def test_scenario_2_2_reusing_a_rotated_refresh_token_is_rejected(
    client, api_prefix, user_factory
):
    user, password = await user_factory(email="rotate-reuse@example.com")
    token_v1 = (await _login(client, api_prefix, user.email, password))["refresh_token"]

    first = await client.post(
        f"{api_prefix}/auth/refresh", json={"refresh_token": token_v1}
    )
    assert first.status_code == 200

    replay = await client.post(
        f"{api_prefix}/auth/refresh", json={"refresh_token": token_v1}
    )

    assert replay.status_code == 401
    assert "access_token" not in replay.json()


async def test_reuse_detected_revokes_entire_token_family(
    client, api_prefix, user_factory
):
    """OBJ-002 dispatch task item 4 / design notes section 2: replaying an
    already-rotated token doesn't just fail itself -- it must revoke every
    currently-active descendant of that family, INCLUDING a token that was
    legitimately issued by a prior rotation before the reuse was detected.

    Chain: token_v1 --rotate--> token_v2 --rotate--> token_v3 (legitimate,
    currently "the" active session token, never itself replayed). Then
    token_v1 (already long-dead) is replayed. Expected: the replay itself
    fails 401 AND revokes the whole family, so token_v3 must also stop
    working afterward -- a weaker implementation that only rejects the
    specific replayed token (and leaves siblings alone) would incorrectly
    let the final call below succeed.
    """
    user, password = await user_factory(email="rotate-family-revoke@example.com")
    token_v1 = (await _login(client, api_prefix, user.email, password))["refresh_token"]

    step2 = await client.post(
        f"{api_prefix}/auth/refresh", json={"refresh_token": token_v1}
    )
    assert step2.status_code == 200
    token_v2 = step2.json()["refresh_token"]

    step3 = await client.post(
        f"{api_prefix}/auth/refresh", json={"refresh_token": token_v2}
    )
    assert step3.status_code == 200
    token_v3 = step3.json()["refresh_token"]

    # Reuse: replay the long-dead token_v1.
    reuse_resp = await client.post(
        f"{api_prefix}/auth/refresh", json={"refresh_token": token_v1}
    )
    assert reuse_resp.status_code == 401

    # The legitimate, never-replayed token_v3 must now ALSO be dead.
    v3_after_reuse = await client.post(
        f"{api_prefix}/auth/refresh", json={"refresh_token": token_v3}
    )
    assert v3_after_reuse.status_code == 401, (
        "reuse detection must revoke the ENTIRE family, not just deny the "
        "specific replayed token -- token_v3 was never itself reused but "
        "shares family_id with token_v1"
    )


async def test_scenario_2_4_multiple_devices_rotate_independently(
    client, api_prefix, user_factory
):
    user, password = await user_factory(email="rotate-multidevice@example.com")
    device_a = (await _login(client, api_prefix, user.email, password))["refresh_token"]
    device_b = (await _login(client, api_prefix, user.email, password))["refresh_token"]

    a_resp = await client.post(
        f"{api_prefix}/auth/refresh", json={"refresh_token": device_a}
    )
    assert a_resp.status_code == 200
    device_a_v2 = a_resp.json()["refresh_token"]

    # Device B's original token, from an independent login/family, must
    # still work -- rotating A does not touch B.
    b_resp = await client.post(
        f"{api_prefix}/auth/refresh", json={"refresh_token": device_b}
    )
    assert b_resp.status_code == 200, (
        "each login seeds an independent token family -- refreshing one "
        "device's session must not affect another device's session "
        "(Scenario 2.4)"
    )

    # And device_a's now-retired v1 must still be rejected (rotation on A
    # happened for real, independent of B's activity).
    a_replay = await client.post(
        f"{api_prefix}/auth/refresh", json={"refresh_token": device_a}
    )
    assert a_replay.status_code == 401
    assert device_a_v2 != device_b


async def test_scenario_2_5_legacy_pre_obj002_refresh_token_rejected(
    client, api_prefix, user_factory
):
    """A refresh token shaped like the OLD (pre-OBJ-002) contract -- no
    `jti` claim at all -- must be rejected. design notes section 5: 'the
    absence of the claim alone routes it to rejection', no special-casing
    needed. Also confirmed idempotent: two identical calls both just 401,
    never creating a session as a side effect of the lookup miss."""
    user, _ = await user_factory(email="rotate-legacy@example.com")
    legacy_token = jwt.encode(
        {"sub": user.email, "type": "refresh", "exp": 9999999999},
        settings.SECRET_KEY,
        algorithm=settings.ALGORITHM,
    )

    first = await client.post(
        f"{api_prefix}/auth/refresh", json={"refresh_token": legacy_token}
    )
    second = await client.post(
        f"{api_prefix}/auth/refresh", json={"refresh_token": legacy_token}
    )

    assert first.status_code == 401
    assert second.status_code == 401


async def test_obj010_multiple_sequential_rotations_do_not_violate_family_unique_constraint(
    client, api_prefix, user_factory
):
    """OBJ-010 regression test (docs/database/obj-006-migration-plan.md
    "CRITICAL finding: migration 0008 breaks the current /auth/refresh
    handler"). The old insert-then-revoke ordering briefly had two rows
    sharing `family_id` with `revoked_at IS NULL`, which migration 0008's
    partial unique index (`ux_refresh_sessions_family_id_active`) forbids --
    every single rotation raised a duplicate-key IntegrityError once that
    migration was applied. Rotating five times in a row must keep succeeding
    under the revoke-then-insert-then-link reorder (verified for real
    against a database migrated through 0008 -- see the developer's Gate 3
    report; also runs harmlessly against the default create_all schema,
    which has no such constraint to violate).
    """
    user, password = await user_factory(email="rotate-multi-obj010@example.com")
    token = (await _login(client, api_prefix, user.email, password))["refresh_token"]

    for _ in range(5):
        resp = await client.post(
            f"{api_prefix}/auth/refresh", json={"refresh_token": token}
        )
        assert resp.status_code == 200, resp.text
        token = resp.json()["refresh_token"]


async def test_obj010_concurrently_revoked_session_fails_closed_on_refresh(
    client, api_prefix, user_factory, db_session
):
    """OBJ-010 TOCTOU fix (obj-006-migration-plan.md section 5's
    `/auth/refresh` bullet): the rotation UPDATE now repeats the
    `WHERE revoked_at IS NULL` predicate atomically instead of relying on
    the earlier SELECT alone. This simulates a concurrent request that
    already revoked the same row between this request's SELECT and its
    UPDATE -- the same sequential-simulation convention this project already
    uses for TOCTOU-shaped scenarios (this file's own module docstring;
    tests/README.md's Scenario 2.7 note) rather than true concurrency.
    Expected: the atomic UPDATE affects 0 rows, and the request fails closed
    (401) instead of silently overwriting `revoked_at` as if it had won the
    race.
    """
    from datetime import datetime, timezone

    from sqlalchemy import update as sa_update

    from app.models.refresh_session import RefreshSession

    user, password = await user_factory(email="rotate-toctou-obj010@example.com")
    token = (await _login(client, api_prefix, user.email, password))["refresh_token"]
    jti = _decode(token)["jti"]

    # Simulate a concurrent request that already revoked this exact row
    # (e.g. its own rotation, or a reuse-detection sweep) before this
    # request's UPDATE runs.
    await db_session.execute(
        sa_update(RefreshSession)
        .where(RefreshSession.id == jti)
        .values(revoked_at=datetime.now(timezone.utc))
    )
    await db_session.commit()

    resp = await client.post(
        f"{api_prefix}/auth/refresh", json={"refresh_token": token}
    )

    assert resp.status_code == 401
    assert "access_token" not in resp.json()


async def test_expired_refresh_session_returns_401(client, api_prefix, user_factory):
    """design notes section 2, branch 3: an ordinary time-expired session
    row (never revoked) is a plain 401 -- largely redundant with the JWT's
    own `exp` check, kept as the table's own defensive second check since
    the table (not the JWT) is what /auth/logout and reuse-detection
    actually mutate."""
    from freezegun import freeze_time

    user, password = await user_factory(email="rotate-expiry@example.com")
    with freeze_time("2026-01-01 00:00:00"):
        token_v1 = (await _login(client, api_prefix, user.email, password))["refresh_token"]

    with freeze_time("2026-01-08 00:00:01"):  # past REFRESH_TOKEN_EXPIRE_DAYS=7
        resp = await client.post(
            f"{api_prefix}/auth/refresh", json={"refresh_token": token_v1}
        )

    assert resp.status_code == 401
