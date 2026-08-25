"""
OBJ-005 Story 2 -- Gate 1 decision 1 (Option A, block unverified users),
implemented per docs/api/obj-005-design-notes.md section 3 as a
distinguishable `400 "Email not verified"` at BOTH /auth/login and
/auth/refresh, extending the existing, already-Gate-3-reviewed `is_active`
precedent by one predicate. Login/refresh enforcement mechanics were
ADOPTED without a separate user ask (dependency_graph.md, 2026-08-24) --
this file tests exactly that adopted mechanics, not the requirements doc's
own stricter literal AC (Scenario 2.A.1's byte-identical-response wording),
per design notes section 3.2's documented, reasoned override.

Deliberately NOT checked at /auth/me (design notes section 3.3, Scenario
2.A.3): an already-issued access token must keep working even if
is_verified is reverted after issuance -- enforcement gates NEW session
issuance (login, refresh), not existing sessions. The single most
regression-prone mistake here would be adding the is_verified check inside
`get_current_user`/`get_current_active_user` instead of only at
login/refresh -- test_me_endpoint_does_not_reject_an_unverified_user_with_a_pre_existing_access_token
below is the dedicated guard for that, and is EXPECTED TO ALREADY PASS
today (same 'documented already-green baseline, must not regress'
convention as every prior objective's Gate-3-reviewed-precedent tests) --
its value is purely as a regression trap for Phase 3, not as a red-phase
proof of anything new.

------------------------------------------------------------------------
CRITICAL CROSS-CUTTING RISK, FLAGGED HERE FOR developer's Phase 3 pass
(NOT fixed in this file -- out of this file's scope per task instructions
to keep shared-fixture changes additive-only, and tests/factories.py is a
shared file used by every other objective's already-authored test files):
------------------------------------------------------------------------
tests/factories.py's `create_user` defaults to `is_verified=False`. EVERY
existing test file in this suite (tests/api/test_refresh_rotation.py,
test_token_type_enforcement.py, test_logout.py, test_password_reset_
invalidation.py, test_timing_side_channel.py, test_rate_limit_ip_spoofing.py,
test_audit_logging.py, and others) calls `user_factory(...)` WITHOUT ever
passing `is_verified=True`, then logs that user in via /auth/login to
exercise its own scenario. Confirmed via grep across tests/api/ and
tests/unit/: zero existing test files pass `is_verified=True` anywhere.

Once this objective's Phase 3 lands the /auth/login enforcement this file
tests, EVERY ONE of those pre-existing, currently-green logins will start
failing with 400 "Email not verified" instead of 200 -- a suite-wide
regression across OBJ-001/002/003/004's test files, not a hypothetical
edge case. This is a genuine testability/design gap this pass discovered,
not present in any prior design document.

Recommended fix, for developer to apply AS PART OF Phase 3 (matching this
project's established precedent of implementation-adjacent factory updates,
e.g. OBJ-003's mandatory hash_otp update to tests/factories.py's
create_verification): change `create_user`'s default to `is_verified=True`
in tests/factories.py, and update the one existing test that explicitly
asserts the OLD default (`tests/api/test_me_endpoint.py:39`,
`assert body["is_verified"] is False`) to either pass `is_verified=False`
explicitly or assert `True`. This file's own tests below all pass
`is_verified=` explicitly regardless of the shared default, so they are
correct either way -- this note is about the OTHER ~13 files' passive
reliance on today's default, not about this file's own tests.
------------------------------------------------------------------------

Requires Postgres -- see tests/README.md / tests/conftest.py module
docstring.
"""

from unittest.mock import patch

from app.core import security

UNVERIFIED_DETAIL = "Email not verified"


async def _login(client, api_prefix, email, password):
    return await client.post(
        f"{api_prefix}/auth/login", data={"username": email, "password": password}
    )


async def test_login_blocked_for_unverified_user_with_correct_password(
    client, api_prefix, user_factory
):
    """Scenario 2.A.1 (as resolved by design notes section 3.2's adopted
    mechanics: distinguishable 400, not a fully generic response)."""
    user, password = await user_factory(
        email="login-unverified@example.com", is_verified=False
    )

    resp = await _login(client, api_prefix, user.email, password)

    assert resp.status_code == 400, (
        f"an unverified user with a CORRECT password must be blocked at "
        f"login (Gate 1 decision 1, Option A) -- got {resp.status_code}: "
        f"{resp.text}"
    )
    assert resp.json()["detail"] == UNVERIFIED_DETAIL
    assert "access_token" not in resp.json() and "refresh_token" not in resp.json()


async def test_login_succeeds_normally_for_a_verified_user(
    client, api_prefix, user_factory
):
    """Scenario 2.A.2. Expected to already pass today (is_verified isn't
    checked at all yet) -- kept as an explicit regression anchor: adding
    the new is_verified branch must not accidentally block VERIFIED users
    too."""
    user, password = await user_factory(email="login-verified@example.com", is_verified=True)

    resp = await _login(client, api_prefix, user.email, password)

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert "access_token" in body and "refresh_token" in body


async def test_login_wrong_password_for_unverified_user_still_returns_generic_credentials_error(
    client, api_prefix, user_factory
):
    """The is_verified check must sit AFTER credential validation (design
    notes section 3.2: 'positioned immediately after the existing
    is_active check' -- itself after verify_password_or_dummy). A WRONG
    password for an unverified user must get the ordinary bad-credentials
    400, never the unverified-specific message -- otherwise a wrong-
    password attempt against an unverified account would leak, via the
    response text alone, that the account exists but merely isn't
    verified, without the attacker ever having proven they know the
    password."""
    user, _ = await user_factory(email="login-unverified-wrongpw@example.com", is_verified=False)

    resp = await _login(client, api_prefix, user.email, "DefinitelyWrongPass1!")

    assert resp.status_code == 400
    assert resp.json()["detail"] == "Incorrect email or password", (
        f"a WRONG password must never reveal the unverified state -- got "
        f"detail={resp.json().get('detail')!r}"
    )


async def test_login_still_calls_verify_password_or_dummy_exactly_once_for_unverified_user(
    client, api_prefix, user_factory
):
    """Design notes section 6 / section 3.2: 'assert
    security.verify_password_or_dummy's call count/target at /login... for
    any test touching the is_verified branch's interaction with finding
    #5's guarantee.' Structural, not wall-clock timing -- same convention
    as tests/api/test_timing_side_channel.py. Proves the new is_verified
    branch sits AFTER the bcrypt call (so finding #5's guarantee -- bcrypt
    always runs exactly once -- is not reopened by this objective) rather
    than being used to short-circuit past it."""
    user, password = await user_factory(
        email="login-unverified-timing@example.com", is_verified=False
    )

    with patch(
        "app.core.security.verify_password", wraps=security.verify_password
    ) as mock_verify:
        resp = await _login(client, api_prefix, user.email, password)

    assert resp.status_code == 400
    assert resp.json()["detail"] == UNVERIFIED_DETAIL
    assert mock_verify.call_count == 1, (
        f"the bcrypt verify must still run exactly once for an unverified "
        f"user with a CORRECT password -- was called "
        f"{mock_verify.call_count} time(s). If this is 0, the is_verified "
        f"check has been placed BEFORE the password check, reopening "
        f"finding #5's timing side-channel for unverified accounts."
    )
    called_target_hash = mock_verify.call_args.args[1]
    assert called_target_hash == user.hashed_password, (
        "the bcrypt verify must target the real user's hash, not the "
        "dummy hash -- this user genuinely exists"
    )


async def test_refresh_blocked_when_the_owning_users_is_verified_becomes_false(
    client, api_prefix, user_factory, db_session
):
    """Scenario 2.A.3 + 2.A.4: a refresh token obtained while VERIFIED,
    whose owning user is later (hypothetically) reverted to unverified,
    must be rejected by /auth/refresh -- 'the refresh token also cannot be
    used to refresh' (2.A.3), 'no new access token is issued' (2.A.4).
    Directly mutates User.is_verified via db_session (the SAME session the
    client fixture overrides deps.get_db with, per this project's
    established direct-DB-mutation convention -- see
    tests/api/test_password_reset_invalidation.py) to simulate the
    'hypothetically, via admin endpoint or debugging scenario' framing in
    the requirements doc, since there is no real endpoint that flips
    is_verified back to False."""
    user, password = await user_factory(
        email="refresh-unverified-after-issuance@example.com", is_verified=True
    )
    login_resp = await _login(client, api_prefix, user.email, password)
    assert login_resp.status_code == 200, login_resp.text
    refresh_token = login_resp.json()["refresh_token"]

    user.is_verified = False
    db_session.add(user)
    await db_session.commit()

    resp = await client.post(
        f"{api_prefix}/auth/refresh", json={"refresh_token": refresh_token}
    )

    assert resp.status_code == 400, (
        f"a refresh token belonging to a now-unverified user must be "
        f"rejected -- got {resp.status_code}: {resp.text}"
    )
    assert resp.json()["detail"] == UNVERIFIED_DETAIL


async def test_refresh_still_succeeds_for_a_verified_users_valid_token(
    client, api_prefix, user_factory
):
    """Regression anchor: verified users' refresh flow must be completely
    unaffected. Expected to already pass today."""
    user, password = await user_factory(email="refresh-verified@example.com", is_verified=True)
    login_resp = await _login(client, api_prefix, user.email, password)
    assert login_resp.status_code == 200, login_resp.text

    resp = await client.post(
        f"{api_prefix}/auth/refresh",
        json={"refresh_token": login_resp.json()["refresh_token"]},
    )

    assert resp.status_code == 200, resp.text
    assert "access_token" in resp.json() and "refresh_token" in resp.json()


async def test_me_endpoint_does_not_reject_an_unverified_user_with_a_pre_existing_access_token(
    client, api_prefix, user_factory, db_session
):
    """Scenario 2.A.3 / design notes section 3.3 -- the regression GUARD
    for over-broad enforcement. Expected to ALREADY PASS today (no
    is_verified check exists anywhere yet) -- its value is proving this
    stays true once /auth/login and /auth/refresh gain their own checks:
    if a future change accidentally adds an is_verified check inside
    get_current_user/get_current_active_user (rather than only at
    login/refresh), THIS is the test that catches it.
    """
    user, _ = await user_factory(
        email="me-unverified-existing-token@example.com", is_verified=True
    )
    access_token = security.create_access_token(user.email, ver=user.token_version)

    # Simulate the hypothetical downgrade described in Scenario 2.A.3,
    # AFTER the token was already issued.
    user.is_verified = False
    db_session.add(user)
    await db_session.commit()

    resp = await client.get(
        f"{api_prefix}/auth/me", headers={"Authorization": f"Bearer {access_token}"}
    )

    assert resp.status_code == 200, (
        f"an already-issued access token must remain usable at /auth/me "
        f"even if the user's is_verified is later reverted to False -- "
        f"is_verified is an auditing gate on NEW session issuance only, "
        f"never baked into get_current_user's core claim checks (matches "
        f"is_active's own identical scope). Got {resp.status_code}: "
        f"{resp.text}"
    )
    assert resp.json()["is_verified"] is False, (
        "the response DOES reflect the current (now-False) DB value -- "
        "/auth/me is not rejecting the request, but it also isn't lying "
        "about the user's current state"
    )
