"""
OBJ-005 Story 1 -- POST /auth/verify-email. Traces to
docs/requirements/obj-005-email-verification-flow.md Scenarios 1.2, 1.3, 1.4,
1.5, 1.8 (partial) and docs/api/obj-005-design-notes.md section 2.1 / section
1.1 (generalized `_check_and_consume_otp`, `purpose="email_verification"`).

This endpoint does not exist yet in app/api/v1/endpoints/auth.py -- every
test in this file is expected to fail 404 today (RED, for the right reason:
missing route, not a broken test). Once implemented, this reuses the exact
same `_check_and_consume_otp` mechanism as /auth/verify-otp
(purpose-scoped, shared-attempts-budget, generic-400, no distinguishable
lockout signal) but CONSUMES the row on success (deletes it, sets
User.is_verified = True) rather than /auth/verify-otp's check-without-
consuming -- see design notes section 2.1.

Purpose-budget isolation from /auth/verify-otp's `reset_password` purpose is
NOT tested here -- that is the dedicated, highest-value cross-purpose test
in tests/api/test_verification_purpose_isolation.py, not duplicated in this
file.

Requires Postgres -- see tests/README.md / tests/conftest.py module
docstring.
"""

from freezegun import freeze_time

MAX_OTP_ATTEMPTS = 5
VERIFY_EMAIL_RATE_LIMIT_PER_MINUTE = 10
EMAIL_VERIFICATION_PURPOSE = "email_verification"


async def _seed_email_verification_code(
    verification_factory, *, email, code="123456", ttl_minutes=30
):
    return await verification_factory(
        email=email, code=code, purpose=EMAIL_VERIFICATION_PURPOSE, ttl_minutes=ttl_minutes
    )


async def test_verify_email_with_valid_code_returns_200_and_marks_user_verified(
    client, api_prefix, user_factory, verification_factory, db_session
):
    """Scenario 1.2: valid code -> 200, User.is_verified becomes True,
    response body contains user.id/email/is_verified=True (design notes
    section 2.1 point 4: reuses UserResponse, no tokens issued)."""
    user, _ = await user_factory(email="verify-email-valid@example.com", is_verified=False)
    await _seed_email_verification_code(verification_factory, email=user.email, code="654321")

    resp = await client.post(
        f"{api_prefix}/auth/verify-email",
        json={"email": user.email, "otp": "654321"},
    )

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["email"] == user.email
    assert body["is_verified"] is True
    assert "id" in body and "created_at" in body
    assert "access_token" not in body and "refresh_token" not in body, (
        "design notes section 2.1: 'No auto-login' -- the response must "
        "never include tokens"
    )

    await db_session.refresh(user)
    assert user.is_verified is True, (
        "the underlying User row must actually be updated, not just the "
        "HTTP response body"
    )


async def test_verify_email_deletes_the_verification_row_on_success(
    client, api_prefix, user_factory, verification_factory, db_session
):
    """Design notes section 2.1 point 3: 'delete the Verification row
    (matching /auth/reset-password's consume-and-delete pattern, not
    /auth/verify-otp's check-without-consuming pattern)'."""
    from sqlalchemy import select

    from app.models.verification import Verification

    user, _ = await user_factory(email="verify-email-consumed@example.com", is_verified=False)
    await _seed_email_verification_code(verification_factory, email=user.email, code="222333")

    resp = await client.post(
        f"{api_prefix}/auth/verify-email",
        json={"email": user.email, "otp": "222333"},
    )
    assert resp.status_code == 200, resp.text

    result = await db_session.execute(
        select(Verification).filter(
            Verification.email == user.email,
            Verification.purpose == EMAIL_VERIFICATION_PURPOSE,
        )
    )
    assert result.scalars().first() is None, (
        "a successfully-consumed email-verification row must be deleted, "
        "not merely marked used -- matches /auth/reset-password's pattern"
    )


async def test_verify_email_code_cannot_be_reused_after_success(
    client, api_prefix, user_factory, verification_factory
):
    """Scenario 1.5: replaying an already-consumed code must fail, and must
    NOT toggle is_verified back to False. Requires no special-casing per
    design notes section 2.1: the row is gone, so this falls into the
    ordinary 'no live row' generic-400 branch."""
    user, _ = await user_factory(email="verify-email-reuse@example.com", is_verified=False)
    await _seed_email_verification_code(verification_factory, email=user.email, code="777888")

    first = await client.post(
        f"{api_prefix}/auth/verify-email",
        json={"email": user.email, "otp": "777888"},
    )
    assert first.status_code == 200, first.text

    second = await client.post(
        f"{api_prefix}/auth/verify-email",
        json={"email": user.email, "otp": "777888"},
    )
    assert second.status_code == 400, (
        "Scenario 1.5: a replayed, already-consumed verification code must "
        "be rejected -- no side effects, no re-verification"
    )


async def test_verify_email_with_expired_code_rejected(
    client, api_prefix, user_factory, verification_factory
):
    """Scenario 1.3. Uses the objective's own TTL (30 minutes, design notes
    section 1.2) rather than password-reset's 10 -- freezegun makes the
    exact TTL length irrelevant to the test, but 31 minutes proves this
    endpoint's own configured window, not an accidental reuse of the
    password-reset constant."""
    user, _ = await user_factory(email="verify-email-expired@example.com", is_verified=False)

    with freeze_time("2026-01-01 00:00:00"):
        await _seed_email_verification_code(
            verification_factory, email=user.email, code="333444", ttl_minutes=30
        )

    with freeze_time("2026-01-01 00:31:00"):
        resp = await client.post(
            f"{api_prefix}/auth/verify-email",
            json={"email": user.email, "otp": "333444"},
        )

    assert resp.status_code == 400
    assert resp.json()["detail"] == "Invalid or expired verification code"


async def test_verify_email_with_wrong_code_rejected(
    client, api_prefix, user_factory, verification_factory
):
    """Scenario 1.4."""
    user, _ = await user_factory(email="verify-email-wrong@example.com", is_verified=False)
    await _seed_email_verification_code(verification_factory, email=user.email, code="555555")

    resp = await client.post(
        f"{api_prefix}/auth/verify-email",
        json={"email": user.email, "otp": "000000"},
    )

    assert resp.status_code == 400
    assert resp.json()["detail"] == "Invalid or expired verification code"


async def test_verify_email_error_message_is_distinct_from_verify_otps(
    client, api_prefix, user_factory
):
    """Design notes section 2.1: 'Decision: distinct message text from
    /verify-otp's ("Invalid or expired verification code" vs. "Invalid or
    expired OTP")'. No live row for either endpoint in this test -- a bare
    'no such code' case is enough to distinguish the two message strings."""
    user, _ = await user_factory(email="verify-email-message@example.com", is_verified=False)

    verify_email_resp = await client.post(
        f"{api_prefix}/auth/verify-email",
        json={"email": user.email, "otp": "999999"},
    )
    verify_otp_resp = await client.post(
        f"{api_prefix}/auth/verify-otp",
        json={"email": user.email, "otp": "999999"},
    )

    assert verify_email_resp.status_code == 400
    assert verify_otp_resp.status_code == 400
    assert verify_email_resp.json()["detail"] == "Invalid or expired verification code"
    assert verify_otp_resp.json()["detail"] == "Invalid or expired OTP"
    assert verify_email_resp.json()["detail"] != verify_otp_resp.json()["detail"], (
        "openapi.yaml / design notes section 2.1: the two endpoints must use "
        "distinct generic error text -- this is a UX clarity choice, not an "
        "oracle (the two purposes never share a response)"
    )


async def test_verify_email_locked_out_after_max_attempts_even_with_correct_code(
    client, api_prefix, user_factory, verification_factory
):
    """Mirrors tests/api/test_otp_lockout.py's
    test_scenario_2_3_locked_out_after_max_attempts_even_with_correct_code,
    scoped to purpose=email_verification -- same shared-attempts mechanism
    (design notes section 1.1), independently proven here for THIS
    endpoint's own purpose value."""
    user, _ = await user_factory(email="verify-email-lockout@example.com", is_verified=False)
    await _seed_email_verification_code(verification_factory, email=user.email, code="111222")

    for attempt in range(MAX_OTP_ATTEMPTS):
        resp = await client.post(
            f"{api_prefix}/auth/verify-email",
            json={"email": user.email, "otp": "000000"},
        )
        assert resp.status_code == 400, f"failed guess #{attempt + 1} should be a plain 400"

    resp = await client.post(
        f"{api_prefix}/auth/verify-email",
        json={"email": user.email, "otp": "111222"},
    )
    assert resp.status_code == 400, (
        f"{MAX_OTP_ATTEMPTS} prior failed attempts must lock out the "
        "email-verification row even for a subsequent CORRECT code"
    )


async def test_verify_email_rate_limited_after_10_requests_per_ip_email(
    client, api_prefix, user_factory, verification_factory
):
    """Design notes section 2.1 point 1: VERIFY_EMAIL_RATE_LIMIT_PER_MINUTE
    = 10, same value as VERIFY_OTP_RATE_LIMIT_PER_MINUTE, mirrors
    tests/api/test_rate_limit.py's verify-otp coverage."""
    user, _ = await user_factory(email="verify-email-ratelimit@example.com", is_verified=False)
    await _seed_email_verification_code(verification_factory, email=user.email, code="666777")

    statuses = []
    for _ in range(VERIFY_EMAIL_RATE_LIMIT_PER_MINUTE + 1):
        resp = await client.post(
            f"{api_prefix}/auth/verify-email",
            json={"email": user.email, "otp": "000000"},
        )
        statuses.append(resp.status_code)

    assert statuses[-1] == 429
    header_names = {name.lower() for name in resp.headers.keys()}
    assert "retry-after" in header_names


async def test_verify_email_missing_otp_field_returns_422(client, api_prefix):
    resp = await client.post(
        f"{api_prefix}/auth/verify-email",
        json={"email": "verify-email-schema@example.com"},
    )
    assert resp.status_code == 422
