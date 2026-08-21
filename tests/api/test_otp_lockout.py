"""
OBJ-001 Story 2 -- OTP attempt lockout. Traces to
docs/requirements/obj-001-critical-auth-hardening.md Scenarios 2.1, 2.2,
2.3, 2.5, 2.7, and obj-001-design-notes.md section 2 (shared `attempts`
counter across /verify-otp and /reset-password, closing audit finding #2's
"free oracle").

Gate 1 decision (dependency_graph.md, 2026-08-21): MAX_OTP_ATTEMPTS = 5.

Scenario 2.7 ("10 rapid parallel requests") is exercised here as
sequential requests, not true concurrency -- test-gap-analysis.md's TOCTOU
note explicitly flags genuine race-condition testing as
flaky/environment-dependent and out of the standard suite. Sequential
requests are sufficient to prove the *business rule* (budget exhausted =
locked, regardless of request ordering); they do not prove the lock is
race-free under concurrent writes.

These tests exercise ONLY observable HTTP behavior (status codes), not any
particular storage shape for the attempts counter, per
obj-001-design-notes.md section 2's instruction to keep OTP lockout
state opaque to callers.

Requires Postgres -- see tests/README.md for the environment blocker noted
during this red-phase pass.
"""

MAX_OTP_ATTEMPTS = 5


async def test_scenario_2_1_valid_unexpired_otp_is_accepted(
    client, api_prefix, user_factory, verification_factory
):
    user, _ = await user_factory(email="judy@example.com")
    await verification_factory(email=user.email, code="111111")

    resp = await client.post(
        f"{api_prefix}/auth/verify-otp", json={"email": user.email, "otp": "111111"}
    )

    assert resp.status_code == 200


async def test_scenario_2_2_otp_rejected_after_ttl_expires(
    client, api_prefix, user_factory, verification_factory
):
    from freezegun import freeze_time

    user, _ = await user_factory(email="mallory@example.com")
    with freeze_time("2026-01-01 00:00:00"):
        await verification_factory(email=user.email, code="222222", ttl_minutes=10)
    with freeze_time("2026-01-01 00:10:01"):
        resp = await client.post(
            f"{api_prefix}/auth/verify-otp",
            json={"email": user.email, "otp": "222222"},
        )

    assert resp.status_code == 400


async def test_scenario_2_3_locked_out_after_max_attempts_even_with_correct_code(
    client, api_prefix, user_factory, verification_factory
):
    user, _ = await user_factory(email="niaj@example.com")
    await verification_factory(email=user.email, code="333333")

    for attempt in range(MAX_OTP_ATTEMPTS):
        resp = await client.post(
            f"{api_prefix}/auth/verify-otp",
            json={"email": user.email, "otp": "000000"},
        )
        assert resp.status_code == 400, f"failed guess #{attempt + 1} should be a plain 400"

    # The MAX_OTP_ATTEMPTS-th failure should have invalidated the row.
    # The correct code must now ALSO be rejected -- this is the lockout.
    resp = await client.post(
        f"{api_prefix}/auth/verify-otp", json={"email": user.email, "otp": "333333"}
    )
    assert resp.status_code == 400, (
        f"{MAX_OTP_ATTEMPTS} prior failed attempts must lock out the OTP row "
        "even for a subsequent CORRECT code (Gate 1 decision: 5 failed attempts)"
    )


async def test_scenario_2_3_lockout_response_is_indistinguishable_from_expired(
    client, api_prefix, user_factory, verification_factory
):
    """openapi.yaml /auth/verify-otp: 'Invalid, expired, or attempt-locked-out
    OTP. All three cases are indistinguishable by design.' No new status
    code, no distinguishing message."""
    user, _ = await user_factory(email="oscar@example.com")
    await verification_factory(email=user.email, code="999999")
    for _ in range(MAX_OTP_ATTEMPTS):
        await client.post(
            f"{api_prefix}/auth/verify-otp",
            json={"email": user.email, "otp": "000000"},
        )

    locked_resp = await client.post(
        f"{api_prefix}/auth/verify-otp", json={"email": user.email, "otp": "999999"}
    )

    assert locked_resp.status_code == 400
    assert locked_resp.json()["detail"] == "Invalid or expired OTP", (
        "lockout must reuse the exact same generic message as "
        "wrong-code/expired -- no new oracle"
    )


async def test_verify_otp_and_reset_password_share_one_attempt_budget(
    client, api_prefix, user_factory, verification_factory
):
    """Audit finding #2 / design notes section 2: verify-otp and
    reset-password increment the SAME counter on the SAME (email, purpose)
    row -- this is the fix for verify-otp being a free oracle for
    reset-password's guesses."""
    user, _ = await user_factory(email="olivia@example.com")
    await verification_factory(email=user.email, code="444444")

    for _ in range(3):
        await client.post(
            f"{api_prefix}/auth/verify-otp",
            json={"email": user.email, "otp": "000000"},
        )
    for _ in range(2):
        await client.post(
            f"{api_prefix}/auth/reset-password",
            json={
                "email": user.email,
                "otp": "000000",
                "new_password": "NewValidPass123!",
            },
        )

    resp = await client.post(
        f"{api_prefix}/auth/verify-otp", json={"email": user.email, "otp": "444444"}
    )
    assert resp.status_code == 400, (
        "3 failures via verify-otp + 2 via reset-password = 5 combined "
        "failures against ONE shared counter must lock out the row"
    )


async def test_scenario_2_5_otp_cannot_be_reused_after_successful_reset(
    client, api_prefix, user_factory, verification_factory
):
    user, _ = await user_factory(email="peggy@example.com")
    await verification_factory(email=user.email, code="555555")

    first = await client.post(
        f"{api_prefix}/auth/reset-password",
        json={
            "email": user.email,
            "otp": "555555",
            "new_password": "NewValidPass123!",
        },
    )
    assert first.status_code == 200

    second = await client.post(
        f"{api_prefix}/auth/reset-password",
        json={
            "email": user.email,
            "otp": "555555",
            "new_password": "AnotherValidPass123!",
        },
    )
    assert second.status_code == 400, "a consumed OTP must not be usable a second time"
