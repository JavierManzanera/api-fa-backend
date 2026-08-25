"""
OBJ-005 -- purpose-budget isolation between `reset_password` and
`email_verification` Verification rows sharing the same table. Traces to
docs/requirements/obj-005-email-verification-flow.md's "Interaction with
OBJ-001/003 Verification Table" edge case ("Same-table sharing does NOT
imply shared lockout counters: a failed email-verification attempt should
not decrement the user's password-reset OTP budget, and vice versa") and
docs/api/obj-005-design-notes.md section 1.1.

THE HIGHEST-VALUE TEST IN THIS PASS (design notes section 6, by direct
analogy to OBJ-002's test_reuse_detected_revokes_entire_token_family): the
generalization of `_check_and_consume_otp` from a hardcoded
`purpose="reset_password"` filter to a `purpose` PARAMETER (design notes
section 1.1) is the one change with real potential to silently merge two
budgets that must stay separate, if the parameter is threaded through
incorrectly (e.g. a leftover hardcoded RESET_PASSWORD_PURPOSE somewhere in
the query, or a shared row keyed only on email without also filtering by
purpose). Both directions are tested below, not just one -- a bug could
plausibly affect only one direction (e.g. if /auth/verify-email's call
site were the one with the leftover hardcoded value, only the
email-verification-affecting-reset-password direction would break).

Requires Postgres -- see tests/README.md / tests/conftest.py module
docstring.
"""

MAX_OTP_ATTEMPTS = 5


async def test_failing_email_verification_attempts_does_not_touch_the_reset_password_budget(
    client, api_prefix, user_factory, verification_factory
):
    user, _ = await user_factory(email="isolation-a@example.com", is_verified=False)
    await verification_factory(
        email=user.email, code="111111", purpose="reset_password", ttl_minutes=10
    )
    await verification_factory(
        email=user.email, code="222222", purpose="email_verification", ttl_minutes=30
    )

    # Exhaust the email_verification budget with MAX_OTP_ATTEMPTS wrong
    # guesses via /auth/verify-email.
    for attempt in range(MAX_OTP_ATTEMPTS):
        resp = await client.post(
            f"{api_prefix}/auth/verify-email",
            json={"email": user.email, "otp": "000000"},
        )
        assert resp.status_code == 400, f"failed guess #{attempt + 1} should be a plain 400"

    # The email_verification row is now locked out -- confirm that first,
    # so a failure below is unambiguously about the OTHER purpose's budget,
    # not a mistaken assumption that the lockout itself didn't happen.
    locked = await client.post(
        f"{api_prefix}/auth/verify-email",
        json={"email": user.email, "otp": "222222"},
    )
    assert locked.status_code == 400, (
        "sanity check: the email_verification row should now be locked out "
        "-- if this fails, the lockout mechanism itself is broken, not "
        "purpose isolation"
    )

    # The UNRELATED reset_password row's correct code must STILL work --
    # its own attempts counter must be untouched by the five failures
    # above, which were scoped to a completely different purpose.
    reset_resp = await client.post(
        f"{api_prefix}/auth/verify-otp",
        json={"email": user.email, "otp": "111111"},
    )
    assert reset_resp.status_code == 200, (
        f"{MAX_OTP_ATTEMPTS} failed attempts against the "
        f"email_verification purpose must NOT decrement the SAME email's "
        f"reset_password budget -- got {reset_resp.status_code}: "
        f"{reset_resp.text}. If this fails, _check_and_consume_otp's "
        f"purpose generalization has accidentally merged the two budgets."
    )


async def test_failing_reset_password_attempts_does_not_touch_the_email_verification_budget(
    client, api_prefix, user_factory, verification_factory
):
    """The inverse direction -- see module docstring for why both
    directions are tested independently."""
    user, _ = await user_factory(email="isolation-b@example.com", is_verified=False)
    await verification_factory(
        email=user.email, code="333333", purpose="reset_password", ttl_minutes=10
    )
    await verification_factory(
        email=user.email, code="444444", purpose="email_verification", ttl_minutes=30
    )

    for attempt in range(MAX_OTP_ATTEMPTS):
        resp = await client.post(
            f"{api_prefix}/auth/verify-otp",
            json={"email": user.email, "otp": "000000"},
        )
        assert resp.status_code == 400, f"failed guess #{attempt + 1} should be a plain 400"

    locked = await client.post(
        f"{api_prefix}/auth/verify-otp",
        json={"email": user.email, "otp": "333333"},
    )
    assert locked.status_code == 400, (
        "sanity check: the reset_password row should now be locked out"
    )

    verify_email_resp = await client.post(
        f"{api_prefix}/auth/verify-email",
        json={"email": user.email, "otp": "444444"},
    )
    assert verify_email_resp.status_code == 200, (
        f"{MAX_OTP_ATTEMPTS} failed attempts against the reset_password "
        f"purpose must NOT decrement the SAME email's email_verification "
        f"budget -- got {verify_email_resp.status_code}: "
        f"{verify_email_resp.text}"
    )


async def test_email_verification_and_reset_password_rows_coexist_independently(
    client, api_prefix, user_factory, verification_factory, db_session
):
    """Simpler companion check, DB-state level rather than attempts-budget
    level: creating a live row for one purpose must not disturb (delete,
    expire, or overwrite) a live row for the other purpose on the SAME
    email -- both must be independently queryable and independently
    consumable, in either order."""
    from sqlalchemy import select

    from app.models.verification import Verification

    user, _ = await user_factory(email="isolation-coexist@example.com", is_verified=False)
    await verification_factory(
        email=user.email, code="555555", purpose="reset_password", ttl_minutes=10
    )
    await verification_factory(
        email=user.email, code="666666", purpose="email_verification", ttl_minutes=30
    )

    result = await db_session.execute(
        select(Verification).filter(Verification.email == user.email)
    )
    rows = result.scalars().all()
    assert len(rows) == 2, (
        f"both purposes' rows must coexist for the same email -- found "
        f"{len(rows)} row(s)"
    )
    purposes = {row.purpose for row in rows}
    assert purposes == {"reset_password", "email_verification"}

    # Consume the email_verification row (deletes it, per design notes
    # section 2.1) -- the reset_password row must survive untouched.
    verify_resp = await client.post(
        f"{api_prefix}/auth/verify-email",
        json={"email": user.email, "otp": "666666"},
    )
    assert verify_resp.status_code == 200, verify_resp.text

    remaining = await db_session.execute(
        select(Verification).filter(Verification.email == user.email)
    )
    remaining_rows = remaining.scalars().all()
    assert len(remaining_rows) == 1 and remaining_rows[0].purpose == "reset_password", (
        "consuming the email_verification row must not affect the "
        "unrelated reset_password row for the same email"
    )
