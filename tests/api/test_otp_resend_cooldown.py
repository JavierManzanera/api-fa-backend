"""
OBJ-001 Gate 1 decision (dependency_graph.md, 2026-08-21): /forgot-password
enforces a 60s issuance cooldown per (email, purpose). A repeat request
within the cooldown window still returns the same generic 200
(anti-enumeration preserved) but must NOT rotate the existing OTP code or
reset its attempt counter (obj-001-design-notes.md section 2).

Cannot be tested by reading the OTP out of the HTTP response (it is only
ever "sent" via the print-based mock channel, never returned) -- so this
test seeds a KNOWN code directly via the DB factory, then proves indirectly
that a same-window repeat call did not rotate it: the seeded code must
still validate afterward. If the implementation naively deletes+reissues
on every call (today's behavior), the seeded code would be gone.

Requires Postgres -- see tests/README.md for the environment blocker noted
during this red-phase pass.
"""

from freezegun import freeze_time


async def test_repeat_forgot_password_within_cooldown_does_not_rotate_existing_otp(
    client, api_prefix, user_factory, verification_factory
):
    user, _ = await user_factory(email="victor@example.com")

    with freeze_time("2026-01-01 00:00:00"):
        await verification_factory(email=user.email, code="999999")

        with freeze_time("2026-01-01 00:00:05"):  # 5s later, well inside 60s cooldown
            resp = await client.post(
                f"{api_prefix}/auth/forgot-password", json={"email": user.email}
            )
            assert resp.status_code == 200, (
                "a repeat request inside the cooldown must still return the "
                "generic 200 -- no distinguishable signal to an attacker"
            )

        verify = await client.post(
            f"{api_prefix}/auth/verify-otp",
            json={"email": user.email, "otp": "999999"},
        )

    assert verify.status_code == 200, (
        "the pre-existing OTP must still validate: a repeat /forgot-password "
        "call inside the 60s cooldown must not rotate/replace it"
    )


async def test_forgot_password_after_cooldown_elapses_issues_a_fresh_otp(
    client, api_prefix, user_factory, verification_factory
):
    """Sanity counterpart: once the cooldown window has elapsed, a repeat
    call IS allowed to rotate the code -- the old seeded one should stop
    working. This documents the boundary, it doesn't re-assert 2.4's rate
    limiting (a fresh IP+email pair well past any rate-limit window)."""
    user, _ = await user_factory(email="walter@example.com")

    with freeze_time("2026-01-01 00:00:00"):
        await verification_factory(email=user.email, code="123123")

    with freeze_time("2026-01-01 00:02:00"):  # 120s later, past the 60s cooldown
        resp = await client.post(
            f"{api_prefix}/auth/forgot-password", json={"email": user.email}
        )
        assert resp.status_code == 200

        stale = await client.post(
            f"{api_prefix}/auth/verify-otp",
            json={"email": user.email, "otp": "123123"},
        )

    assert stale.status_code == 400, (
        "past the cooldown window, a new /forgot-password call is expected "
        "to rotate the code -- the old seeded one should no longer validate"
    )
