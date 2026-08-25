"""
OBJ-005 Story 1 -- POST /auth/resend-verification-email. Traces to
docs/requirements/obj-005-email-verification-flow.md Scenarios 1.6, 1.7 and
docs/api/obj-005-design-notes.md section 2.2 (mirrors /auth/forgot-
password's pattern almost line for line: unauthenticated, always-generic
200, per-email rate limiting, silent resend cooldown, rotate-on-success --
plus one addition /forgot-password doesn't need: an already-verified user's
resend is a silent no-op).

This endpoint does not exist yet -- every test in this file is expected to
fail 404 today (RED, for the right reason: missing route).

Deliberately does NOT use any EmailSender mock/override -- every assertion
in this file is provable purely via HTTP status codes and direct DB state
(Verification row presence/absence, code content via a follow-up
/auth/verify-email call), matching this project's existing convention
for /auth/forgot-password's analogous tests (tests/api/test_otp_resend_cooldown.py,
tests/api/test_rate_limit.py) which also never needed to inspect email
delivery directly. The EmailSender-call-count assertion for the "no email
sent to an already-verified user" property lives in
test_resend_is_a_silent_noop_for_an_already_verified_user below (using the
injected email_sender override, per design notes section 6's testability
guidance) since a "no DB row" proof alone doesn't fully cover "no email
attempt was made."

Requires Postgres -- see tests/README.md / tests/conftest.py module
docstring.
"""

from freezegun import freeze_time
from sqlalchemy import select

from app.models.verification import Verification

EMAIL_VERIFICATION_PURPOSE = "email_verification"
RESEND_VERIFICATION_RATE_LIMIT_PER_MINUTE = 5
EMAIL_VERIFICATION_RESEND_COOLDOWN_SECONDS = 60


async def _count_verification_rows(db_session, email, purpose=EMAIL_VERIFICATION_PURPOSE):
    result = await db_session.execute(
        select(Verification).filter(
            Verification.email == email, Verification.purpose == purpose
        )
    )
    return len(result.scalars().all())


async def test_resend_returns_generic_200_for_a_nonexistent_email(client, api_prefix):
    """Anti-enumeration, same property as /auth/forgot-password (design
    notes section 2.2 point 2)."""
    resp = await client.post(
        f"{api_prefix}/auth/resend-verification-email",
        json={"email": "resend-nonexistent@example.com"},
    )
    assert resp.status_code == 200
    assert "detail" not in resp.json(), "must be the generic MessageResponse shape, not an error"


async def test_resend_returns_generic_200_and_creates_a_fresh_code_for_unverified_user(
    client, api_prefix, user_factory, db_session
):
    """Scenario 1.6."""
    user, _ = await user_factory(email="resend-unverified@example.com", is_verified=False)

    resp = await client.post(
        f"{api_prefix}/auth/resend-verification-email", json={"email": user.email}
    )

    assert resp.status_code == 200
    assert resp.json() == {
        "msg": "If the email exists and is not yet verified, a verification code has been sent."
    }
    assert await _count_verification_rows(db_session, user.email) == 1, (
        "a fresh purpose=email_verification Verification row must be "
        "created for an unverified user's resend request"
    )


async def test_resend_is_a_silent_noop_for_an_already_verified_user(
    client, api_prefix, user_factory, db_session
):
    """Design notes section 2.2 point 3: an already-verified user's resend
    is a silent no-op -- same generic 200, no new Verification row, no
    email sent. The 'no email sent' half needs the injected EmailSender
    override (design notes section 6's testability guidance); the
    'no new row' half is provable via plain DB state alone.

    `deps.get_email_sender` does not exist yet -- overriding it raises
    AttributeError, a correct RED signal for missing OBJ-005
    implementation, not a broken test (same documented-AttributeError
    convention as tests/factories.py's create_verification docstring for
    security.hash_otp before OBJ-003 landed).
    """
    from app.api import deps
    from app.main import app

    user, _ = await user_factory(email="resend-already-verified@example.com", is_verified=True)

    class _RecordingEmailSender:
        def __init__(self):
            self.calls = []

        async def send(self, *, to, subject, body, html_body=None):
            self.calls.append({"to": to, "subject": subject, "body": body})

    sender = _RecordingEmailSender()
    app.dependency_overrides[deps.get_email_sender] = lambda: sender

    resp = await client.post(
        f"{api_prefix}/auth/resend-verification-email", json={"email": user.email}
    )

    assert resp.status_code == 200
    assert resp.json() == {
        "msg": "If the email exists and is not yet verified, a verification code has been sent."
    }
    assert await _count_verification_rows(db_session, user.email) == 0, (
        "an already-verified user's resend must not create any "
        "Verification row"
    )
    assert sender.calls == [], (
        "an already-verified user's resend must not attempt to send any "
        "email -- both the anti-oracle AND the avoid-spamming-an-already-"
        "verified-inbox rationale (design notes section 2.2 point 3)"
    )


async def test_resend_within_cooldown_does_not_rotate_existing_code(
    client, api_prefix, user_factory, verification_factory
):
    """Mirrors tests/api/test_otp_resend_cooldown.py's cooldown-preserves-
    existing-code test, scoped to purpose=email_verification with the
    60s EMAIL_VERIFICATION_RESEND_COOLDOWN_SECONDS (design notes section
    2.2 point 4)."""
    user, _ = await user_factory(email="resend-cooldown@example.com", is_verified=False)

    with freeze_time("2026-01-01 00:00:00"):
        await verification_factory(
            email=user.email, code="909090", purpose=EMAIL_VERIFICATION_PURPOSE, ttl_minutes=30
        )

        with freeze_time("2026-01-01 00:00:05"):  # 5s later, inside the 60s cooldown
            resp = await client.post(
                f"{api_prefix}/auth/resend-verification-email", json={"email": user.email}
            )
            assert resp.status_code == 200

        verify = await client.post(
            f"{api_prefix}/auth/verify-email",
            json={"email": user.email, "otp": "909090"},
        )

    assert verify.status_code == 200, (
        "the pre-existing code must still validate: a repeat resend inside "
        "the 60s cooldown must not rotate/replace it"
    )


async def test_resend_after_cooldown_elapses_rotates_the_code(
    client, api_prefix, user_factory, verification_factory
):
    user, _ = await user_factory(email="resend-post-cooldown@example.com", is_verified=False)

    with freeze_time("2026-01-01 00:00:00"):
        await verification_factory(
            email=user.email, code="808080", purpose=EMAIL_VERIFICATION_PURPOSE, ttl_minutes=30
        )

    with freeze_time("2026-01-01 00:02:00"):  # 120s later, past the 60s cooldown
        resp = await client.post(
            f"{api_prefix}/auth/resend-verification-email", json={"email": user.email}
        )
        assert resp.status_code == 200

        stale = await client.post(
            f"{api_prefix}/auth/verify-email",
            json={"email": user.email, "otp": "808080"},
        )

    assert stale.status_code == 400, (
        "past the cooldown window, a resend must rotate the code -- the "
        "old seeded one should no longer validate"
    )


async def test_resend_rate_limited_after_5_requests_per_ip_email(
    client, api_prefix, user_factory
):
    """Design notes section 2.2 point 1:
    RESEND_VERIFICATION_RATE_LIMIT_PER_MINUTE = 5, same value as
    FORGOT_PASSWORD_RATE_LIMIT_PER_MINUTE.

    OBJ-014 (obj-014-design-notes.md sections 2/3/6, finding #20
    mitigation): the last RATE_LIMIT_EMAIL_RESERVED_SLOTS (default 1) of
    each scope's email-keyed limit are reserved for an IP not yet recorded
    against that email this window. This test's never-rotated real IP
    (the shared `client` fixture uses one throughout) can therefore only
    ever claim the main pool (limit - reserved) -- documented, accepted
    trade-off, design notes section 6."""
    user, _ = await user_factory(email="resend-ratelimit@example.com", is_verified=False)
    main_pool_limit = RESEND_VERIFICATION_RATE_LIMIT_PER_MINUTE - 1  # RATE_LIMIT_EMAIL_RESERVED_SLOTS default

    statuses = []
    for _ in range(RESEND_VERIFICATION_RATE_LIMIT_PER_MINUTE + 1):
        resp = await client.post(
            f"{api_prefix}/auth/resend-verification-email", json={"email": user.email}
        )
        statuses.append(resp.status_code)

    assert statuses[:main_pool_limit] == [200] * main_pool_limit
    assert all(status == 429 for status in statuses[main_pool_limit:])


async def test_resend_429_response_carries_retry_after(client, api_prefix, user_factory):
    user, _ = await user_factory(email="resend-ratelimit-header@example.com", is_verified=False)
    for _ in range(RESEND_VERIFICATION_RATE_LIMIT_PER_MINUTE):
        await client.post(
            f"{api_prefix}/auth/resend-verification-email", json={"email": user.email}
        )

    resp = await client.post(
        f"{api_prefix}/auth/resend-verification-email", json={"email": user.email}
    )

    assert resp.status_code == 429
    header_names = {name.lower() for name in resp.headers.keys()}
    assert "retry-after" in header_names


async def test_resend_missing_email_field_returns_422(client, api_prefix):
    resp = await client.post(f"{api_prefix}/auth/resend-verification-email", json={})
    assert resp.status_code == 422
