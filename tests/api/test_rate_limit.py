"""
OBJ-001 Story 2, Scenario 2.4 -- rate limiting per IP+email prevents
distributed brute force. Traces to
docs/requirements/obj-001-critical-auth-hardening.md and
obj-001-design-notes.md section 2.

Gate 1 decision (dependency_graph.md, 2026-08-21):
  - 5 req/min per IP+email on /forgot-password
  - 10 req/min per IP+email on /verify-otp and /reset-password
  - exceeding the limit returns 429 with a Retry-After header

These tests exercise ONLY observable HTTP behavior (status codes / headers),
never a specific storage backend, per obj-001-design-notes.md section 2's
explicit instruction ("Postgres table, no Redis" is an infra choice, not a
test assumption).

CAUTION for developer: this assumes the rate limiter reads/writes through
the same overridable `get_db` session/engine used by the rest of the app
(see tests/conftest.py `client` fixture docstring). If implemented as a
fully separate module-level engine/session, these tests will fail with a
raw DB connection error instead of a clean assertion once the code lands --
flag back to qa-engineer if so, rather than assuming the test is wrong.

Requires Postgres -- see tests/README.md for the environment blocker noted
during this red-phase pass.
"""

FORGOT_PASSWORD_LIMIT = 5
VERIFY_OTP_LIMIT = 10
RESET_PASSWORD_LIMIT = 10

# OBJ-014 (obj-014-design-notes.md sections 2/3/6, finding #20 mitigation):
# the last RATE_LIMIT_EMAIL_RESERVED_SLOTS (default 1) of each scope's
# email-keyed limit are now reserved for an IP that has NOT yet been
# recorded against that email in the current window. A single, never-
# rotated IP/email pair (exactly this test's shape -- the shared `client`
# fixture uses one real IP for every request) can therefore only ever claim
# the MAIN POOL (limit - reserved), because by the time the tally reaches
# the reserved band its own IP has already been recorded and is
# ineligible. This is the documented, accepted trade-off of the fix (design
# notes section 6): a lone non-rotating actor is capped one request lower
# than before, in exchange for guaranteeing a genuinely different IP
# (the real victim's) at least one request through even after a single
# attacking IP has exhausted the rest of the budget. Still strictly <=
# the pre-OBJ-014 ceiling, never more -- the protection is not weakened.
RESERVED_SLOTS_DEFAULT = 1
FORGOT_PASSWORD_MAIN_POOL_LIMIT = FORGOT_PASSWORD_LIMIT - RESERVED_SLOTS_DEFAULT


async def test_forgot_password_rate_limited_after_5_requests_per_ip_email(
    client, api_prefix, user_factory
):
    user, _ = await user_factory(email="rachel@example.com")

    statuses = []
    for _ in range(FORGOT_PASSWORD_LIMIT + 1):
        resp = await client.post(
            f"{api_prefix}/auth/forgot-password", json={"email": user.email}
        )
        statuses.append(resp.status_code)

    # OBJ-014: a single, never-rotated IP is capped at the main pool
    # (limit - reserved), not the full limit -- see the module-level
    # comment above FORGOT_PASSWORD_MAIN_POOL_LIMIT.
    assert statuses[:FORGOT_PASSWORD_MAIN_POOL_LIMIT] == [200] * FORGOT_PASSWORD_MAIN_POOL_LIMIT
    assert all(status == 429 for status in statuses[FORGOT_PASSWORD_MAIN_POOL_LIMIT:]), (
        f"requests from the {FORGOT_PASSWORD_MAIN_POOL_LIMIT + 1}th onward, "
        f"from the SAME never-rotated IP, must be rate-limited -- got {statuses}"
    )


async def test_forgot_password_429_response_carries_retry_after(
    client, api_prefix, user_factory
):
    user, _ = await user_factory(email="sybil-2@example.com")
    for _ in range(FORGOT_PASSWORD_LIMIT):
        await client.post(
            f"{api_prefix}/auth/forgot-password", json={"email": user.email}
        )

    resp = await client.post(
        f"{api_prefix}/auth/forgot-password", json={"email": user.email}
    )

    assert resp.status_code == 429
    header_names = {name.lower() for name in resp.headers.keys()}
    assert "retry-after" in header_names, (
        "openapi.yaml RateLimited response documents a Retry-After header"
    )


async def test_verify_otp_rate_limited_after_10_requests_per_ip_email(
    client, api_prefix, user_factory, verification_factory
):
    user, _ = await user_factory(email="sybil@example.com")
    await verification_factory(email=user.email, code="666666")

    statuses = []
    for _ in range(VERIFY_OTP_LIMIT + 1):
        resp = await client.post(
            f"{api_prefix}/auth/verify-otp",
            json={"email": user.email, "otp": "000000"},
        )
        statuses.append(resp.status_code)

    assert statuses[-1] == 429


async def test_reset_password_rate_limited_after_10_requests_per_ip_email(
    client, api_prefix, user_factory, verification_factory
):
    user, _ = await user_factory(email="trent@example.com")
    await verification_factory(email=user.email, code="777777")

    statuses = []
    for _ in range(RESET_PASSWORD_LIMIT + 1):
        resp = await client.post(
            f"{api_prefix}/auth/reset-password",
            json={
                "email": user.email,
                "otp": "000000",
                "new_password": "NewValidPass123!",
            },
        )
        statuses.append(resp.status_code)

    assert statuses[-1] == 429


async def test_rate_limit_triggers_regardless_of_varied_otp_guesses(
    client, api_prefix, user_factory, verification_factory
):
    """Scenario 2.4: 'the rate limit applies even if the guesses are
    varied' -- must not be foolable by never repeating the same OTP."""
    user, _ = await user_factory(email="uma@example.com")
    await verification_factory(email=user.email, code="888888")

    last_status = None
    for i in range(VERIFY_OTP_LIMIT + 1):
        resp = await client.post(
            f"{api_prefix}/auth/verify-otp",
            json={"email": user.email, "otp": f"{i:06d}"},
        )
        last_status = resp.status_code

    assert last_status == 429
