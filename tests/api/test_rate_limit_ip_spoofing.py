"""
OBJ-004 backlog item (OBJ-001 Gate 3, security-specialist, "New MEDIUM") --
task item 6's explicit second requirement: "test rate-limiting/lockout still
can't be trivially bypassed by spoofing the header when TRUSTED_PROXY_COUNT=0."

Companion to tests/unit/test_client_ip.py, which proves the SAME property at
the unit level (client_ip() ignores X-Forwarded-For entirely when
TRUSTED_PROXY_COUNT=0). This file proves it end-to-end through the real
rate limiter + HTTP stack: an attacker who varies X-Forwarded-For per
request must not be able to reset/evade the existing per-(scope, ip, email)
rate-limit budget from tests/api/test_rate_limit.py.

No Gherkin/AC doc exists for OBJ-004 -- see test_environment_settings.py's
docstring for the shared "derived from design notes" rationale. Scenario
derivation from obj-004-design-notes.md section 6.1: "if the app trusted
X-Forwarded-For unconditionally with no reverse proxy in front, any client
could set X-Forwarded-For: 1.2.3.4 directly and spoof an arbitrary IP,
defeating rate limiting in the opposite direction (unlimited requests, each
claiming a different fake source)." -> the tests below drive exactly that
attack shape and assert it does NOT work.

Uses tests/api/test_rate_limit.py's own established thresholds
(FORGOT_PASSWORD_LIMIT = 5) rather than re-deriving them, per this
project's existing convention of keeping rate-limit constants in one place
per file and cross-referencing rather than duplicating (see
tests/README.md's own risk note on this).

Requires Postgres -- see tests/README.md / tests/conftest.py. Runs against
the suite's default TRUSTED_PROXY_COUNT (0, unset in conftest.py -- see
tests/unit/test_client_ip.py's TestTrustedProxyCountSettingsDefault), which
is exactly the configuration this test needs.
"""

FORGOT_PASSWORD_LIMIT = 5


async def test_varying_x_forwarded_for_does_not_bypass_forgot_password_rate_limit(
    client, api_prefix, user_factory
):
    """The core anti-bypass property: a DIFFERENT spoofed X-Forwarded-For
    value on every single request must not reset the rate-limit window --
    with TRUSTED_PROXY_COUNT=0, the real (shared, ASGITransport-assigned)
    client IP is what actually gets keyed, so the budget still exhausts
    exactly like tests/api/test_rate_limit.py's unspoofed baseline."""
    user, _ = await user_factory(email="spoofer@example.com")

    statuses = []
    for i in range(FORGOT_PASSWORD_LIMIT + 1):
        resp = await client.post(
            f"{api_prefix}/auth/forgot-password",
            json={"email": user.email},
            headers={"X-Forwarded-For": f"10.0.0.{i}"},  # a different fake IP every request
        )
        statuses.append(resp.status_code)

    assert statuses[:FORGOT_PASSWORD_LIMIT] == [200] * FORGOT_PASSWORD_LIMIT
    assert statuses[FORGOT_PASSWORD_LIMIT] == 429, (
        f"spoofing a different X-Forwarded-For value on every request must "
        f"NOT reset or evade the rate limit when TRUSTED_PROXY_COUNT=0 -- "
        f"got status sequence {statuses}, expected the "
        f"{FORGOT_PASSWORD_LIMIT + 1}th request to still be 429"
    )


async def test_single_repeated_spoofed_xff_value_also_still_rate_limited(
    client, api_prefix, user_factory
):
    """Simpler companion case: even a single, consistent spoofed
    X-Forwarded-For (mimicking an attacker who read a blog post about IP
    spoofing but doesn't vary it) must not somehow grant a SEPARATE budget
    from an unspoofed request -- i.e. the header isn't being partially
    trusted or merged into the key in some other way."""
    user, _ = await user_factory(email="spoofer-static@example.com")

    statuses = []
    for _ in range(FORGOT_PASSWORD_LIMIT + 1):
        resp = await client.post(
            f"{api_prefix}/auth/forgot-password",
            json={"email": user.email},
            headers={"X-Forwarded-For": "203.0.113.250"},
        )
        statuses.append(resp.status_code)

    assert statuses[FORGOT_PASSWORD_LIMIT] == 429


async def test_unspoofed_and_spoofed_requests_share_the_same_budget(
    client, api_prefix, user_factory
):
    """Interleaves plain requests (no X-Forwarded-For header at all) with
    spoofed ones for the SAME email -- both must draw from the same budget,
    proving the real (ignored-header) client IP is the actual rate-limit
    key in both cases, not two different keys that happen to each have
    their own allowance."""
    user, _ = await user_factory(email="spoofer-mixed@example.com")

    statuses = []
    for i in range(FORGOT_PASSWORD_LIMIT + 1):
        headers = {"X-Forwarded-For": f"172.16.0.{i}"} if i % 2 == 0 else {}
        resp = await client.post(
            f"{api_prefix}/auth/forgot-password",
            json={"email": user.email},
            headers=headers,
        )
        statuses.append(resp.status_code)

    assert statuses[FORGOT_PASSWORD_LIMIT] == 429, (
        f"got {statuses} -- spoofed and unspoofed requests must share one "
        f"budget, not get separate allowances"
    )
