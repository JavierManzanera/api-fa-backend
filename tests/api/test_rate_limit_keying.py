"""
OBJ-013 -- rate limiter keying hardening (closes audit finding #17,
docs/security/audit-report.md "Gate 3 -- Verificacion OBJ-009"). Traces to
docs/api/obj-013-design-notes.md.

Design notes section 1 (the finding): `enforce_rate_limit`'s current query
is a single AND across (scope, ip, email) -- rotating EITHER `ip` or `email`
alone resets the attacker to a fresh zero-count bucket on every request,
because no PREVIOUS row shares the (ip, email) pair with the new one.

Design notes section 2/3 (the fix): replace the one combined COUNT with TWO
independent COUNTs -- one on (scope, ip), one on (scope, email) -- either
reaching its OWN limit is a 429. `limit` keeps its existing meaning (the
email-keyed threshold, unchanged value at all 6 call sites); a new
`ip_limit` (default `limit * settings.RATE_LIMIT_IP_MULTIPLIER`, new
setting defaulting to 5) is the more-generous IP-keyed threshold.
Zero call-site diffs at any of the 6 endpoints -- this is a purely internal
change to app/core/rate_limit.py.

RED-PHASE EXPECTATION, read before assuming a failure means a broken test:
- TestEmailRotationBypassNowClosed (point 1a in the qa-engineer dispatch)
  is the actual vulnerability-closure proof and IS EXPECTED TO FAIL red
  today. Today's rate_limit.py has no per-IP-only check at all, so 26
  requests from the same real IP with 26 distinct emails all return 200 --
  there's no 25th-request 429 to observe yet.
- TestDimensionParitySymmetric's "IP-triggered" half depends on the same
  not-yet-implemented IP-only check, so it is ALSO expected to fail red
  today (it can't even find a 429 response to compare).
- test_rate_limit_ip_multiplier_setting_defaults_to_five (moved to
  tests/unit/test_rate_limit_ip_multiplier_setting.py, not here) is
  likewise expected to fail red / error today (Settings has no such field).
- TestSpoofedXffRotationRegressionGuard, TestLegitimateSharedIpTrafficNotThrottled,
  and TestOriginalPerEmailLimitsUnchanged are explicitly REGRESSION GUARDS,
  not new red cases -- they assert properties that already hold under
  TODAY'S code (see each class's own docstring for why) and must CONTINUE
  to hold once the two-independent-checks fix lands. If any of those three
  classes fails today, that is itself a signal something is already broken
  independent of this objective -- flag back rather than assuming it's
  fine to force red.

TESTABILITY NOTE (mirrors tests/api/test_rate_limit_ip_spoofing.py and
tests/unit/test_client_ip.py's own convention): `client_ip()` only trusts
X-Forwarded-For when `settings.TRUSTED_PROXY_COUNT > 0`. The suite-wide
default (unset in conftest.py) is 0, so every request through the shared
`client` fixture -- regardless of any X-Forwarded-For header sent -- is
observed by the rate limiter as the SAME real IP (whatever
httpx.ASGITransport assigns as the synthetic peer). This is exactly what
makes the "same real IP, distinct emails" scenario (point 1a) trivial to
construct with zero header gymnastics: it's just the client fixture's
default behavior. It is ALSO why "rotating IP via a spoofed header" (the
symmetric case, point 1b) does NOT produce a genuinely different real IP
under the suite's default TRUSTED_PROXY_COUNT=0 -- seen in
TestSpoofedXffRotationRegressionGuard below.

RATE_LIMIT_IP_MULTIPLIER is defined here as a local literal constant
(value 5, matching design notes section 2's recommended default),
deliberately NOT imported from app.core.config (where it does not exist
yet) -- same red-phase-safe convention test_register_rate_limit.py already
established for REGISTER_RATE_LIMIT_PER_MINUTE.

Requires Postgres -- see tests/README.md / tests/conftest.py module
docstring.
"""

VALID_PASSWORD = "ValidPass123!"

REGISTER_EMAIL_LIMIT = 5  # app/api/v1/endpoints/auth.py REGISTER_RATE_LIMIT_PER_MINUTE
FORGOT_PASSWORD_EMAIL_LIMIT = 5
VERIFY_OTP_EMAIL_LIMIT = 10

# Design notes section 2/3: new settings.RATE_LIMIT_IP_MULTIPLIER default.
RATE_LIMIT_IP_MULTIPLIER = 5
REGISTER_IP_LIMIT = REGISTER_EMAIL_LIMIT * RATE_LIMIT_IP_MULTIPLIER  # 25
FORGOT_PASSWORD_IP_LIMIT = FORGOT_PASSWORD_EMAIL_LIMIT * RATE_LIMIT_IP_MULTIPLIER  # 25


async def _register(client, api_prefix, email, password=VALID_PASSWORD, headers=None):
    return await client.post(
        f"{api_prefix}/auth/register",
        json={"email": email, "password": password},
        headers=headers or {},
    )


# ----------------------------------------------------------------------------
# Point 1a -- the actual finding #17 closure proof. EXPECTED RED today.
# ----------------------------------------------------------------------------


class TestEmailRotationBypassNowClosed:
    """An attacker who rotates ONLY the email field, from one fixed real IP,
    used to reset to a fresh zero-count bucket on every single request under
    the old (scope, ip, email) AND-keyed query (no previous row shares the
    new, never-before-seen email). The fix's IP-only check must now catch
    this: 25 requests (the default IP limit at /register's 5/min email
    limit x 5x multiplier) succeed, the 26th is throttled -- even though no
    single email ever repeated."""

    async def test_distinct_emails_same_ip_throttled_at_26th_request(self, client, api_prefix):
        statuses = []
        for i in range(REGISTER_IP_LIMIT + 1):
            resp = await _register(client, api_prefix, f"ip-rotation-{i}@example.com")
            statuses.append(resp.status_code)

        assert statuses[:REGISTER_IP_LIMIT] == [200] * REGISTER_IP_LIMIT, (
            f"expected the first {REGISTER_IP_LIMIT} requests (each a distinct, "
            f"never-repeated email from the same real IP) to succeed -- got {statuses}"
        )
        assert statuses[REGISTER_IP_LIMIT] == 429, (
            f"the {REGISTER_IP_LIMIT + 1}th request from the SAME real IP must be "
            f"throttled by the IP-only check even though no single email repeated "
            f"-- got status sequence {statuses}. This is the exact bypass finding "
            f"#17 (obj-013-design-notes.md section 1) describes: rotating only "
            f"`email` reset the old AND-keyed counter to zero on every request."
        )

    async def test_distinct_emails_same_ip_429_carries_retry_after(self, client, api_prefix):
        for i in range(REGISTER_IP_LIMIT):
            await _register(client, api_prefix, f"ip-rotation-header-{i}@example.com")

        resp = await _register(client, api_prefix, "ip-rotation-header-final@example.com")

        assert resp.status_code == 429, resp.text
        header_names = {name.lower() for name in resp.headers.keys()}
        assert "retry-after" in header_names, (
            "the IP-triggered 429 must carry Retry-After, same as the existing "
            "email-triggered 429 shape (openapi.yaml's RateLimited response)"
        )


# ----------------------------------------------------------------------------
# Point 1b -- symmetric case, REGRESSION GUARD (should already pass today).
# ----------------------------------------------------------------------------


class TestSpoofedXffRotationRegressionGuard:
    """The task's 'attacker rotates only IP' symmetric case, read precisely:
    under the suite's default TRUSTED_PROXY_COUNT=0, a spoofed
    X-Forwarded-For header is completely ignored (tests/unit/test_client_ip.py,
    tests/api/test_rate_limit_ip_spoofing.py) -- so sending a different
    X-Forwarded-For value on every request does NOT actually rotate the real
    observed IP at all. The real (ip, email) pair therefore stays fully
    CONSTANT across every request in this test, which both the old AND-keyed
    query and the new email-only check throttle identically at the original
    email limit (5). This was never the bypass -- finding #17 requires a
    GENUINELY distinct real IP per request (not achievable through an
    untrusted header), which is exactly why this class is a regression guard
    (must already pass today) and not a new red case."""

    async def test_spoofed_xff_per_request_does_not_change_real_throttle_key(
        self, client, api_prefix
    ):
        email = "xff-spoof-same-email@example.com"

        statuses = []
        for i in range(REGISTER_EMAIL_LIMIT + 1):
            resp = await _register(
                client,
                api_prefix,
                email,
                headers={"X-Forwarded-For": f"198.51.100.{i}"},  # different fake IP every time
            )
            statuses.append(resp.status_code)

        assert statuses[:REGISTER_EMAIL_LIMIT] == [200] * REGISTER_EMAIL_LIMIT, (
            f"got {statuses}"
        )
        assert statuses[REGISTER_EMAIL_LIMIT] == 429, (
            f"a spoofed, per-request-varying X-Forwarded-For must NOT extend the "
            f"budget beyond the original {REGISTER_EMAIL_LIMIT} -- got {statuses}. "
            f"TRUSTED_PROXY_COUNT=0 means the header is decorative; the real IP "
            f"never actually changes, so this must behave exactly like the "
            f"unspoofed same-IP/same-email case."
        )


# ----------------------------------------------------------------------------
# Point 2 -- false-positive guard: legitimate shared-IP traffic under the
# new, more generous IP threshold must NOT be throttled. Should already
# pass today (old code has no IP-only check to false-positive on) and must
# continue to pass after the fix (20 < the new 25 IP limit).
# ----------------------------------------------------------------------------


class TestLegitimateSharedIpTrafficNotThrottled:
    async def test_20_distinct_emails_same_ip_under_ip_threshold_all_succeed(
        self, client, api_prefix
    ):
        legitimate_traffic_count = 20  # < REGISTER_IP_LIMIT (25) at the default 5x multiplier

        statuses = []
        for i in range(legitimate_traffic_count):
            resp = await _register(client, api_prefix, f"legit-shared-ip-{i}@example.com")
            statuses.append(resp.status_code)

        assert statuses == [200] * legitimate_traffic_count, (
            f"{legitimate_traffic_count} distinct-email registrations from one shared "
            f"IP (e.g. NAT'd office, corporate VPN egress), each well under the "
            f"{REGISTER_IP_LIMIT}/min IP threshold, must all succeed -- got {statuses}. "
            f"A false positive here would globally throttle legitimate multi-user "
            f"traffic behind one IP, the exact risk design notes section 2 flags."
        )


# ----------------------------------------------------------------------------
# Point 3 -- regression guard: the existing 6 endpoints' original per-email
# limits (ip and email both held constant, matching today's exact repeat
# scenario) must be unchanged by this fix. Representative sample of two
# scopes with different threshold values (5 and 10); test_rate_limit.py and
# test_register_rate_limit.py already cover the full 6-endpoint matrix for
# the pre-existing single-AND-key behavior -- these two are kept here,
# co-located with the keying-fix suite, specifically to prove the NEW
# two-independent-checks code path preserves them, not to re-derive them.
# ----------------------------------------------------------------------------


class TestOriginalPerEmailLimitsUnchanged:
    async def test_forgot_password_still_429s_on_6th_request_same_email_and_ip(
        self, client, api_prefix, user_factory
    ):
        user, _ = await user_factory(email="obj013-forgot-password-regression@example.com")

        statuses = []
        for _ in range(FORGOT_PASSWORD_EMAIL_LIMIT + 1):
            resp = await client.post(
                f"{api_prefix}/auth/forgot-password", json={"email": user.email}
            )
            statuses.append(resp.status_code)

        assert statuses[:FORGOT_PASSWORD_EMAIL_LIMIT] == [200] * FORGOT_PASSWORD_EMAIL_LIMIT
        assert statuses[FORGOT_PASSWORD_EMAIL_LIMIT] == 429, (
            f"the email-keyed limit for /forgot-password (unchanged at "
            f"{FORGOT_PASSWORD_EMAIL_LIMIT}/min) must still trip on the "
            f"{FORGOT_PASSWORD_EMAIL_LIMIT + 1}th request from the same (ip, email) "
            f"-- got {statuses}"
        )

    async def test_verify_otp_still_429s_on_11th_request_same_email_and_ip(
        self, client, api_prefix, user_factory, verification_factory
    ):
        """Deliberately wrong OTP guesses on every request (mirrors
        test_rate_limit.py's test_rate_limit_triggers_regardless_of_varied_otp_guesses):
        this endpoint has a SEPARATE 5-attempt OTP-lockout mechanism
        (MAX_OTP_ATTEMPTS, app/api/v1/endpoints/auth.py) on top of the
        rate limiter, so intermediate statuses are legitimately 400
        (invalid OTP / lockout), never 200 -- only the outer rate-limit
        ceiling at request 11 is this test's concern, same assertion
        shape the pre-existing test_rate_limit.py uses for this exact
        endpoint (checks only the final status, not every intermediate
        one)."""
        user, _ = await user_factory(email="obj013-verify-otp-regression@example.com")
        await verification_factory(email=user.email, code="654321")

        statuses = []
        for i in range(VERIFY_OTP_EMAIL_LIMIT + 1):
            resp = await client.post(
                f"{api_prefix}/auth/verify-otp",
                json={"email": user.email, "otp": f"{i:06d}"},
            )
            statuses.append(resp.status_code)

        assert statuses[VERIFY_OTP_EMAIL_LIMIT] == 429, (
            f"the email-keyed limit for /verify-otp (unchanged at "
            f"{VERIFY_OTP_EMAIL_LIMIT}/min) must still trip on the "
            f"{VERIFY_OTP_EMAIL_LIMIT + 1}th request from the same (ip, email) -- "
            f"got {statuses}"
        )


# ----------------------------------------------------------------------------
# Point 4 -- the 429 response must not become a new oracle: body/headers
# identical whether the IP-only or the email-only check tripped. The
# IP-triggered half depends on the not-yet-implemented IP check, so this
# whole test is EXPECTED RED today (same reason as TestEmailRotationBypassNowClosed).
# ----------------------------------------------------------------------------


class TestDimensionParitySymmetric:
    async def test_429_body_and_headers_identical_whether_ip_or_email_dimension_tripped(
        self, client, api_prefix
    ):
        # IP-triggered: 26 distinct emails, one shared real IP.
        ip_triggered_resp = None
        for i in range(REGISTER_IP_LIMIT + 1):
            resp = await _register(client, api_prefix, f"parity-ip-triggered-{i}@example.com")
            ip_triggered_resp = resp

        # Email-triggered: 6 requests, same email, same shared real IP.
        email_triggered_email = "parity-email-triggered@example.com"
        email_triggered_resp = None
        for _ in range(REGISTER_EMAIL_LIMIT + 1):
            email_triggered_resp = await _register(client, api_prefix, email_triggered_email)

        assert ip_triggered_resp.status_code == 429, (
            f"expected the IP-only check to have tripped by the "
            f"{REGISTER_IP_LIMIT + 1}th distinct-email request -- got "
            f"{ip_triggered_resp.status_code}: {ip_triggered_resp.text}"
        )
        assert email_triggered_resp.status_code == 429, (
            f"expected the email-only check to have tripped by the "
            f"{REGISTER_EMAIL_LIMIT + 1}th same-email request -- got "
            f"{email_triggered_resp.status_code}: {email_triggered_resp.text}"
        )

        assert ip_triggered_resp.json() == email_triggered_resp.json(), (
            "the 429 body must be byte-for-byte identical regardless of which "
            f"dimension tripped -- ip-triggered={ip_triggered_resp.json()!r} "
            f"email-triggered={email_triggered_resp.json()!r}. A differentiated "
            "body would be a new oracle letting an attacker infer which "
            "dimension (ip or email) they were throttled on (design notes "
            "section 3's `dimension` field is explicitly audit-log-only, never "
            "wire-visible, for exactly this reason)."
        )

        ip_headers = {name.lower() for name in ip_triggered_resp.headers.keys()}
        email_headers = {name.lower() for name in email_triggered_resp.headers.keys()}
        assert "retry-after" in ip_headers and "retry-after" in email_headers, (
            "both dimensions' 429 responses must carry Retry-After"
        )
        assert (
            ip_triggered_resp.headers.get("retry-after")
            == email_triggered_resp.headers.get("retry-after")
        ), (
            "the Retry-After value itself must not differ between dimensions -- "
            "both checks share the same window_seconds (design notes section 5)"
        )


# ----------------------------------------------------------------------------
# Point 5 -- Gate 3 verification gap-fill (2026-08-25, qa-engineer): the
# TestDimensionParitySymmetric class above proves the two 429s are EQUAL to
# each other, which is the property that matters for the anti-oracle
# guarantee, but it never pins down WHAT that shared shape actually is or
# asserts the `dimension` field's name is absent by construction. These two
# tests close that gap directly rather than only by inference:
#   (a) the IP-triggered 429 body is EXACTLY the documented generic shape
#       (docs/api/openapi.yaml's RateLimited component) with no extra keys
#       -- in particular no `dimension` key -- not just "equal to the other
#       one".
#   (b) the fix is centralized, not something that only happens to work at
#       /register: a SECOND, independent endpoint (/forgot-password) also
#       enforces its own IP-only check at limit x RATE_LIMIT_IP_MULTIPLIER.
#       auth.py's diff for OBJ-013 (commit 78d0f66) touches zero lines in
#       any endpoint handler -- confirmed via `git show 78d0f66 --stat` --
#       so this is a belt-and-suspenders proof of that structural claim
#       against a second call site, not a redundant re-test of /register.
# ----------------------------------------------------------------------------


class TestNoNewOracleExplicitBodyShape:
    async def test_ip_triggered_429_body_has_no_dimension_key_and_matches_documented_shape(
        self, client, api_prefix
    ):
        for i in range(REGISTER_IP_LIMIT):
            await _register(client, api_prefix, f"oracle-shape-{i}@example.com")

        resp = await _register(client, api_prefix, "oracle-shape-final@example.com")

        assert resp.status_code == 429, resp.text
        assert resp.json() == {"detail": "Too many requests. Please try again later."}, (
            f"the IP-triggered 429 body must be EXACTLY the documented generic "
            f"RateLimited shape (openapi.yaml) with no additional keys -- in "
            f"particular the internal `dimension` field (design notes section 3) "
            f"must never appear on the wire -- got {resp.json()!r}"
        )
        assert "dimension" not in resp.text.lower(), (
            f"the literal string 'dimension' must not appear anywhere in the "
            f"response body text -- got {resp.text!r}"
        )


class TestFixCentralizedAcrossEndpoints:
    async def test_forgot_password_ip_only_check_also_throttles_at_26th_distinct_email(
        self, client, api_prefix
    ):
        """Same shape as TestEmailRotationBypassNowClosed but against a
        SECOND endpoint, to prove the IP-only check is genuinely centralized
        in enforce_rate_limit and not something only exercised/working at
        /register (the endpoint every other test in this file happens to
        use). /forgot-password never validates the email against an
        existing account before the rate-limit check runs (anti-enumeration,
        OBJ-007 finding #6), so distinct never-used emails are as trivial to
        construct here as at /register."""
        statuses = []
        for i in range(FORGOT_PASSWORD_IP_LIMIT + 1):
            resp = await client.post(
                f"{api_prefix}/auth/forgot-password",
                json={"email": f"fp-ip-rotation-{i}@example.com"},
            )
            statuses.append(resp.status_code)

        assert statuses[:FORGOT_PASSWORD_IP_LIMIT] == [200] * FORGOT_PASSWORD_IP_LIMIT, (
            f"expected the first {FORGOT_PASSWORD_IP_LIMIT} requests (each a "
            f"distinct, never-repeated email from the same real IP) to succeed "
            f"-- got {statuses}"
        )
        assert statuses[FORGOT_PASSWORD_IP_LIMIT] == 429, (
            f"the {FORGOT_PASSWORD_IP_LIMIT + 1}th request from the SAME real IP "
            f"to a SECOND endpoint must also be throttled by the IP-only check "
            f"even though no single email repeated -- got status sequence "
            f"{statuses}. Confirms the fix is centralized in enforce_rate_limit, "
            f"not accidentally only working at /register."
        )
