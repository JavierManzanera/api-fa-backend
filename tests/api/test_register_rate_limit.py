"""
OBJ-009 -- IP+email rate limiting on POST /auth/register (closes audit
finding #16, docs/security/audit-report.md "Gate 3 -- Verificacion OBJ-007").
Traces to docs/api/obj-009-design-notes.md.

Design notes section 1: REGISTER_RATE_LIMIT_PER_MINUTE = 5, same value/
justification category as FORGOT_PASSWORD_RATE_LIMIT_PER_MINUTE and
RESEND_VERIFICATION_RATE_LIMIT_PER_MINUTE (an endpoint that triggers an
outbound email send on every call). Mirrors tests/api/test_rate_limit.py
and tests/api/test_resend_verification_email.py's rate-limit tests almost
line for line -- same style, same assertions shape.

Design notes section 2 (the load-bearing decision this file exists to
guard): `enforce_rate_limit` must be called exactly ONCE in the shared
`register()` handler, before the new-vs-duplicate-email branch split --
never duplicated per-branch, never keyed by a branch-specific scope. Get
this wrong and OBJ-007's Gate 3 anti-enumeration guarantee (finding #6,
closed) is reopened as a NEW timing/observability side channel: an
attacker could distinguish "new email" from "duplicate email" by noticing
which one gets throttled after N requests, even with response bodies
still byte-identical. The tests in TestRateLimitDoesNotReopenEnumeration
below exist specifically to catch that regression, not just to prove a
429 eventually happens.

RED-PHASE EXPECTATION: every test in this file should currently FAIL --
`register()` has no `enforce_rate_limit` call at all yet
(app/api/v1/endpoints/auth.py, current `register()` body reads `ip =
rate_limit.client_ip(http_request)` then goes straight to the `SELECT
User` lookup -- no rate-limit check in between). Every request in every
test below is expected to return 200 (or 503 for the send-failure helper,
unused here), never 429 -- so the `429` assertions are the ones expected
to fail red, for the right reason (missing implementation), not a broken
test.

REGISTER_RATE_LIMIT_PER_MINUTE is defined here as a local literal
constant, deliberately NOT imported from app.api.v1.endpoints.auth (where
it does not exist yet) -- same convention test_rate_limit.py and
test_resend_verification_email.py already established, so a missing
symbol doesn't fail the whole file at collection and mask which specific
behavior each test is checking.

Requires Postgres -- see tests/README.md / tests/conftest.py module
docstring.
"""

import inspect

from freezegun import freeze_time

from app.api.v1.endpoints import auth as auth_module

REGISTER_RATE_LIMIT_PER_MINUTE = 5
VALID_PASSWORD = "ValidPass123!"
RATE_LIMIT_WINDOW_SECONDS = 60


async def _register(client, api_prefix, email, password=VALID_PASSWORD):
    return await client.post(
        f"{api_prefix}/auth/register", json={"email": email, "password": password}
    )


# ----------------------------------------------------------------------------
# Core rate-limit behavior -- mirrors test_rate_limit.py /
# test_resend_verification_email.py's established pattern.
# ----------------------------------------------------------------------------


async def test_register_rate_limited_after_5_requests_per_ip_email(client, api_prefix):
    """Repeats the SAME email REGISTER_RATE_LIMIT_PER_MINUTE + 1 times.
    Request 1 hits the new-account branch (creates the user); requests 2-5
    hit the duplicate-email branch (the email now exists). This naturally
    exercises design notes section 2's shared-budget property: the counter
    must be keyed on (scope, ip, email) before the branch split, so a
    sequence that crosses from the new-account branch into the
    duplicate-email branch mid-run still shares ONE budget, not two."""
    email = "register-ratelimit@example.com"

    statuses = []
    for _ in range(REGISTER_RATE_LIMIT_PER_MINUTE + 1):
        resp = await _register(client, api_prefix, email)
        statuses.append(resp.status_code)

    assert statuses[:REGISTER_RATE_LIMIT_PER_MINUTE] == (
        [200] * REGISTER_RATE_LIMIT_PER_MINUTE
    ), f"expected the first {REGISTER_RATE_LIMIT_PER_MINUTE} requests to succeed, got {statuses}"
    assert statuses[REGISTER_RATE_LIMIT_PER_MINUTE] == 429, (
        f"the {REGISTER_RATE_LIMIT_PER_MINUTE + 1}th request within the window must be "
        f"rate-limited -- got status sequence {statuses}"
    )


async def test_register_429_response_carries_retry_after(client, api_prefix):
    email = "register-ratelimit-header@example.com"
    for _ in range(REGISTER_RATE_LIMIT_PER_MINUTE):
        await _register(client, api_prefix, email)

    resp = await _register(client, api_prefix, email)

    assert resp.status_code == 429
    header_names = {name.lower() for name in resp.headers.keys()}
    assert "retry-after" in header_names, (
        "openapi.yaml's RateLimited response documents a Retry-After header"
    )


async def test_register_rate_limit_resets_after_window_elapses(client, api_prefix):
    """Sanity counterpart to the two tests above: once
    RATE_LIMIT_WINDOW_SECONDS has elapsed, a fresh request for the same
    (ip, email) pair must succeed again -- the budget is a sliding window,
    not a permanent lockout."""
    email = "register-ratelimit-window@example.com"

    with freeze_time("2026-01-01 00:00:00") as frozen:
        for _ in range(REGISTER_RATE_LIMIT_PER_MINUTE):
            resp = await _register(client, api_prefix, email)
            assert resp.status_code == 200, resp.text

        blocked = await _register(client, api_prefix, email)
        assert blocked.status_code == 429, (
            f"expected the budget to be exhausted before advancing time, got "
            f"{blocked.status_code}: {blocked.text}"
        )

        frozen.move_to("2026-01-01 00:01:01")  # 61s later, past the 60s window

        resp_after_window = await _register(client, api_prefix, email)

    assert resp_after_window.status_code == 200, (
        f"a request past the rate-limit window must succeed again -- got "
        f"{resp_after_window.status_code}: {resp_after_window.text}"
    )


async def test_register_missing_password_returns_422(client, api_prefix):
    """Sanity check: a 422-triggering malformed request should not itself
    consume a rate-limit slot in a way that breaks validation -- unrelated
    to rate limiting directly, kept here as a quick regression guard since
    this file already exercises /register's request validation surface."""
    resp = await client.post(
        f"{api_prefix}/auth/register", json={"email": "register-no-password@example.com"}
    )
    assert resp.status_code == 422


# ----------------------------------------------------------------------------
# The actual point of this objective (design notes section 2 / section 4):
# rate limiting must not become a NEW anti-enumeration side channel on top
# of OBJ-007's already-closed finding #6. These tests fail if a future
# implementation calls enforce_rate_limit per-branch instead of once,
# shared, before the branch split.
# ----------------------------------------------------------------------------


class TestRateLimitDoesNotReopenEnumeration:
    async def test_duplicate_email_only_traffic_is_also_rate_limited_after_5(
        self, client, api_prefix, user_factory
    ):
        """Design notes section 4 point 1's mirror image: if a future
        implementation only wired enforce_rate_limit into
        _handle_new_email_registration (forgetting the duplicate branch),
        an attacker could send unlimited requests for an
        already-registered email with no throttling at all. Pre-creates
        the user so EVERY request in this test hits the duplicate-email
        branch exclusively (no new-account branch call happens at all),
        and asserts the exact same 5-then-429 threshold as the
        new-account-starting test above."""
        user, _ = await user_factory(email="register-dup-ratelimit@example.com")

        statuses = []
        for _ in range(REGISTER_RATE_LIMIT_PER_MINUTE + 1):
            resp = await _register(client, api_prefix, user.email)
            statuses.append(resp.status_code)

        assert statuses[:REGISTER_RATE_LIMIT_PER_MINUTE] == (
            [200] * REGISTER_RATE_LIMIT_PER_MINUTE
        ), (
            f"duplicate-email-only traffic must be rate-limited using the SAME "
            f"threshold as new-account traffic -- got {statuses}"
        )
        assert statuses[REGISTER_RATE_LIMIT_PER_MINUTE] == 429, (
            f"duplicate-email-only traffic must ALSO be throttled at the "
            f"{REGISTER_RATE_LIMIT_PER_MINUTE + 1}th request -- got {statuses}. A "
            f"per-branch enforce_rate_limit call site that only covers the "
            f"new-account branch would leave this traffic completely "
            f"unthrottled (an infinite-request DoS amplification vector, "
            f"finding #16's original concern)."
        )

    async def test_429_body_is_identical_whether_the_email_is_new_or_already_registered(
        self, client, api_prefix, user_factory
    ):
        """The core anti-enumeration property: exhausts the rate limit for
        a NEVER-before-seen email (so the run starts on the new-account
        branch) and, independently, for a PRE-EXISTING email (so the run
        is duplicate-branch-only), then compares the resulting 429
        responses byte-for-byte. Any structural difference here -- a
        different scope-derived Retry-After value, a different body, an
        extra header -- would itself be a distinguishing signal an
        attacker could use to infer whether an email is registered,
        exactly the class of bug OBJ-007 (finding #6) already closed once
        and this objective must not reopen via a new mechanism."""
        existing_user, _ = await user_factory(email="register-429-parity-existing@example.com")

        new_email_statuses = []
        for _ in range(REGISTER_RATE_LIMIT_PER_MINUTE + 1):
            resp = await _register(client, api_prefix, "register-429-parity-new@example.com")
            new_email_statuses.append(resp)
        new_email_429 = new_email_statuses[-1]

        dup_email_statuses = []
        for _ in range(REGISTER_RATE_LIMIT_PER_MINUTE + 1):
            resp = await _register(client, api_prefix, existing_user.email)
            dup_email_statuses.append(resp)
        dup_email_429 = dup_email_statuses[-1]

        assert new_email_429.status_code == 429, new_email_429.text
        assert dup_email_429.status_code == 429, dup_email_429.text
        assert new_email_429.json() == dup_email_429.json(), (
            "the 429 body must be byte-for-byte identical regardless of "
            f"whether the throttled email was new or already-registered -- "
            f"new={new_email_429.json()!r} dup={dup_email_429.json()!r}"
        )

        new_headers = {name.lower() for name in new_email_429.headers.keys()}
        dup_headers = {name.lower() for name in dup_email_429.headers.keys()}
        assert "retry-after" in new_headers and "retry-after" in dup_headers, (
            "both branches' 429 responses must carry Retry-After"
        )
        assert (
            new_email_429.headers.get("retry-after")
            == dup_email_429.headers.get("retry-after")
        ), "the Retry-After value itself must not differ between branches"


# ----------------------------------------------------------------------------
# QA Gate 3 addition (2026-08-25): structural guard for a blind spot the
# behavioral tests above cannot cover. If a future edit split
# enforce_rate_limit into TWO call sites -- one inside
# _handle_new_email_registration, one inside _handle_duplicate_email_registration
# -- using the SAME scope="register" and the SAME limit on both, every
# behavioral test above would still pass: only one branch executes per
# request, so identical scope+limit produces identical observed 200/429
# sequences and identical response bodies. Design notes section 4 point 1
# forbids this anyway ("two call sites, even with identical arguments
# today, is a maintenance hazard") precisely because nothing observable
# would catch the drift the day someone edits only one of the two call
# sites. This test asserts the call site by source inspection instead of
# by behavior, so that class of regression fails loudly here.
# ----------------------------------------------------------------------------


def test_register_rate_limit_call_site_is_singular_and_shared():
    register_src = inspect.getsource(auth_module.register)
    new_email_src = inspect.getsource(auth_module._handle_new_email_registration)
    dup_email_src = inspect.getsource(auth_module._handle_duplicate_email_registration)

    assert register_src.count("enforce_rate_limit(") == 1, (
        "register() itself must contain exactly one enforce_rate_limit call "
        f"-- found {register_src.count('enforce_rate_limit(')}"
    )
    assert new_email_src.count("enforce_rate_limit(") == 0, (
        "_handle_new_email_registration must NOT call enforce_rate_limit -- "
        "the check belongs solely in the shared register() handler"
    )
    assert dup_email_src.count("enforce_rate_limit(") == 0, (
        "_handle_duplicate_email_registration must NOT call enforce_rate_limit "
        "-- the check belongs solely in the shared register() handler"
    )
    assert 'scope="register"' in register_src, (
        "register()'s enforce_rate_limit call must use the single shared "
        "scope=\"register\" literal, not a branch-specific scope"
    )
