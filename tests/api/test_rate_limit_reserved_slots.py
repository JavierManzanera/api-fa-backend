"""
OBJ-014 -- Finding #20 mitigation (docs/security/audit-report.md "Gate 3 --
Verificacion OBJ-013" section 3d): the reserved fresh-IP slot mechanism.
Traces to docs/api/obj-014-design-notes.md sections 2/3.

THE VULNERABILITY (pre-fix): `enforce_rate_limit`'s email-only check is a
plain COUNT(*) keyed on (scope, email) alone, no `ip` predicate at all. A
single fixed attacker IP can drive that tally to `limit` using a victim's
email, and the victim's own next legitimate request -- from their own,
different, real IP -- is then blocked too, because the bucket is shared
indiscriminately between whoever supplies that email string.

THE FIX: the last `RATE_LIMIT_EMAIL_RESERVED_SLOTS` hits of each scope's
email-keyed `limit` are reserved for an IP that has NOT yet been recorded
against that email in the current window. Total ceiling per email/window
is UNCHANGED (still `limit`) -- this restricts WHO may spend the last slice
of the existing budget, it is not a new budget.

TESTABILITY: the shared `client` fixture's httpx.ASGITransport assigns one
single synthetic real IP to every request (see
tests/api/test_rate_limit_keying.py's own docstring), so distinct *real*
IPs cannot be produced merely by varying the X-Forwarded-For header at the
suite's default TRUSTED_PROXY_COUNT=0 -- that header is decorative
(tests/unit/test_client_ip.py, tests/api/test_rate_limit_ip_spoofing.py).
This file therefore monkeypatches `settings.TRUSTED_PROXY_COUNT = 1` (same
technique test_client_ip.py itself uses to control client_ip()'s output)
so that a single, well-formed X-Forwarded-For hop IS trusted as the
request's real observed IP -- letting each test drive genuinely distinct
per-request IPs through the full HTTP stack, not just distinct headers.

Uses /forgot-password (FORGOT_PASSWORD_EMAIL_LIMIT = 5, anti-enumeration:
any email always returns 200 without existing first -- OBJ-007 finding #6),
same endpoint tests/api/test_rate_limit_ip_spoofing.py already uses for
this exact reason.

Requires Postgres -- see tests/README.md / tests/conftest.py.
"""

import pytest

from app.core import rate_limit
from app.core.config import settings as config_settings

FORGOT_PASSWORD_EMAIL_LIMIT = 5  # app/api/v1/endpoints/auth.py FORGOT_PASSWORD_RATE_LIMIT_PER_MINUTE
RESERVED_SLOTS_DEFAULT = 1  # obj-014-design-notes.md section 3/6
MAIN_POOL_LIMIT = FORGOT_PASSWORD_EMAIL_LIMIT - RESERVED_SLOTS_DEFAULT  # 4


@pytest.fixture(autouse=True)
def trust_one_proxy_hop(monkeypatch):
    """All tests in this file need a genuinely distinct real IP per
    request, driven via a single trusted X-Forwarded-For hop -- see module
    docstring. Explicit RATE_LIMIT_EMAIL_RESERVED_SLOTS=1 pins the default
    regardless of what a future objective might change it to."""
    monkeypatch.setattr(config_settings, "TRUSTED_PROXY_COUNT", 1)
    monkeypatch.setattr(config_settings, "RATE_LIMIT_EMAIL_RESERVED_SLOTS", RESERVED_SLOTS_DEFAULT)


async def _forgot_password(client, api_prefix, email, ip):
    return await client.post(
        f"{api_prefix}/auth/forgot-password",
        json={"email": email},
        headers={"X-Forwarded-For": ip},
    )


class TestVictimFreshIpProtectedAfterAttackerExhaustsMainPool:
    """The core finding #20 closure proof: a single fixed attacker IP
    hammering the victim's email must NOT be able to deny the victim's own,
    different, fresh IP -- the reserved slot guarantees it at least one
    request through, even though the attacker's own repeated attempts in
    that same band are refused."""

    async def test_attacker_fills_main_pool_then_victim_fresh_ip_still_gets_through(
        self, client, api_prefix
    ):
        email = "victim-reserved-slot@example.com"
        attacker_ip = "198.51.100.10"
        victim_ip = "198.51.100.20"

        # 1) Attacker's fixed IP fills the main pool (limit - reserved = 4
        #    requests) -- behaves exactly as pre-OBJ-014: any IP may
        #    contribute, uncapped, first-come-first-served.
        statuses = []
        for _ in range(MAIN_POOL_LIMIT):
            resp = await _forgot_password(client, api_prefix, email, attacker_ip)
            statuses.append(resp.status_code)
        assert statuses == [200] * MAIN_POOL_LIMIT, (
            f"the first {MAIN_POOL_LIMIT} requests (the main pool) from a "
            f"single attacker IP must all succeed, unrestricted -- got {statuses}. "
            "This also demonstrates a flat per-IP cap is NOT what's "
            "implemented: a cap below main_pool_limit would fail this "
            "assertion (see design notes section 2.2 for why a flat per-IP "
            "cap was rejected -- it would reopen findings #2/#16)."
        )

        # 2) The SAME attacker IP tries again, still within `limit` overall
        #    (email_hit_count == 4 < limit == 5) -- but it's now in the
        #    reserved band, and this IP has already been recorded against
        #    this email this window, so it is refused.
        attacker_retry = await _forgot_password(client, api_prefix, email, attacker_ip)
        assert attacker_retry.status_code == 429, (
            "a REPEAT attacker IP must be refused in the reserved band even "
            "though the raw email tally (4) has not yet reached `limit` (5) "
            "-- this is the mechanism that closes finding #20: the last "
            "reserved slot(s) are off-limits to an IP already seen for this "
            f"email this window. Got {attacker_retry.status_code}: {attacker_retry.text}"
        )

        # 3) The VICTIM's own, genuinely fresh IP (never recorded against
        #    this email this window) consumes the still-available reserved
        #    slot and gets through -- even though the attacker had already
        #    hammered the bucket right up to the boundary.
        victim_resp = await _forgot_password(client, api_prefix, email, victim_ip)
        assert victim_resp.status_code == 200, (
            "the victim's own fresh IP must be guaranteed at least one "
            "request through via the reserved slot, regardless of how "
            f"thoroughly the attacker's fixed IP hammered the main pool -- "
            f"got {victim_resp.status_code}: {victim_resp.text}"
        )


class TestTotalCeilingPerEmailUnchanged:
    """The reserved-slot mechanism must NOT weaken the existing per-email
    ceiling -- it redistributes WHO can spend the last slice, it does not
    grant extra budget. Once `limit` total hits have landed (regardless of
    which IPs), the bucket is hard-closed to everyone, including a brand
    new, never-before-seen IP -- proving the reserved pool is a bounded
    subset of the SAME total, not an unlimited add-on (design notes section
    2.3/2.4: this is exactly what distinguishes the fix from a broken
    'unconditional first-time-IP-always-passes' rule, which would let a
    fresh IP through here too)."""

    async def test_ceiling_still_exactly_limit_a_third_fresh_ip_is_still_blocked(
        self, client, api_prefix
    ):
        email = "ceiling-unchanged@example.com"
        attacker_ip = "198.51.100.30"
        victim_ip = "198.51.100.40"
        third_fresh_ip = "198.51.100.50"

        # Consume the main pool from the attacker IP.
        for _ in range(MAIN_POOL_LIMIT):
            resp = await _forgot_password(client, api_prefix, email, attacker_ip)
            assert resp.status_code == 200, resp.text

        # Consume the single reserved slot from the victim's fresh IP.
        victim_resp = await _forgot_password(client, api_prefix, email, victim_ip)
        assert victim_resp.status_code == 200, (
            f"expected the reserved slot to still be available -- got "
            f"{victim_resp.status_code}: {victim_resp.text}"
        )

        # Total hits recorded for this email this window: MAIN_POOL_LIMIT + 1
        # == FORGOT_PASSWORD_EMAIL_LIMIT exactly -- the ceiling is reached.
        # A THIRD, never-before-seen IP must still be blocked: if the
        # mechanism were an unbounded "first-time IP always passes" rule
        # (design notes section 2.3, rejected), this fresh IP would
        # incorrectly succeed here.
        third_resp = await _forgot_password(client, api_prefix, email, third_fresh_ip)
        assert third_resp.status_code == 429, (
            "the total per-email ceiling must remain exactly "
            f"{FORGOT_PASSWORD_EMAIL_LIMIT} -- a THIRD fresh IP, arriving "
            "after the ceiling was already reached by "
            f"{MAIN_POOL_LIMIT} (main pool) + 1 (reserved slot) requests, "
            "must still be refused. A pass here would mean the reserved "
            "pool is an ADDITIONAL, unbounded budget rather than a bounded "
            f"subset of the same `limit` -- got {third_resp.status_code}: "
            f"{third_resp.text}. (This is precisely the failure mode design "
            "notes section 2.3 rejects: an unconditional "
            "first-time-IP-always-passes rule would let this request "
            "through, reopening finding #17's distributed-attacker bypass.)"
        )


class TestReservedSlotsSettingDisablesMitigationWhenZero:
    """design notes section 6: RATE_LIMIT_EMAIL_RESERVED_SLOTS=0 explicitly
    disables the mitigation -- main_pool_limit becomes `limit`, identical
    to pre-OBJ-014 behavior (a repeat attacker IP is allowed to consume the
    entire budget itself, and a late-arriving fresh IP gets no special
    protection once the tally is exhausted)."""

    async def test_zero_reserved_slots_lets_attacker_consume_entire_budget_alone(
        self, client, api_prefix, monkeypatch
    ):
        monkeypatch.setattr(config_settings, "RATE_LIMIT_EMAIL_RESERVED_SLOTS", 0)
        email = "reserved-slots-disabled@example.com"
        attacker_ip = "198.51.100.60"
        victim_ip = "198.51.100.70"

        statuses = []
        for _ in range(FORGOT_PASSWORD_EMAIL_LIMIT):
            resp = await _forgot_password(client, api_prefix, email, attacker_ip)
            statuses.append(resp.status_code)
        assert statuses == [200] * FORGOT_PASSWORD_EMAIL_LIMIT, (
            f"with the mitigation disabled (reserved=0), a single attacker "
            f"IP must be able to consume the full {FORGOT_PASSWORD_EMAIL_LIMIT}-"
            f"request budget alone, identical to pre-OBJ-014 behavior -- got {statuses}"
        )

        victim_resp = await _forgot_password(client, api_prefix, email, victim_ip)
        assert victim_resp.status_code == 429, (
            "with reserved=0, a fresh victim IP gets NO special protection "
            "once the shared tally is exhausted -- confirms 0 is a genuine "
            f"opt-out, not a no-op. Got {victim_resp.status_code}: {victim_resp.text}"
        )


class TestFix20DoesNotWeakenExistingEmailBruteForceProtection:
    """Regression guard: single-IP brute force against one email must never
    get MORE total requests through than before OBJ-014 (still capped well
    below/at `limit`) -- the reserved-slot mechanism only ever RESTRICTS who
    can spend the tail of the budget, it never loosens the existing cap.

    IMPORTANT, precisely per design notes section 2/6 (this is the
    documented trade-off, not a bug): a single IP that never rotates can
    only ever claim the MAIN POOL (`limit - reserved` == 4 at the default),
    because by the time the tally reaches the reserved band, that same IP
    has necessarily already been recorded against this email and is
    therefore ineligible for the reserved slot(s). A single non-rotating
    actor is CAPPED AT 4, not 5, post-OBJ-014 -- strictly less than (never
    more than) the pre-OBJ-014 ceiling of 5, which is exactly the
    "must not weaken protection" property this class exists to confirm."""

    async def test_single_ip_single_email_capped_at_main_pool_not_beyond_original_limit(
        self, client, api_prefix
    ):
        email = "single-ip-brute-force-regression@example.com"
        ip = "198.51.100.80"

        statuses = []
        for _ in range(FORGOT_PASSWORD_EMAIL_LIMIT + 1):
            resp = await _forgot_password(client, api_prefix, email, ip)
            statuses.append(resp.status_code)

        assert statuses[:MAIN_POOL_LIMIT] == [200] * MAIN_POOL_LIMIT, (
            f"a single, never-rotated IP must get its main-pool allotment "
            f"({MAIN_POOL_LIMIT} requests) through -- got {statuses}"
        )
        assert all(status == 429 for status in statuses[MAIN_POOL_LIMIT:]), (
            f"a single, never-rotated IP must be refused from the "
            f"{MAIN_POOL_LIMIT + 1}th request onward (it can never claim the "
            f"reserved slot -- it was already recorded against this email on "
            f"its first request) -- and must NEVER exceed the pre-OBJ-014 "
            f"ceiling of {FORGOT_PASSWORD_EMAIL_LIMIT} total successes "
            f"regardless. Got {statuses}"
        )
        assert statuses.count(200) <= FORGOT_PASSWORD_EMAIL_LIMIT, (
            f"total successes for one email in one window must never exceed "
            f"the original {FORGOT_PASSWORD_EMAIL_LIMIT} ceiling -- got {statuses}"
        )


class TestReservedSlotsClampedDefensively:
    """design notes section 3: `reserved_slots` is clamped defensively so it
    can never consume the ENTIRE pool (main_pool_limit >= 1 always,
    provided limit > 0), even if a future explicit per-call override passed
    a value >= `limit`. No current call site does this (all 6 rely on the
    centralized settings default), so this is exercised via a DIRECT call
    to `enforce_rate_limit`, bypassing the HTTP layer -- the same
    "more precise instrument" rationale tests/unit/test_client_ip.py
    already established for testing this module's internals directly."""

    async def test_reserved_slots_larger_than_limit_still_leaves_main_pool_of_at_least_one(
        self, db_session
    ):
        scope = "obj014-clamp-test-scope"
        email = "clamp-test@example.com"
        attacker_ip = "203.0.113.100"
        victim_ip = "203.0.113.200"
        third_fresh_ip = "203.0.113.201"
        fourth_fresh_ip = "203.0.113.202"
        limit = 3

        # reserved_slots (10) >> limit (3) -- without the clamp this would
        # make main_pool_limit negative/zero and the email-only band check
        # would misbehave. The clamp caps resolved_reserved to `limit - 1`
        # == 2 (never the WHOLE pool), leaving main_pool_limit = limit -
        # resolved_reserved == 3 - 2 == 1: exactly one unrestricted slot,
        # the smallest a main pool can ever be, regardless of how large a
        # `reserved_slots` override is requested.
        kwargs = dict(
            db=db_session,
            scope=scope,
            email=email,
            limit=limit,
            ip_limit=1_000_000,  # keep the IP-only check out of the way
            reserved_slots=10,
        )

        # Main pool (clamped floor of 1): unrestricted, any IP -- the
        # attacker's first request always gets through.
        first = await rate_limit.enforce_rate_limit(ip=attacker_ip, **kwargs)
        assert first is None, (
            "the clamped main pool must still accept at least one request "
            "unrestricted (main_pool_limit floors at 1, never 0 or negative)"
        )

        # Second request, same (already-seen) attacker IP -- now in the
        # (clamped) reserved band (email_hit_count == 1 == main_pool_limit)
        # -- must be refused.
        with pytest.raises(Exception) as exc_info:
            await rate_limit.enforce_rate_limit(ip=attacker_ip, **kwargs)
        assert getattr(exc_info.value, "status_code", None) == 429, (
            "a repeat IP must be refused once inside the (clamped) reserved "
            f"band -- got {exc_info.value!r}"
        )

        # Two genuinely fresh IPs still get the two clamped reserved slots
        # (resolved_reserved == min(10, limit - 1) == 2).
        second = await rate_limit.enforce_rate_limit(ip=victim_ip, **kwargs)
        third = await rate_limit.enforce_rate_limit(ip=third_fresh_ip, **kwargs)
        assert second is None and third is None, (
            "both clamped reserved slots (2, not the requested 10) must "
            "still be available to distinct fresh IPs"
        )

        # Total ceiling is still exactly `limit` (3): a FOURTH fresh IP,
        # arriving after 1 (main pool) + 2 (reserved) == 3 == limit hits
        # have already landed, must now be hard-blocked -- proving the
        # requested reserved_slots=10 never expanded the total budget.
        with pytest.raises(Exception) as exc_info:
            await rate_limit.enforce_rate_limit(ip=fourth_fresh_ip, **kwargs)
        assert getattr(exc_info.value, "status_code", None) == 429
