"""
OBJ-004 backlog item (OBJ-001 Gate 3, security-specialist, "New MEDIUM") --
`app.core.rate_limit.client_ip()` gains X-Forwarded-For-aware hop selection,
gated by a new `TRUSTED_PROXY_COUNT` Settings field. Pure-function unit
tests, no DB/HTTP -- `client_ip()` takes a duck-typed request-like object
(`.headers.get(...)`, `.client.host` / `.client is None`) and returns a
string; testing it directly here is a MORE precise instrument than an HTTP
round-trip would be, same rationale test_database_ssl.py already
established in this project for `_build_ssl_connect_arg`.

No Gherkin/AC doc exists for OBJ-004 -- see test_environment_settings.py's
docstring for the shared "derived from design notes" rationale. Scenario
derivation from obj-004-design-notes.md section 6.2:

  - "TRUSTED_PROXY_COUNT: int = 0. '0' means don't trust X-Forwarded-For at
    all, use the direct socket peer" -> TestTrustedProxyCountZeroIgnoresHeader.
  - "the N-th hop counting from the right is the address appended by the
    OUTERMOST trusted proxy... regardless of anything a client prepends" ->
    TestNthFromRightHopSelection.
  - "Bounds check, not a silent fallback to a wrong value: if len(hops) <
    trusted... falls back to request.client.host" -> TestBoundsCheckFallback.
  - "request.client.host if request.client else 'unknown'" (unchanged
    baseline behavior) -> TestNoClientFallback.
  - design notes section 6.1's own framing ("if the app trusted
    X-Forwarded-For unconditionally... any client could set
    X-Forwarded-For: 1.2.3.4 directly and spoof an arbitrary IP") is the
    THREAT MODEL TestTrustedProxyCountZeroIgnoresHeader defends against at
    the unit level; tests/api/test_rate_limit_ip_spoofing.py covers the
    same property at the HTTP/rate-limiter-integration level (task item 6's
    explicit "rate-limiting/lockout still can't be trivially bypassed"
    requirement).

TESTABILITY ASSUMPTION, flagged for `developer` (same class of flag already
established for the rate limiter's DB-session requirement and the
SecurityHeadersMiddleware CSP-path split): this file assumes `client_ip()`
reads `settings.TRUSTED_PROXY_COUNT` as a live ATTRIBUTE LOOKUP at call
time (as design notes section 6.2's illustrative code shows: `trusted =
settings.TRUSTED_PROXY_COUNT` inside the function body), not a value
captured into a module-level constant at import time. This is what lets
`monkeypatch.setattr(config_settings, "TRUSTED_PROXY_COUNT", N)` work
per-test without a subprocess. If implemented as an import-time constant
instead, these tests will fail to observe the monkeypatched value (not a
crash -- a clean, misleading-looking assertion mismatch) -- treat that as a
testability signal to fix, not a broken test.

Today (red phase): `app.core.rate_limit.client_ip()` has no
X-Forwarded-For awareness at all (`return request.client.host if
request.client else "unknown"`, unconditionally) and `Settings` has no
`TRUSTED_PROXY_COUNT` field. Every "N-th hop" test below therefore fails
today; the TRUSTED_PROXY_COUNT=0-ignores-header tests currently pass
vacuously (the header is already ignored today, just not because of any
TRUSTED_PROXY_COUNT check) -- kept as forward-looking regression anchors,
same convention as this project's other "already-correct baseline" tests.
"""

import pytest

from app.core import rate_limit
from app.core.config import settings as config_settings


class _FakeClient:
    def __init__(self, host):
        self.host = host


class _FakeHeaders(dict):
    """Case-insensitive .get(), matching Starlette's Headers interface
    shape (the only method client_ip() is documented to call on
    request.headers)."""

    def get(self, key, default=None):
        key_lower = key.lower()
        for k, v in self.items():
            if k.lower() == key_lower:
                return v
        return default


class _FakeRequest:
    def __init__(self, *, client_host="203.0.113.99", headers=None):
        self.client = _FakeClient(client_host) if client_host is not None else None
        self.headers = _FakeHeaders(headers or {})


@pytest.fixture
def trusted_proxy_count(monkeypatch):
    def _set(value: int):
        monkeypatch.setattr(config_settings, "TRUSTED_PROXY_COUNT", value)

    return _set


class TestTrustedProxyCountZeroIgnoresHeader:
    """design notes section 6.2: '0 means don't trust X-Forwarded-For at
    all, use the direct socket peer -- the maximally safe default, and
    exactly today's existing (unconfigured) behavior.'"""

    def test_direct_peer_used_when_no_xff_header(self, trusted_proxy_count):
        trusted_proxy_count(0)
        request = _FakeRequest(client_host="198.51.100.1")
        assert rate_limit.client_ip(request) == "198.51.100.1"

    def test_xff_header_completely_ignored_when_trust_is_zero(self, trusted_proxy_count):
        """The core anti-spoofing property: even a PRESENT, well-formed
        X-Forwarded-For header must not influence the result at all when
        TRUSTED_PROXY_COUNT=0."""
        trusted_proxy_count(0)
        request = _FakeRequest(
            client_host="198.51.100.1",
            headers={"x-forwarded-for": "1.2.3.4"},
        )
        assert rate_limit.client_ip(request) == "198.51.100.1", (
            "X-Forwarded-For must be completely ignored when "
            "TRUSTED_PROXY_COUNT=0 -- trusting it here would let any client "
            "spoof its own rate-limit identity (design notes section 6.1)"
        )

    def test_xff_header_with_many_spoofed_hops_still_ignored(self, trusted_proxy_count):
        trusted_proxy_count(0)
        request = _FakeRequest(
            client_host="198.51.100.1",
            headers={"x-forwarded-for": "9.9.9.9, 8.8.8.8, 7.7.7.7"},
        )
        assert rate_limit.client_ip(request) == "198.51.100.1"


class TestNthFromRightHopSelection:
    """design notes section 6.2: 'the N-th hop counting from the right is
    the address appended by the OUTERMOST trusted proxy... correct
    regardless of anything a client prepends earlier in the header.'"""

    def test_trust_one_proxy_picks_rightmost_hop(self, trusted_proxy_count):
        trusted_proxy_count(1)
        request = _FakeRequest(
            client_host="10.0.0.1",  # the proxy's own socket peer address -- irrelevant once trusted
            headers={"x-forwarded-for": "1.2.3.4, 5.6.7.8"},
        )
        assert rate_limit.client_ip(request) == "5.6.7.8", (
            "with TRUSTED_PROXY_COUNT=1, the rightmost XFF entry is the one "
            "appended by the single trusted proxy based on the real TCP "
            "connection it observed -- '1.2.3.4' is attacker-prependable "
            "and must be ignored"
        )

    def test_trust_two_proxies_picks_second_from_right(self, trusted_proxy_count):
        trusted_proxy_count(2)
        request = _FakeRequest(
            client_host="10.0.0.1",
            headers={"x-forwarded-for": "1.2.3.4, 5.6.7.8, 9.9.9.9"},
        )
        assert rate_limit.client_ip(request) == "5.6.7.8", (
            "with TRUSTED_PROXY_COUNT=2, the address 2 hops from the right "
            "is the one appended by the OUTERMOST of the two trusted "
            "proxies -- '9.9.9.9' (the innermost hop, closest to the app) "
            "and '1.2.3.4' (client-prependable) must both be ignored"
        )

    def test_whitespace_around_hops_is_stripped(self, trusted_proxy_count):
        trusted_proxy_count(1)
        request = _FakeRequest(
            client_host="10.0.0.1",
            headers={"x-forwarded-for": " 1.2.3.4 ,  5.6.7.8 "},
        )
        assert rate_limit.client_ip(request) == "5.6.7.8"

    def test_client_cannot_defeat_selection_by_prepending_extra_fake_hops(self, trusted_proxy_count):
        """The exact attack design notes section 6.2 names: a client
        prepending arbitrarily many fake hops before the real proxy-chain
        entries must not shift which hop gets selected, since selection
        counts from the right (anchored on the trusted proxies), not the
        left."""
        trusted_proxy_count(1)
        request = _FakeRequest(
            client_host="10.0.0.1",
            headers={
                "x-forwarded-for": "9.9.9.9, 8.8.8.8, 7.7.7.7, 6.6.6.6, 5.6.7.8"
            },
        )
        assert rate_limit.client_ip(request) == "5.6.7.8"


class TestBoundsCheckFallback:
    """design notes section 6.2: 'if len(hops) < trusted... falls back to
    request.client.host rather than indexing out of range or trusting a
    too-short, ambiguous header.'"""

    def test_fewer_hops_than_trusted_count_falls_back_to_direct_peer(self, trusted_proxy_count):
        trusted_proxy_count(3)
        request = _FakeRequest(
            client_host="10.0.0.1",
            headers={"x-forwarded-for": "1.2.3.4, 5.6.7.8"},  # only 2 hops, 3 trusted
        )
        assert rate_limit.client_ip(request) == "10.0.0.1", (
            "fewer XFF entries than TRUSTED_PROXY_COUNT must fall back to "
            "the direct socket peer, not raise an IndexError or trust an "
            "ambiguous/too-short header"
        )

    def test_missing_xff_header_with_nonzero_trust_falls_back_to_direct_peer(self, trusted_proxy_count):
        trusted_proxy_count(1)
        request = _FakeRequest(client_host="10.0.0.1", headers={})
        assert rate_limit.client_ip(request) == "10.0.0.1"

    def test_empty_xff_header_with_nonzero_trust_falls_back_to_direct_peer(self, trusted_proxy_count):
        trusted_proxy_count(1)
        request = _FakeRequest(client_host="10.0.0.1", headers={"x-forwarded-for": ""})
        assert rate_limit.client_ip(request) == "10.0.0.1"


class TestNoClientFallback:
    """Unchanged baseline behavior (not an OBJ-004 change, kept as a
    regression anchor): request.client can be None depending on the ASGI
    transport."""

    def test_no_client_and_trust_zero_returns_unknown_literal(self, trusted_proxy_count):
        trusted_proxy_count(0)
        request = _FakeRequest(client_host=None)
        assert rate_limit.client_ip(request) == "unknown"

    def test_no_client_and_nonzero_trust_but_no_xff_returns_unknown_literal(self, trusted_proxy_count):
        trusted_proxy_count(2)
        request = _FakeRequest(client_host=None, headers={})
        assert rate_limit.client_ip(request) == "unknown"


class TestTrustedProxyCountSettingsDefault:
    def test_trusted_proxy_count_defaults_to_zero(self):
        """design notes section 6.2: 'new Settings field
        TRUSTED_PROXY_COUNT: int = 0.' tests/conftest.py deliberately does
        NOT set this env var, so this directly observes the real default
        for the whole suite (no subprocess needed -- unlike ENVIRONMENT/
        POSTGRES_SSL_MODE, this field has a safe default, not a required-no-
        default shape)."""
        from app.core.config import settings

        assert settings.TRUSTED_PROXY_COUNT == 0
