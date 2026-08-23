"""
OBJ-003 finding #7 -- OTP hashed at rest (HMAC-SHA256), unit-level.

NO business-analyst / Gherkin doc exists for OBJ-003 (per the agent chain in
.ai-context/dependency_graph.md: `solution-architect -> database-architect
|| qa-engineer -> developer` -- backend/infra hardening, no user-facing
story). Scenarios below are therefore derived directly from
`docs/api/obj-003-design-notes.md` section 1, not translated from Gherkin --
each design decision in that section implies at least one testable
scenario, enumerated below with the design-notes anchor it comes from:

  - section 1 decision ("HMAC-SHA256... stored as a hex digest") ->
    test_hash_otp_output_is_not_plaintext, test_hash_otp_output_is_a_64_char_hex_digest
  - section 1 (HMAC over a fixed input must be deterministic, or verification
    would never work) -> test_hash_otp_is_deterministic_for_the_same_code
  - section 1 (a hash function with collisions across distinct inputs would
    defeat the whole point) -> test_hash_otp_differs_for_different_codes
  - section 1.1 Option B, the actual chosen construction
    (`HMAC(SECRET_KEY, "api-fa-backend:otp-hmac:v1", sha256)`-derived key,
    then `HMAC(derived_key, code, sha256).hexdigest()`) ->
    test_hash_otp_matches_the_designed_key_derivation_construction. This is
    the literal construction the task asked to confirm against; verified
    directly against obj-003-design-notes.md section 1.1's illustrative code
    (own computation below, independent of app.core.security's internals) --
    NOT cross-checked against a `database-architect` Phase 1 section in
    dependency_graph.md, since no such section existed in the graph at the
    time this pass read it (concurrent pass, informal review only, no schema
    rename decided yet -- see obj-003-design-notes.md section 1.4).
  - section 1.3 ("Verify-time comparison moves to hmac.compare_digest... this
    closes a (much smaller, secondary) digest-comparison timing concern") ->
    test_verify_otp_hash_accepts_the_correct_code,
    test_verify_otp_hash_rejects_the_wrong_code,
    test_verify_otp_hash_uses_constant_time_comparison_not_bare_equality
  - section 1.3 ("`_check_and_consume_otp` changes from `if verification.code
    != otp:` to `if not security.verify_otp_hash(otp, verification.code):`")
    -> test_check_and_consume_otp_compares_via_hash_not_plain_equality
    (static source introspection of auth.py, same technique as
    tests/unit/test_otp_generation.py's CSPRNG check -- a call-count/behavior
    test can't easily distinguish "hashed and constant-time-compared" from
    "hashed and compared with `==`" without also verifying which comparison
    primitive fires, so source-level assertion is the more precise
    instrument here, same rationale as test_otp_generation.py's docstring).

Module ownership (obj-003-design-notes.md section 1, citing
obj-001-design-notes.md section 1's "module ownership" rule): `hash_otp` /
`verify_otp_hash` live in `app/core/security.py`, alongside
`get_password_hash`/`verify_password`/JWT encode-decode. Today (red phase)
neither function exists -- every test below fails with AttributeError, not
a clean assertion failure, which is the correct "missing implementation"
signal for a function that doesn't exist yet (same convention already
established in this project, e.g. OBJ-002's `User.token_version`
AttributeError during its own red phase).

No DB, no HTTP -- pure unit tests, same tier as tests/unit/test_security.py.
"""

import hashlib
import hmac
import inspect

import app.api.v1.endpoints.auth as auth_endpoints_module
from app.core import security
from app.core.config import settings

_OTP_HMAC_CONTEXT = b"api-fa-backend:otp-hmac:v1"


def _expected_hash_via_design_notes_construction(code: str) -> str:
    """Independent re-implementation of obj-003-design-notes.md section 1.1's
    Option B construction, computed here rather than imported from
    app.core.security -- this is what makes
    test_hash_otp_matches_the_designed_key_derivation_construction a genuine
    check of the *chosen* construction, not a tautology that would pass for
    any arbitrary hashing scheme security.hash_otp happened to implement."""
    derived_key = hmac.new(
        settings.SECRET_KEY.encode("utf-8"), _OTP_HMAC_CONTEXT, hashlib.sha256
    ).digest()
    return hmac.new(derived_key, code.encode("utf-8"), hashlib.sha256).hexdigest()


class TestHashOtpOutputShape:
    def test_hash_otp_output_is_not_plaintext(self):
        assert security.hash_otp("123456") != "123456", (
            "hash_otp('123456') must not return the plaintext code itself "
            "(design notes section 1: 'stored as a hex digest')"
        )

    def test_hash_otp_output_is_a_64_char_hex_digest(self):
        digest = security.hash_otp("123456")
        assert len(digest) == 64, (
            f"SHA-256 hex digest must be 64 hex characters, got length "
            f"{len(digest)} ({digest!r})"
        )
        assert all(c in "0123456789abcdef" for c in digest.lower()), (
            f"hash_otp output must be a hex string, got {digest!r}"
        )


class TestHashOtpDeterminismAndCollisionResistance:
    def test_hash_otp_is_deterministic_for_the_same_code(self):
        assert security.hash_otp("654321") == security.hash_otp("654321"), (
            "the same code must hash to the same digest, or verify_otp_hash "
            "could never match a stored value against a freshly-submitted code"
        )

    def test_hash_otp_differs_for_different_codes(self):
        assert security.hash_otp("111111") != security.hash_otp("222222")


class TestHashOtpKeyDerivationConstruction:
    """The task's explicit instruction: confirm the factory/app hashing
    against the exact 'HMAC(SECRET_KEY, "api-fa-backend:otp-hmac:v1", sha256)
    -derived-key' construction from obj-003-design-notes.md section 1.1,
    Option B (the decided option, not the rejected A/C alternatives)."""

    def test_hash_otp_matches_the_designed_key_derivation_construction(self):
        code = "042017"
        expected = _expected_hash_via_design_notes_construction(code)
        assert security.hash_otp(code) == expected, (
            "hash_otp(code) must equal HMAC(HMAC(SECRET_KEY, "
            "b'api-fa-backend:otp-hmac:v1', sha256).digest(), code, "
            "sha256).hexdigest() -- the specific Option B construction "
            "decided in obj-003-design-notes.md section 1.1. A different "
            "hash construction (e.g. reusing SECRET_KEY raw -- rejected "
            "Option A, or a dedicated new secret -- rejected Option C, or a "
            "non-HMAC hash entirely) would fail this test even if it also "
            "produced a 64-char hex digest."
        )

    def test_hash_otp_does_not_reuse_raw_secret_key_as_the_hmac_key_directly(self):
        """Rejected Option A (obj-003-design-notes.md section 1.1 table):
        `hmac.new(SECRET_KEY.encode(), code, sha256)` with NO key
        derivation step. If hash_otp used this instead of the decided
        Option B, it would coincidentally produce the same 64-char hex
        shape but a DIFFERENT digest value than the derived-key
        construction -- this test would catch that even if the
        'construction' test above were weaker."""
        code = "555555"
        raw_key_digest = hmac.new(
            settings.SECRET_KEY.encode("utf-8"), code.encode("utf-8"), hashlib.sha256
        ).hexdigest()
        assert security.hash_otp(code) != raw_key_digest, (
            "hash_otp must NOT be equivalent to hmac.new(SECRET_KEY, code, "
            "sha256) with no key-derivation step (rejected Option A) -- key "
            "separation (Option B, decided) requires an intermediate "
            "derived key, not the raw SECRET_KEY bytes"
        )


class TestVerifyOtpHash:
    def test_verify_otp_hash_accepts_the_correct_code(self):
        stored = security.hash_otp("777777")
        assert security.verify_otp_hash("777777", stored) is True

    def test_verify_otp_hash_rejects_the_wrong_code(self):
        stored = security.hash_otp("777777")
        assert security.verify_otp_hash("000000", stored) is False

    def test_verify_otp_hash_rejects_a_plaintext_stored_value(self):
        """Defense against a half-migrated state: if `stored_hash` is
        somehow still plaintext (e.g. a pre-OBJ-003 row, per design notes
        section 1.4's self-healing/fail-closed migration story), the
        comparison must fail closed (return False), never raise and never
        accidentally match."""
        assert security.verify_otp_hash("777777", "777777") is False

    def test_verify_otp_hash_uses_constant_time_comparison_not_bare_equality(self):
        """Static source check, same technique/rationale as
        tests/unit/test_otp_generation.py's CSPRNG check: a call-count test
        can't distinguish 'hashed + hmac.compare_digest' from 'hashed +
        plain ==' without inspecting which primitive is actually used
        (design notes section 1.3's explicit closes-a-secondary-timing-
        concern rationale for hmac.compare_digest specifically)."""
        source = inspect.getsource(security.verify_otp_hash)
        assert "compare_digest" in source, (
            "verify_otp_hash must use hmac.compare_digest (or an "
            "equivalent constant-time comparator) for the digest "
            "comparison, per obj-003-design-notes.md section 1.3 -- not a "
            "bare `==`"
        )


class TestCheckAndConsumeOtpUsesHashComparison:
    """obj-003-design-notes.md section 1.3, the exact diff described:
    '`_check_and_consume_otp` (`auth.py:73`) changes from `if
    verification.code != otp:` to `if not security.verify_otp_hash(otp,
    verification.code):`'. Static introspection, not behavioral -- see the
    file docstring's rationale for why source-level is the right tool here."""

    def test_check_and_consume_otp_compares_via_hash_not_plain_equality(self):
        source = inspect.getsource(auth_endpoints_module._check_and_consume_otp)
        assert "verify_otp_hash" in source, (
            "_check_and_consume_otp must call security.verify_otp_hash(...) "
            "for the code comparison, per obj-003-design-notes.md section "
            "1.3 -- it currently still does a bare `verification.code != "
            "otp` plaintext comparison"
        )
        assert "verification.code != otp" not in source, (
            "the old plaintext `!=` comparison must be fully replaced, not "
            "kept alongside the new hash check"
        )
