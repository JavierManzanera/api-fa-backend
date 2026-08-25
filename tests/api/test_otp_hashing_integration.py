"""
OBJ-003 finding #7 -- OTP hashed at rest, end-to-end through the REAL
`/auth/forgot-password` flow (not `tests/factories.py`'s
`verification_factory`, which seeds a row directly and would not exercise
the endpoint's own hashing code path at all).

No Gherkin/AC doc exists for OBJ-003 (see tests/unit/test_otp_hashing.py's
docstring for the full explanation of why scenarios here are derived
directly from `docs/api/obj-003-design-notes.md` rather than translated
from a business-analyst doc). Scenario derivation for this file:

  - design notes section 1 ("no endpoint returns the OTP in an HTTP
    response") + the task's explicit constraint ("no endpoint ever returns
    the OTP... assert the stored value is NOT a 6-digit numeric string, or
    similar structural assertion, not a literal known-plaintext comparison")
    -> test_verification_code_column_is_not_a_plaintext_6_digit_otp,
    test_verification_code_column_is_a_sha256_hex_digest_shape,
    test_verification_code_column_equals_apps_own_hash_of_the_real_otp
  - design notes section 1.3 ("hashing happens only at the storage
    boundary, never affecting what the user actually receives") -- the
    real OTP is recovered out-of-band via the app's OTP delivery seam.
  - task item 1 ("Assert /verify-otp and /reset-password still work
    correctly end-to-end with the hashed storage (regression: the OTP
    lockout/rate-limit flows from OBJ-001 must still pass)") ->
    test_verify_otp_succeeds_end_to_end_with_the_real_issued_otp,
    test_reset_password_succeeds_end_to_end_with_the_real_issued_otp

--------------------------------------------------------------------------
OBJ-004 UPDATE (2026-08-24, qa-engineer, required non-optional carry-over
per obj-004-design-notes.md section 5.2 / dependency_graph.md's OBJ-004
Phase 1 section): this file ORIGINALLY recovered the real OTP via `capsys`
against the debug `print(...)`-based mock email sender in
`/auth/forgot-password`. OBJ-004 finding #10 (part 2) removes that print
statement entirely and replaces it with `app.core.notifications.
send_otp_notification(email, otp, *, purpose)` -- a monkeypatchable no-op
seam (Gate 1 APPROVED decision 3). This file's own docstring already
anticipated this exact breakage (OBJ-003's qa-engineer pass flagged it as a
known forward risk, not a surprise) and is updated HERE, in the same OBJ-004
Phase 2 pass that removes the print, per the design notes' own mandate:
"Required, non-optional carry-over for qa-engineer's OBJ-004 Phase 2 pass:
tests/api/test_otp_hashing_integration.py must switch from capsys-based
stdout capture to unittest.mock.patch(...) ... reading the real OTP from the
mock's call arguments instead."

`_forgot_password_and_capture_real_otp` below now patches
`app.api.v1.endpoints.auth.notifications.send_otp_notification` for the
duration of the `/forgot-password` call and reads the real OTP out of the
mock's call arguments -- never a hardcoded/known plaintext value, same
no-known-plaintext discipline as before, just a different (non-stdout)
recovery channel. No test's ASSERTIONS changed, only the mechanism used to
learn the real OTP value; this is a testability-mechanism fix, not a
weakening of what's being verified. PATCH-TARGET COUPLING note: see
tests/unit/test_otp_debug_print_removed.py's
test_forgot_password_calls_the_notification_seam_with_the_real_otp for the
full explanation of the assumed `from app.core import notifications` /
`notifications.send_otp_notification(...)` import style this patch target
depends on.

Requires Postgres -- see tests/README.md / tests/conftest.py module
docstring.

COLUMN-NAME COUPLING, flagged after the fact: `database-architect`'s
concurrent OBJ-003 schema review (dependency_graph.md, "OBJ-003 --
database-architect informal schema review") recommends renaming
`Verification.code` -> `code_hash` (non-blocking, still an open bikeshed as
of this pass, NOT taken per OBJ-003's Phase 3 report). This file reads
`Verification.code`/`verification.code` directly in four places -- if that
rename is ever taken, update those four references to `code_hash` alongside
the model/auth.py changes database-architect's own review already scoped.
"""

import re
from unittest.mock import patch

from sqlalchemy import select

from app.core import security
from app.models.verification import Verification

_NOTIFICATION_SEAM_PATCH_TARGET = (
    "app.api.v1.endpoints.auth.notifications.send_otp_notification"
)


async def _forgot_password_and_capture_real_otp(client, api_prefix, email) -> str:
    """Drives the real /auth/forgot-password endpoint with the OTP delivery
    seam mocked, and returns the real, freshly-issued OTP recovered from the
    mock's call arguments -- never a hardcoded/known plaintext value.
    """
    with patch(_NOTIFICATION_SEAM_PATCH_TARGET) as mock_send:
        resp = await client.post(f"{api_prefix}/auth/forgot-password", json={"email": email})
        assert resp.status_code == 200, resp.text

    assert mock_send.called, (
        "app.core.notifications.send_otp_notification must be called by "
        "/auth/forgot-password when a fresh OTP is issued -- it was not "
        "called at all, so no real OTP could be recovered for this test "
        "(see tests/unit/test_otp_debug_print_removed.py for the dedicated "
        "test of this call site)"
    )
    call_args = mock_send.call_args
    all_args = list(call_args.args) + list(call_args.kwargs.values())
    otp_candidates = [
        a for a in all_args if isinstance(a, str) and a.isdigit() and len(a) == 6
    ]
    assert len(otp_candidates) == 1, (
        f"expected exactly one 6-digit OTP string argument passed to "
        f"send_otp_notification, got args={call_args.args} "
        f"kwargs={call_args.kwargs}"
    )
    return otp_candidates[0]


async def _fetch_verification_row(db_session, email: str) -> Verification:
    result = await db_session.execute(
        select(Verification).filter(
            Verification.email == email, Verification.purpose == "reset_password"
        )
    )
    verification = result.scalars().first()
    assert verification is not None, (
        "expected /auth/forgot-password to have created a Verification row"
    )
    return verification


async def test_verification_code_column_is_not_a_plaintext_6_digit_otp(
    client, api_prefix, user_factory, db_session
):
    """Structural, not literal-plaintext, assertion -- per the task's
    explicit constraint that no test may assume it knows the real OTP value
    ahead of time via any channel OTHER than the app's own (mocked) send
    path. This test intentionally does NOT need `real_otp` at all: it only
    proves the stored value doesn't LOOK like a plaintext OTP, independent
    of what the real OTP happened to be."""
    user, _ = await user_factory(email="hashing-structural@example.com")
    await _forgot_password_and_capture_real_otp(client, api_prefix, user.email)

    verification = await _fetch_verification_row(db_session, user.email)

    assert not re.fullmatch(r"\d{6}", verification.code), (
        f"Verification.code must not be a plaintext 6-digit OTP string "
        f"after /auth/forgot-password (audit finding #7) -- got "
        f"{verification.code!r}, which still looks like a plaintext code"
    )


async def test_verification_code_column_is_a_sha256_hex_digest_shape(
    client, api_prefix, user_factory, db_session
):
    user, _ = await user_factory(email="hashing-shape@example.com")
    await _forgot_password_and_capture_real_otp(client, api_prefix, user.email)

    verification = await _fetch_verification_row(db_session, user.email)

    assert len(verification.code) == 64 and all(
        c in "0123456789abcdef" for c in verification.code.lower()
    ), (
        f"Verification.code must be a 64-char SHA-256 hex digest per "
        f"obj-003-design-notes.md section 1, got {verification.code!r} "
        f"(len={len(verification.code)})"
    )


async def test_verification_code_column_equals_apps_own_hash_of_the_real_otp(
    client, api_prefix, user_factory, db_session
):
    """Strongest version of the structural check: ties the stored value
    directly to app.core.security.hash_otp (the single source of truth per
    design notes section 1's module-ownership rule), using the REAL otp
    recovered out-of-band via the notification seam -- never a hardcoded
    'known' code."""
    user, _ = await user_factory(email="hashing-matches-app@example.com")
    real_otp = await _forgot_password_and_capture_real_otp(client, api_prefix, user.email)

    verification = await _fetch_verification_row(db_session, user.email)

    assert verification.code == security.hash_otp(real_otp), (
        "the stored Verification.code must equal security.hash_otp(the "
        "real OTP that was issued) -- ties storage directly to the app's "
        "own hashing primitive, not just 'looks like a hash'"
    )


async def test_verify_otp_succeeds_end_to_end_with_the_real_issued_otp(
    client, api_prefix, user_factory
):
    """Task item 1 regression requirement: /verify-otp must still work
    end-to-end once storage is hashed -- exercised via a REAL
    /forgot-password-issued OTP, not tests/factories.py's
    verification_factory (which bypasses the endpoint entirely)."""
    user, _ = await user_factory(email="hashing-verify-e2e@example.com")
    real_otp = await _forgot_password_and_capture_real_otp(client, api_prefix, user.email)

    resp = await client.post(
        f"{api_prefix}/auth/verify-otp", json={"email": user.email, "otp": real_otp}
    )

    assert resp.status_code == 200, (
        f"a correct, freshly-issued OTP must still verify successfully "
        f"under hashed storage. resp: {resp.status_code} {resp.text}"
    )


async def test_reset_password_succeeds_end_to_end_with_the_real_issued_otp(
    client, api_prefix, user_factory
):
    """Task item 1 regression requirement, /reset-password half."""
    user, _ = await user_factory(email="hashing-reset-e2e@example.com")
    real_otp = await _forgot_password_and_capture_real_otp(client, api_prefix, user.email)

    resp = await client.post(
        f"{api_prefix}/auth/reset-password",
        json={
            "email": user.email,
            "otp": real_otp,
            "new_password": "NewValidPass123!",
        },
    )

    assert resp.status_code == 200, (
        f"a correct, freshly-issued OTP must still reset the password "
        f"successfully under hashed storage. resp: {resp.status_code} "
        f"{resp.text}"
    )

    # Also confirm the underlying regression this task item calls out by
    # name: OTP lockout must still function against a hashed row. A wrong
    # guess against a FRESH otp for a second user must still be rejected
    # (can't reuse the consumed row above -- it's deleted on success).
    user2, _ = await user_factory(email="hashing-reset-e2e-lockout@example.com")
    await _forgot_password_and_capture_real_otp(client, api_prefix, user2.email)
    wrong_resp = await client.post(
        f"{api_prefix}/auth/verify-otp",
        json={"email": user2.email, "otp": "000000"},
    )
    assert wrong_resp.status_code == 400, (
        "a wrong code against a real, hashed-at-rest OTP must still be "
        "rejected 400 -- lockout/attempt-accounting must still function "
        "against hashed storage (task item 1's regression requirement)"
    )
