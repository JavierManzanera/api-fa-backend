"""
OBJ-004 finding #10, part 2 -- OTP debug print removal, structural/
source-inspection half. Companion to tests/api/test_otp_hashing_integration.py
(updated in this same pass to use the new seam instead of capsys) and
tests/api/test_audit_logging.py (which covers the replacement
`auth.otp.requested` log event). This file is the direct structural-check
counterpart to tests/unit/test_otp_generation.py's own
`inspect.getsource`-based technique for the SAME reason: a call-count or
mock-based test alone cannot prove the literal `print(...)` statement is
GONE from the source -- only reading the source can.

No Gherkin/AC doc exists for OBJ-004 -- see test_environment_settings.py's
docstring for the shared "derived from design notes" rationale. Scenario
derivation from obj-004-design-notes.md section 5:

  - "Confirmed via direct read of app/api/v1/endpoints/auth.py:263-266...
    the print still exists" + "Decision: remove the print, replace with a
    non-secret-leaking audit log line + a minimal delivery seam" ->
    test_forgot_password_module_contains_no_print_call,
    test_forgot_password_module_no_longer_prints_the_email_mock_banner.
  - "app/core/notifications.py (new)... send_otp_notification(email, otp,
    *, purpose)... monkeypatchable no-op" (Gate 1 APPROVED, dependency_graph.md
    OBJ-004 Gate 1, decision 3) -> TestNotificationSeamExists.
  - "notifications.send_otp_notification(payload.email, otp,
    purpose=RESET_PASSWORD_PURPOSE)" (design notes section 5.1's
    illustrative call site) -> test_forgot_password_calls_the_notification_seam,
    which drives the REAL endpoint with the seam mocked and asserts it was
    called with the real (not hardcoded) OTP -- the same technique
    tests/api/test_otp_hashing_integration.py now uses to recover the real
    OTP post-print-removal, exercised here as a focused, single-purpose
    test of the seam's call site specifically.

Today (red phase): the print statement still exists (confirmed by this
project's own design notes, which re-verified it directly rather than
trusting OBJ-003 to have already removed it), and app/core/notifications.py
does not exist at all.
"""

import inspect
from unittest.mock import patch

import app.api.v1.endpoints.auth as auth_endpoints_module


def test_forgot_password_module_contains_no_print_call():
    source = inspect.getsource(auth_endpoints_module)
    assert "print(" not in source, (
        "app/api/v1/endpoints/auth.py must not contain any print(...) call "
        "-- audit finding #10 flags the OTP debug print by name; design "
        "notes section 5 replaces it with a structured audit-log event "
        "plus the notifications.send_otp_notification seam, never stdout "
        "print()"
    )


def test_forgot_password_module_no_longer_prints_the_email_mock_banner():
    """Narrower, literal regression check against the exact banner text
    that was there before this objective (in case a differently-shaped
    print, not caught by the blanket 'print(' check above for some
    reason, slips through)."""
    source = inspect.getsource(auth_endpoints_module)
    assert "EMAIL MOCK" not in source, (
        "the '[EMAIL MOCK]' debug print banner must be fully removed from "
        "auth.py, not just modified in place"
    )


class TestNotificationSeamExists:
    def test_notifications_module_exists_with_send_otp_notification(self):
        from app.core import notifications

        assert hasattr(notifications, "send_otp_notification"), (
            "app/core/notifications.py must define send_otp_notification "
            "(design notes section 5.1, Gate 1 APPROVED decision 3) -- the "
            "monkeypatchable interim OTP delivery seam"
        )
        assert callable(notifications.send_otp_notification)

    def test_send_otp_notification_accepts_email_otp_and_purpose_kwarg(self):
        """Matches design notes section 5.1's illustrative signature:
        send_otp_notification(email: str, otp: str, *, purpose: str).
        Calling it directly must not raise -- it's documented as a
        deliberate no-op today (pre-OBJ-005)."""
        from app.core import notifications

        result = notifications.send_otp_notification(
            "seam-direct-call@example.com", "123456", purpose="reset_password"
        )
        assert result is None, (
            "send_otp_notification is documented as a deliberate no-op "
            "today (design notes section 5.1: 'Deliberately a no-op today "
            "-- no delivery channel exists yet') -- OBJ-005 replaces the "
            "BODY, not this contract"
        )


async def test_forgot_password_calls_the_notification_seam_with_the_real_otp(
    client, api_prefix, user_factory
):
    """Drives the real /auth/forgot-password endpoint with the seam
    mocked, and confirms it's actually wired into the call site design
    notes section 5.1 specifies -- not just present, unused, elsewhere in
    the module.

    PATCH-TARGET COUPLING, flagged explicitly (same class of naming-
    coupling risk already established for _build_ssl_connect_arg in
    OBJ-003): this patches
    "app.api.v1.endpoints.auth.notifications.send_otp_notification",
    assuming auth.py imports the module itself (`from app.core import
    notifications`) and calls `notifications.send_otp_notification(...)` --
    the exact style already used for `rate_limit` in this same file
    (`from app.core import rate_limit` / `rate_limit.enforce_rate_limit(...)`).
    If `developer` instead does `from app.core.notifications import
    send_otp_notification`, this patch target needs updating to
    "app.api.v1.endpoints.auth.send_otp_notification" -- not a behavioral
    regression, a naming-coupling issue only.
    """
    user, _ = await user_factory(email="seam-call-site@example.com")

    with patch(
        "app.api.v1.endpoints.auth.notifications.send_otp_notification"
    ) as mock_send:
        resp = await client.post(
            f"{api_prefix}/auth/forgot-password", json={"email": user.email}
        )

    assert resp.status_code == 200
    mock_send.assert_called_once()
    call_args = mock_send.call_args
    # email must be the real user's email, and the otp arg must look like
    # a real 6-digit OTP (never a hardcoded/known value -- there is no
    # other channel this test could have learned it from ahead of time).
    all_args = list(call_args.args) + list(call_args.kwargs.values())
    assert user.email in all_args, (
        f"send_otp_notification must be called with the real user's "
        f"email, got args={call_args.args} kwargs={call_args.kwargs}"
    )
    otp_candidates = [
        a for a in all_args if isinstance(a, str) and a.isdigit() and len(a) == 6
    ]
    assert len(otp_candidates) == 1, (
        f"send_otp_notification must be called with a 6-digit OTP string "
        f"argument, got args={call_args.args} kwargs={call_args.kwargs}"
    )
