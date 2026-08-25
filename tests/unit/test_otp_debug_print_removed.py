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

--------------------------------------------------------------------------
CHORE UPDATE (2026-08-26, developer, audit-report.md "notifications.py/
EmailSender coexisting" finding, obj-005-design-notes.md section 4.1's
originally-designed end state): the interim `app/core/notifications.py`
seam this file originally exercised (`TestNotificationSeamExists` and
`test_forgot_password_calls_the_notification_seam_with_the_real_otp`) is
retired -- `/auth/forgot-password` now delivers via the `EmailSender`
abstraction (`render_password_reset_email` + `email_sender.send(...)`),
matching every other OTP-delivery call site in the codebase, per the
design notes' own converge-on-one-mechanism instruction. Those two seam-
specific pieces are replaced below by
`test_forgot_password_sends_an_email_with_the_real_otp_via_email_sender`,
which asserts the same property (the endpoint's call site is really wired,
not just present-but-unused, and is called with the real, freshly-issued
OTP) through the `EmailSender` dependency-override pattern already
established in tests/api/test_resend_verification_email.py, instead of
patching a now-removed module by name.
"""

import inspect
import re

import app.api.v1.endpoints.auth as auth_endpoints_module
from app.api import deps
from app.main import app


def test_forgot_password_module_contains_no_print_call():
    source = inspect.getsource(auth_endpoints_module)
    assert "print(" not in source, (
        "app/api/v1/endpoints/auth.py must not contain any print(...) call "
        "-- audit finding #10 flags the OTP debug print by name; design "
        "notes section 5 replaces it with a structured audit-log event "
        "plus real email delivery via EmailSender, never stdout print()"
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


async def test_forgot_password_sends_an_email_with_the_real_otp_via_email_sender(
    client, api_prefix, user_factory
):
    """Drives the real /auth/forgot-password endpoint with a recording
    EmailSender injected via dependency override, and confirms it's
    actually wired into the endpoint -- not just present, unused, elsewhere
    in the module. Same dependency-override pattern already established in
    tests/api/test_resend_verification_email.py. `app.dependency_overrides`
    is reset automatically after each test (tests/conftest.py autouse
    fixture)."""

    class _RecordingEmailSender:
        def __init__(self):
            self.calls = []

        async def send(self, *, to, subject, body, html_body=None):
            self.calls.append({"to": to, "subject": subject, "body": body})

    sender = _RecordingEmailSender()
    app.dependency_overrides[deps.get_email_sender] = lambda: sender

    user, _ = await user_factory(email="seam-call-site@example.com")

    resp = await client.post(
        f"{api_prefix}/auth/forgot-password", json={"email": user.email}
    )

    assert resp.status_code == 200
    assert len(sender.calls) == 1, (
        f"expected /auth/forgot-password to call EmailSender.send exactly "
        f"once, got {len(sender.calls)} call(s)"
    )
    call = sender.calls[0]
    # email must be the real user's email, and the body must contain a
    # 6-digit OTP that looks real (never a hardcoded/known value -- there
    # is no other channel this test could have learned it from ahead of
    # time).
    assert call["to"] == user.email, (
        f"EmailSender.send must be called with the real user's email, got "
        f"to={call['to']!r}"
    )
    otp_candidates = re.findall(r"\d{6}", call["body"])
    assert len(otp_candidates) == 1, (
        f"EmailSender.send must be called with a body containing exactly "
        f"one 6-digit OTP string, got body={call['body']!r}"
    )
