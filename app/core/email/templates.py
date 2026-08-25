"""Email copy, owned by a single dedicated module -- never inline in
endpoint code (Scenario 3.5, design notes section 4.4). Each function
returns a (subject, body) tuple, matching `EmailSender.send`'s signature
directly. Plain-text only: `html_body` stays unpopulated/optional on the
`EmailSender.send` side, no HTML template is defined here (no requirement
asks for one)."""

from typing import Tuple


def render_verification_email(otp: str) -> Tuple[str, str]:
    subject = "Verify your email address"
    body = (
        f"Your verification code is: {otp}\n\n"
        "This code expires in 30 minutes. If you did not create an account, "
        "you can safely ignore this email."
    )
    return subject, body


def render_password_reset_email(otp: str) -> Tuple[str, str]:
    subject = "Password reset code"
    body = (
        f"Your password reset code is: {otp}\n\n"
        "This code expires in 10 minutes. If you did not request a password "
        "reset, you can safely ignore this email."
    )
    return subject, body
