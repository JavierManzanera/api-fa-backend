"""Interim OTP delivery seam (OBJ-004 finding #10, part 2,
obj-004-design-notes.md section 5.1, Gate 1 APPROVED decision 3).

Deliberately NOT the full pluggable email-sender abstraction -- that is
explicitly OBJ-005 scope. This is a minimal, monkeypatchable no-op function
boundary that replaces the removed debug `print(...)` in `forgot_password`:
OBJ-005 will later replace this function's BODY (not its call site in
auth.py) with real email delivery.
"""


def send_otp_notification(email: str, otp: str, *, purpose: str) -> None:
    """Placeholder OTP delivery channel. Temporary, pre-OBJ-005 -- a real
    pluggable email-sender abstraction lands in OBJ-005 and will replace
    this function's BODY (not its call site in auth.py) with actual email
    delivery. Deliberately a no-op today: no delivery channel exists yet.
    This is the ONLY function in the codebase that is allowed to receive a
    raw OTP value outside of generation (_generate_otp) and hashing
    (security.hash_otp) -- never print/log `otp` from anywhere else."""
    return None
