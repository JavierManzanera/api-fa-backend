"""
OBJ-001 Story 2, Scenario 2.8 -- cryptographically secure OTP generation.
Traces to obj-001-design-notes.md section 2 implementation note and
docs/security/audit-report.md finding #2 ('auth.py:86
"".join(random.choices(...))' -- not a CSPRNG).

This is a static-introspection check (source uses the `secrets` module, not
`random`), not a statistical distribution test. A chi-square-style
uniformity test over a practical sample size (e.g. 100-1000 draws, per
Scenario 2.8's literal wording) cannot reliably distinguish a well-seeded
Mersenne Twister (`random`) from a CSPRNG (`secrets`) -- both look
uniformly random at that scale. The actual security property being tested
("not predictable by an attacker who can influence or observe timing/other
outputs") is a property of the algorithm class, not the sample, so this
test asserts that property directly at the source level instead.
"""

import inspect

import app.api.v1.endpoints.auth as auth_endpoints_module


def test_forgot_password_otp_generation_uses_secrets_module_not_random():
    source = inspect.getsource(auth_endpoints_module)

    uses_secrets = any(
        needle in source
        for needle in ("secrets.choice", "secrets.randbelow", "secrets.token_")
    )
    assert uses_secrets, (
        "OTP generation in /auth/forgot-password must use the `secrets` "
        "module (CSPRNG) -- e.g. secrets.choice(string.digits) or "
        "secrets.randbelow(1_000_000). It currently does not."
    )

    assert "random.choices" not in source and "random.choice(" not in source, (
        "OTP generation must not use the non-cryptographic `random` module "
        "(audit-report.md finding #2)."
    )
