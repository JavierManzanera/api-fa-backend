"""
OBJ-005 -- POST /auth/register's new server-side effect (generates +
sends a verification code) and new failure mode (Gate 1 decision 3: fail
the registration, rolled back, if the email send fails). Traces to
docs/requirements/obj-005-email-verification-flow.md Scenario 1.1 and
docs/api/obj-005-design-notes.md section 2.3.

Response shape/status on SUCCESS is unchanged (201, UserResponse,
is_verified: false) -- covered here only as a regression anchor, expected
to already pass today. The two genuinely new behaviors this file exercises
are: (a) a purpose=email_verification Verification row is created on
success, and (b) the whole registration is atomically rolled back (no User
row survives) if the email send fails -- design notes section 6's
explicitly named highest-priority test for this file: 'assert both halves
of the failure -- (a) the HTTP response is 503, and (b) no User row with
that email exists afterward (a fresh SELECT, not just trusting the status
code)'.

EmailSender mocking uses FastAPI's own dependency-override mechanism on
`deps.get_email_sender` (design notes section 4.5's documented DI seam) --
NOT `unittest.mock.patch` against a concrete class's import path, and NOT
stdout/capsys capture (both explicitly disallowed by design notes section
6). `deps.get_email_sender` does not exist yet, so every override in this
file raises AttributeError today -- a correct RED signal for missing
OBJ-005 implementation (the DI seam itself), not a broken test.

Requires Postgres -- see tests/README.md / tests/conftest.py module
docstring.
"""

from sqlalchemy import select

from app.models.user import User
from app.models.verification import Verification

EMAIL_VERIFICATION_PURPOSE = "email_verification"
VALID_PASSWORD = "ValidPass123!"


class _RecordingEmailSender:
    """Duck-typed stand-in for the not-yet-existing `EmailSender` ABC --
    deliberately does NOT subclass `app.core.email.base.EmailSender`
    (importing it would fail at collection time; every failure in this
    module should be attributable to the specific behavior each test
    exercises, not a blanket import error). FastAPI's dependency-override
    mechanism only needs a callable returning an object with the right
    shape, not a registered subclass.
    """

    def __init__(self, *, raise_error: bool = False):
        self.calls = []
        self._raise_error = raise_error

    async def send(self, *, to, subject, body, html_body=None):
        self.calls.append({"to": to, "subject": subject, "body": body, "html_body": html_body})
        if self._raise_error:
            from app.core.email.base import EmailSendError

            raise EmailSendError("simulated downstream email-provider failure")


def _override_email_sender(sender):
    from app.api import deps
    from app.main import app

    app.dependency_overrides[deps.get_email_sender] = lambda: sender


async def _register(client, api_prefix, email, password=VALID_PASSWORD):
    return await client.post(
        f"{api_prefix}/auth/register", json={"email": email, "password": password}
    )


async def test_register_success_response_shape_is_unchanged(client, api_prefix):
    """Regression anchor -- design notes section 2.3: '201, UserResponse,
    is_verified: false unchanged'. Expected to already pass today (no
    OBJ-005 code needed for the response SHAPE, only for the new side
    effects covered by the other tests below)."""
    resp = await _register(client, api_prefix, "register-shape@example.com")

    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["email"] == "register-shape@example.com"
    assert body["is_verified"] is False
    assert set(body.keys()) == {"id", "email", "is_active", "is_verified", "created_at"}, (
        "Scenario 1.1: 'response body contains only user.id, user.email, "
        "and is_verified=False -- no token/secret leaked'"
    )


async def test_register_creates_an_email_verification_row(
    client, api_prefix, db_session
):
    """Scenario 1.1 / design notes section 2.3: registration must create a
    purpose=email_verification Verification row. Provable via plain DB
    state, no EmailSender mocking needed."""
    resp = await _register(client, api_prefix, "register-creates-row@example.com")
    assert resp.status_code == 201, resp.text

    result = await db_session.execute(
        select(Verification).filter(
            Verification.email == "register-creates-row@example.com",
            Verification.purpose == EMAIL_VERIFICATION_PURPOSE,
        )
    )
    assert result.scalars().first() is not None, (
        "POST /auth/register must create a purpose=email_verification "
        "Verification row on success"
    )


async def test_register_calls_email_sender_send_with_a_six_digit_code_in_the_body(
    client, api_prefix
):
    """Design notes section 2.3 / section 6: assert the injected
    EmailSender.send is actually invoked, and that the rendered body
    contains a 6-digit code (design notes section 1: same OTP format as
    password-reset, section 4.4: templates.render_verification_email)."""
    sender = _RecordingEmailSender()
    _override_email_sender(sender)

    resp = await _register(client, api_prefix, "register-calls-sender@example.com")

    assert resp.status_code == 201, resp.text
    assert len(sender.calls) == 1, (
        f"expected exactly one EmailSender.send call, got {len(sender.calls)}"
    )
    call = sender.calls[0]
    assert call["to"] == "register-calls-sender@example.com"
    assert any(
        word in call["body"] for word in ("verif", "Verif")
    ), "email body should be the verification template, not some other content"
    digit_runs = [tok for tok in call["body"].split() if tok.isdigit() and len(tok) == 6]
    assert len(digit_runs) >= 1, (
        f"expected a 6-digit verification code somewhere in the email body, "
        f"got body={call['body']!r}"
    )


async def test_register_rolls_back_entirely_when_email_send_fails(
    client, api_prefix, db_session
):
    """THE highest-value test in this file (design notes section 6): 'mock
    EmailSender.send to raise EmailSendError, then assert (a) the HTTP
    response is 503, and (b) no User row with that email exists afterward
    (a fresh SELECT, not just trusting the status code) -- this is the
    test that actually proves the rollback, not just the error surface.'
    Gate 1 decision 3 (dependency_graph.md, 2026-08-23): fail the
    registration, rolled back, no partial state survives.
    """
    email = "register-rollback@example.com"
    sender = _RecordingEmailSender(raise_error=True)
    _override_email_sender(sender)

    resp = await _register(client, api_prefix, email)

    assert resp.status_code == 503, (
        f"a failed verification-email send must fail the registration with "
        f"503, per Gate 1 decision 3 -- got {resp.status_code}: {resp.text}"
    )

    # (b) -- the actual proof of rollback: a FRESH SELECT, not the status
    # code alone. Uses a NEW query against db_session (the same session the
    # app used, per the client fixture's deps.get_db override) so this
    # reads the real post-request state, not a stale in-memory object.
    user_result = await db_session.execute(select(User).filter(User.email == email))
    assert user_result.scalars().first() is None, (
        "no User row may survive a failed registration -- if this is the "
        "ONLY failing assertion in this test while the 503 above passed, "
        "that means the endpoint returns the right error code but does "
        "NOT actually roll back the transaction -- a partial-failure bug, "
        "not a false positive"
    )

    verification_result = await db_session.execute(
        select(Verification).filter(
            Verification.email == email, Verification.purpose == EMAIL_VERIFICATION_PURPOSE
        )
    )
    assert verification_result.scalars().first() is None, (
        "no Verification row may survive either -- both inserts must be "
        "undone atomically by the same rollback (design notes section "
        "2.3's flush()-then-rollback() mechanism)"
    )


async def test_register_503_response_shape(client, api_prefix):
    email = "register-rollback-shape@example.com"
    sender = _RecordingEmailSender(raise_error=True)
    _override_email_sender(sender)

    resp = await _register(client, api_prefix, email)

    assert resp.status_code == 503
    assert "detail" in resp.json(), "503 must use the standard HTTPError shape"


async def test_register_after_rollback_the_email_is_available_again(
    client, api_prefix
):
    """A direct consequence of true rollback (not just a deleted user
    afterward): since no row survives, a SECOND registration attempt for
    the SAME email, this time with a working sender, must succeed --
    proving the email wasn't left in a half-registered, permanently-stuck
    state (Scenario 3.4's 'stuck accounts' concern, resolved by Gate 1
    decision 3's strict-fail-and-rollback choice)."""
    email = "register-retry-after-rollback@example.com"

    failing_sender = _RecordingEmailSender(raise_error=True)
    _override_email_sender(failing_sender)
    first = await _register(client, api_prefix, email)
    assert first.status_code == 503, first.text

    working_sender = _RecordingEmailSender(raise_error=False)
    _override_email_sender(working_sender)
    second = await _register(client, api_prefix, email)

    assert second.status_code == 201, (
        f"after a rolled-back registration, the same email must be free to "
        f"register again -- got {second.status_code}: {second.text}"
    )


async def test_register_still_returns_400_for_an_already_existing_email(
    client, api_prefix, user_factory
):
    """Regression anchor -- OBJ-005 does not touch the existing-email 400
    branch (that's audit finding #6 / OBJ-007's separate, still-pending
    scope, per design notes section 2.3's explicit 'not an enumeration
    concern... out of this objective's scope' note). Expected to already
    pass today; must not regress once the email-sending logic is added
    ahead of it."""
    user, _ = await user_factory(email="register-duplicate@example.com")

    resp = await _register(client, api_prefix, user.email)

    assert resp.status_code == 400
    assert resp.json()["detail"] == "The user with this email already exists in the system."


async def test_register_missing_password_returns_422(client, api_prefix):
    resp = await client.post(
        f"{api_prefix}/auth/register", json={"email": "register-no-password@example.com"}
    )
    assert resp.status_code == 422
