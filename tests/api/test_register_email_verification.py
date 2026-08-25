"""
OBJ-005's original scope: POST /auth/register's server-side effect
(generates + sends a verification code) and its failure mode (Gate 1
decision 3: fail the registration, rolled back, if the email send fails).
Traces to docs/requirements/obj-005-email-verification-flow.md Scenario 1.1
and docs/api/obj-005-design-notes.md section 2.3.

EXTENDED by OBJ-007 (2026-08-25, docs/api/obj-007-design-notes.md, closes
audit finding #6): the response contract is now IDENTICAL for a new email
and an already-registered email -- `200` + the generic `MessageResponse`
below, always, replacing the old `201`+`UserResponse` (new) / `400` (
duplicate) split. This file's tests were rewritten accordingly:

- Every assertion that used to expect `201`/`UserResponse` on success now
  expects `200`/`MessageResponse` (design notes section 1).
- `test_register_still_returns_400_for_an_already_existing_email` (the old
  OBJ-005 regression anchor, which explicitly deferred the enumeration
  question to "OBJ-007's separate, still-pending scope") is RETIRED,
  replaced by the new `TestDuplicateEmailAntiEnumeration` class below,
  which is this objective's actual point.

RED-PHASE EXPECTATION: every test in this file should currently FAIL --
either because `register()` still returns `201`+`UserResponse`/`400` (the
old contract, `app/api/v1/endpoints/auth.py` lines 203-229 as of this
writing), or because the duplicate-email branch does not yet call
`security.get_password_hash`/`EmailSender.send` at all. None of these
failures are expected to be import/collection errors -- `GENERIC_
REGISTRATION_MESSAGE` below is a literal string constant owned by this
test file (deliberately NOT imported from `app.api.v1.endpoints.auth`,
where the equivalent constant does not exist yet -- importing a symbol
that doesn't exist yet would fail the whole file at collection, masking
which specific behavior each test is actually checking; same convention
`_RecordingEmailSender` below already established for OBJ-005).

EmailSender mocking uses FastAPI's own dependency-override mechanism on
`deps.get_email_sender` (design notes section 4.5's documented DI seam) --
NOT `unittest.mock.patch` against a concrete class's import path, and NOT
stdout/capsys capture (both explicitly disallowed by design notes section
6).

Requires Postgres -- see tests/README.md / tests/conftest.py module
docstring.
"""

from sqlalchemy import select

from app.models.user import User
from app.models.verification import Verification

EMAIL_VERIFICATION_PURPOSE = "email_verification"
VALID_PASSWORD = "ValidPass123!"

# Literal text from obj-007-design-notes.md section 1 / openapi.yaml's
# /auth/register 200 example -- this exact wording IS part of the contract
# (unlike the duplicate-branch notification email's copy, which design
# notes section 4 explicitly leaves to developer/product judgment and is
# therefore NOT asserted verbatim anywhere in this file).
GENERIC_REGISTRATION_MESSAGE = (
    "If this email is not already registered, we've sent you a "
    "verification code to complete your registration."
)


class _RecordingEmailSender:
    """Duck-typed stand-in for `EmailSender` -- deliberately does NOT
    subclass `app.core.email.base.EmailSender` (see module docstring)."""

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


# --------------------------------------------------------------------------
# New-account branch -- response contract changed (201+UserResponse ->
# 200+MessageResponse), server-side effects unchanged from OBJ-005.
# --------------------------------------------------------------------------


async def test_register_new_email_returns_200_generic_message(client, api_prefix):
    """OBJ-007 design notes section 1: the new-account branch no longer
    returns 201+UserResponse -- it returns the same generic 200/
    MessageResponse as the duplicate-email branch. This assertion FAILS
    today (current code returns 201 with id/email/is_active/is_verified/
    created_at)."""
    resp = await _register(client, api_prefix, "register-shape@example.com")

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body == {"msg": GENERIC_REGISTRATION_MESSAGE}
    assert set(body.keys()) == {"msg"}, (
        "response must be a generic MessageResponse -- must not leak "
        "id/email/is_active/is_verified/created_at (that data would "
        "itself distinguish this branch from the duplicate-email branch)"
    )


async def test_register_creates_an_email_verification_row(
    client, api_prefix, db_session
):
    """Scenario 1.1 / OBJ-005 design notes section 2.3, unchanged by
    OBJ-007 (design notes section 2: 'New email: unchanged from OBJ-005').
    Provable via plain DB state, independent of the response contract
    change above."""
    resp = await _register(client, api_prefix, "register-creates-row@example.com")
    assert resp.status_code == 200, resp.text

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
    """New-account branch must still send the real verification OTP,
    unchanged by OBJ-007 (only the duplicate-email branch's notification
    content is new -- see TestDuplicateEmailAntiEnumeration below)."""
    sender = _RecordingEmailSender()
    _override_email_sender(sender)

    resp = await _register(client, api_prefix, "register-calls-sender@example.com")

    assert resp.status_code == 200, resp.text
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
    """Unchanged by OBJ-007 (design notes section 3: 'New-account branch:
    the entire registration is rolled back'). Still the highest-value test
    for this branch: mocks EmailSendError, asserts (a) 503 and (b) no User/
    Verification row survives via a fresh SELECT."""
    email = "register-rollback@example.com"
    sender = _RecordingEmailSender(raise_error=True)
    _override_email_sender(sender)

    resp = await _register(client, api_prefix, email)

    assert resp.status_code == 503, (
        f"a failed verification-email send must fail the registration with "
        f"503 -- got {resp.status_code}: {resp.text}"
    )

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
        "undone atomically by the same rollback"
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
    """A direct consequence of true rollback: since no row survives, a
    SECOND registration attempt for the SAME email, this time with a
    working sender, must succeed -- proving the email wasn't left in a
    half-registered, permanently-stuck state. Updated for OBJ-007: the
    successful retry now returns 200 (generic message), not 201."""
    email = "register-retry-after-rollback@example.com"

    failing_sender = _RecordingEmailSender(raise_error=True)
    _override_email_sender(failing_sender)
    first = await _register(client, api_prefix, email)
    assert first.status_code == 503, first.text

    working_sender = _RecordingEmailSender(raise_error=False)
    _override_email_sender(working_sender)
    second = await _register(client, api_prefix, email)

    assert second.status_code == 200, (
        f"after a rolled-back registration, the same email must be free to "
        f"register again -- got {second.status_code}: {second.text}"
    )
    assert second.json() == {"msg": GENERIC_REGISTRATION_MESSAGE}


async def test_register_missing_password_returns_422(client, api_prefix):
    resp = await client.post(
        f"{api_prefix}/auth/register", json={"email": "register-no-password@example.com"}
    )
    assert resp.status_code == 422


# --------------------------------------------------------------------------
# Duplicate-email branch -- OBJ-007's actual scope (closes audit finding
# #6). The old regression anchor (`test_register_still_returns_400_for_an_
# already_existing_email`) is retired; every assertion below is new.
# --------------------------------------------------------------------------


class TestDuplicateEmailAntiEnumeration:
    """obj-007-design-notes.md sections 1-2. The duplicate-email branch
    must now be indistinguishable, at the HTTP layer, from the new-account
    branch: same status code, same response body/shape, and (see
    test_timing_side_channel.py's TestRegisterConstantTimeGuarantee for the
    bcrypt-cost side of this) comparable latency. Internally it must still
    create zero new rows and send a *different* notification email, not an
    OTP (design notes section 2)."""

    async def test_duplicate_email_returns_200_not_400(
        self, client, api_prefix, user_factory
    ):
        """The core contract break this objective makes: the old explicit
        400 (the enumeration oracle, audit finding #6) is gone. Fails
        today because current code still raises HTTPException(400, ...)
        for this branch."""
        user, _ = await user_factory(email="register-duplicate@example.com")

        resp = await _register(client, api_prefix, user.email)

        assert resp.status_code == 200, (
            f"a duplicate-email registration must return 200, identically "
            f"to a new-account registration (obj-007-design-notes.md "
            f"section 1) -- got {resp.status_code}: {resp.text}"
        )
        assert resp.json() == {"msg": GENERIC_REGISTRATION_MESSAGE}

    async def test_response_is_identical_for_new_and_duplicate_email(
        self, client, api_prefix, user_factory
    ):
        """The actual point of this objective: compares real response
        bodies byte-for-byte (via JSON equality), not just matching status
        codes independently in two separate tests -- any structural
        difference (even a whitespace-equivalent but distinct body) would
        itself be an enumeration oracle."""
        user, _ = await user_factory(email="register-parity-existing@example.com")

        new_resp = await _register(client, api_prefix, "register-parity-new@example.com")
        dup_resp = await _register(client, api_prefix, user.email)

        assert new_resp.status_code == 200, new_resp.text
        assert dup_resp.status_code == 200, dup_resp.text
        assert new_resp.status_code == dup_resp.status_code
        assert new_resp.json() == dup_resp.json() == {"msg": GENERIC_REGISTRATION_MESSAGE}, (
            "new-account and duplicate-email responses must be "
            "byte-for-byte identical JSON bodies"
        )

    async def test_duplicate_email_creates_no_new_user_or_verification_row(
        self, client, api_prefix, db_session, user_factory
    ):
        """design notes section 2: 'no User/Verification row is created or
        modified' -- unchanged behavior from pre-OBJ-007, re-asserted here
        against the NEW response contract (this test would already pass
        against the old 400 contract too; kept here because it's the
        direct DB-state complement to the response-parity test above,
        which only proves the HTTP layer)."""
        user, _ = await user_factory(email="register-dup-no-rows@example.com")

        resp = await _register(client, api_prefix, user.email)
        assert resp.status_code == 200, resp.text

        users_after = (
            await db_session.execute(select(User).filter(User.email == user.email))
        ).scalars().all()
        assert len(users_after) == 1, (
            "a duplicate registration must not create a second User row "
            "for the same email"
        )

        verification_result = await db_session.execute(
            select(Verification).filter(
                Verification.email == user.email,
                Verification.purpose == EMAIL_VERIFICATION_PURPOSE,
            )
        )
        assert verification_result.scalars().first() is None, (
            "a duplicate registration must not create any Verification "
            "row -- only the new-account branch does that"
        )

    async def test_duplicate_email_sends_a_notification_not_a_new_otp(
        self, client, api_prefix, user_factory
    ):
        """design notes section 2: the duplicate branch must send an
        'already have an account' notification via the SAME EmailSender
        abstraction -- NOT a new verification code. Exact copy is
        developer's call (design notes section 4), so this only asserts
        the distinguishing structural property: no 6-digit OTP anywhere in
        the body."""
        user, _ = await user_factory(email="register-dup-notify@example.com")
        sender = _RecordingEmailSender()
        _override_email_sender(sender)

        resp = await _register(client, api_prefix, user.email)

        assert resp.status_code == 200, resp.text
        assert len(sender.calls) == 1, (
            f"expected exactly one EmailSender.send call on the "
            f"duplicate-email branch, got {len(sender.calls)}"
        )
        call = sender.calls[0]
        assert call["to"] == user.email
        digit_runs = [tok for tok in call["body"].split() if tok.isdigit() and len(tok) == 6]
        assert not digit_runs, (
            "the duplicate-email branch must send an 'already have an "
            "account' notification, NOT a new verification OTP -- found "
            f"what looks like a 6-digit code in the body: {call['body']!r}"
        )

    async def test_duplicate_email_returns_503_when_notification_send_fails(
        self, client, api_prefix, db_session, user_factory
    ):
        """design notes section 3's 503 symmetry: a failed notification
        send on the duplicate branch must ALSO fail with 503, exactly like
        the new-account branch -- otherwise an attacker who can force
        EmailSender failures (e.g. a provider outage) could distinguish
        branches by which ones occasionally 503. Nothing to roll back here
        (no rows are ever created for a duplicate registration), but the
        pre-existing user row must be unaffected."""
        user, _ = await user_factory(email="register-dup-503@example.com")
        sender = _RecordingEmailSender(raise_error=True)
        _override_email_sender(sender)

        resp = await _register(client, api_prefix, user.email)

        assert resp.status_code == 503, (
            f"a failed 'already have an account' notification send must "
            f"return 503, identically to the new-account branch's failure "
            f"mode -- got {resp.status_code}: {resp.text}"
        )
        assert "detail" in resp.json()

        result = await db_session.execute(select(User).filter(User.email == user.email))
        matches = result.scalars().all()
        assert len(matches) == 1, (
            "the pre-existing user row must be unaffected by the failed "
            "notification send"
        )

    async def test_new_and_duplicate_503_bodies_are_identical(
        self, client, api_prefix, user_factory
    ):
        """design notes section 3: the 503 failure body must be identical
        for both branches ('wording deliberately branch-agnostic... not
        "the verification code" or "the notification"') -- closes the
        residual oracle an EmailSender-failure-forcing attacker could
        otherwise exploit even after the 200-path is fixed."""
        user, _ = await user_factory(email="register-503-parity@example.com")
        failing_sender = _RecordingEmailSender(raise_error=True)
        _override_email_sender(failing_sender)
        # Captured up front, as a plain str, before the first _register()
        # call below: that call's 503 path makes the app call db.rollback()
        # on the SAME shared db_session this `user` was created in (deps.
        # get_db is overridden to yield it), and SQLAlchemy's rollback()
        # unconditionally expires every object in the session (unlike
        # commit(), this is NOT gated by expire_on_commit=False -- see
        # tests/conftest.py's db_session fixture). A later `user.email`
        # attribute access would then need to lazy-reload outside of any
        # awaited/greenlet context and raise sqlalchemy.exc.MissingGreenlet
        # -- confirmed live 2026-08-25, see obj-007-test-report.md addendum.
        dup_email = user.email

        new_resp = await _register(client, api_prefix, "register-503-parity-new@example.com")
        dup_resp = await _register(client, api_prefix, dup_email)

        assert new_resp.status_code == dup_resp.status_code == 503
        assert new_resp.json() == dup_resp.json(), (
            "the 503 failure body must be identical for both branches -- "
            f"new={new_resp.json()!r} dup={dup_resp.json()!r}"
        )
