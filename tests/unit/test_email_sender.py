"""
OBJ-005 Story 3 -- the `EmailSender` abstraction. Traces to
docs/requirements/obj-005-email-verification-flow.md Scenarios 3.1, 3.2,
3.3, 3.4 (partial -- the exception-not-boolean contract itself; the
register-rollback consequence of that contract is exercised end-to-end in
tests/api/test_register_email_verification.py, not here), 3.5, and
docs/api/obj-005-design-notes.md section 4 (`app/core/email/` package:
base.py's EmailSender ABC + EmailSendError, console.py's ConsoleEmailSender,
templates.py, plus app/api/deps.py's get_email_sender factory / Settings.
EMAIL_PROVIDER / Settings.EMAIL_FROM).

None of `app/core/email/`, `deps.get_email_sender`, or
`Settings.EMAIL_PROVIDER`/`EMAIL_FROM` exist yet. Every import below is
deferred INTO its owning test function (not hoisted to module level) so
that each test fails independently, for its own precise reason (which
specific piece is missing), rather than the whole file erroring at
collection on the first missing module.

Requires no database -- pure unit tests, no Postgres needed (see
tests/conftest.py module docstring's tests/unit/** note).
"""

import logging

import pytest


def test_email_send_error_exists_and_is_an_exception():
    """Design notes section 4.2: 'This is the ONLY failure signal any
    EmailSender implementation may use.'"""
    from app.core.email.base import EmailSendError

    assert issubclass(EmailSendError, Exception)


def test_email_sender_is_an_abstract_base_class_with_an_abstract_send_method():
    """Scenario 3.1 + design notes section 4.2: EmailSender must be a real
    ABC -- instantiating it directly (without implementing `send`) must
    raise TypeError, not silently succeed as a usable no-op object."""
    from app.core.email.base import EmailSender

    with pytest.raises(TypeError):
        EmailSender()  # abstract -- must not be directly instantiable


async def test_email_sender_send_signature_accepts_the_documented_keyword_arguments():
    """Design notes section 4.2's exact signature: `send(self, *, to, subject,
    body, html_body=None) -> None`. Built via a minimal concrete subclass
    (not ConsoleEmailSender, to isolate this to the ABC's contract alone)."""
    from app.core.email.base import EmailSender

    class _MinimalSender(EmailSender):
        async def send(self, *, to, subject, body, html_body=None):
            self.last_call = {"to": to, "subject": subject, "body": body, "html_body": html_body}

    sender = _MinimalSender()
    result = await sender.send(to="x@example.com", subject="Subject", body="Body")

    assert result is None, (
        "design notes section 4.2: 'raise-on-failure, no boolean return to "
        "misinterpret' -- send() must return None on success, not True/bool"
    )
    assert sender.last_call["html_body"] is None, "html_body must default to None"


class TestConsoleEmailSender:
    """Scenario 3.2 + design notes section 4.3. Default/dev implementation
    -- must never raise, and must log (not print) the full plaintext body
    so developers can copy-paste the OTP in tests, per Scenario 3.2's
    explicit requirement -- WITHOUT reintroducing stdout/capsys capture
    (design notes section 6's explicit prohibition). `caplog` (structured
    logging capture) is used instead, which is not the disallowed
    mechanism -- that prohibition specifically targets stdout/print-based
    capture, and section 4.3 itself specifies this class logs via the
    stdlib `logging` module, not `print`.
    """

    async def test_send_does_not_raise(self):
        from app.core.email.console import ConsoleEmailSender

        sender = ConsoleEmailSender()
        await sender.send(to="dev@example.com", subject="Hello", body="World")
        # No exception -- ConsoleEmailSender "never fails" per design notes.

    async def test_send_logs_the_full_plaintext_body_via_the_logging_module(self, caplog):
        from app.core.email.console import ConsoleEmailSender

        sender = ConsoleEmailSender()
        with caplog.at_level(logging.INFO):
            await sender.send(
                to="dev@example.com",
                subject="Verify your email address",
                body="Your verification code is: 123456",
            )

        combined_log_text = "\n".join(record.message % record.args if record.args else record.message for record in caplog.records)
        assert "123456" in combined_log_text, (
            "Scenario 3.2: the console sender must surface the full "
            "plaintext code so developers can copy-paste it -- got log "
            f"output: {combined_log_text!r}"
        )
        assert "dev@example.com" in combined_log_text


class TestGetEmailSenderFactory:
    """Design notes section 4.5: `deps.get_email_sender()` / the cached
    `_email_sender_singleton()` factory, driven by `Settings.EMAIL_PROVIDER`
    (default "console")."""

    def test_get_email_sender_returns_a_console_email_sender_by_default(self):
        from app.api import deps
        from app.core.email.console import ConsoleEmailSender

        sender = deps.get_email_sender()

        assert isinstance(sender, ConsoleEmailSender), (
            f"Settings.EMAIL_PROVIDER defaults to 'console' (design notes "
            f"section 4.5) -- expected a ConsoleEmailSender, got "
            f"{type(sender)!r}"
        )

    def test_get_email_sender_is_a_singleton(self):
        """Design notes section 4.5: 'mirrors get_settings()'s @lru_cache
        singleton pattern'."""
        from app.api import deps

        first = deps.get_email_sender()
        second = deps.get_email_sender()

        assert first is second, (
            "get_email_sender() must return the SAME instance across "
            "calls (cached singleton), not construct a fresh sender per "
            "call"
        )

    def test_settings_has_email_provider_and_email_from_with_safe_defaults(self):
        from app.core.config import settings

        assert settings.EMAIL_PROVIDER == "console", (
            "design notes section 4.5: Settings.EMAIL_PROVIDER must default "
            "to 'console' (safe default, same convention as LOG_LEVEL)"
        )
        assert isinstance(settings.EMAIL_FROM, str) and "@" in settings.EMAIL_FROM

    def test_get_email_sender_raises_not_implemented_for_an_unconfigured_provider(
        self, monkeypatch
    ):
        """Design notes section 4.5: any EMAIL_PROVIDER other than
        'console' must raise NotImplementedError at first USE (not at
        import/startup -- an intentional, lower-stakes departure from
        SECRET_KEY/POSTGRES_SSL_MODE's fail-at-import pattern, since this
        is an operational/delivery concern, not a security posture
        regression).

        COUPLING NOTE (documented, not incidental): this test clears the
        `@lru_cache` on the private `_email_sender_singleton` factory
        (design notes section 4.5's literal implementation, not just its
        public contract) so this test's EMAIL_PROVIDER override actually
        takes effect rather than returning an already-cached instance from
        a prior test/call. If developer implements the singleton under a
        different private name, this test will fail with AttributeError on
        `deps._email_sender_singleton` specifically (a clean, precise
        signal of exactly what changed) rather than silently passing for
        the wrong reason.
        """
        from app.api import deps
        from app.core.config import settings

        monkeypatch.setattr(settings, "EMAIL_PROVIDER", "smtp")
        deps._email_sender_singleton.cache_clear()

        with pytest.raises(NotImplementedError):
            deps.get_email_sender()

        deps._email_sender_singleton.cache_clear()  # don't leak into other tests


class TestEmailTemplates:
    """Scenario 3.5 + design notes section 4.4: email copy lives in a
    dedicated templates module, never inline in endpoint code, and is
    never HTML-only (html_body stays optional/unpopulated per section
    4.4)."""

    def test_render_verification_email_includes_the_otp_and_returns_subject_body_tuple(self):
        from app.core.email.templates import render_verification_email

        subject, body = render_verification_email("123456")

        assert isinstance(subject, str) and subject
        assert "123456" in body
        assert "30" in body, (
            "design notes section 1.2 / 4.4: the verification email's TTL "
            "wording should reflect EMAIL_VERIFICATION_OTP_TTL_MINUTES = 30, "
            "distinct from password-reset's 10-minute wording"
        )

    def test_render_password_reset_email_includes_the_otp_and_returns_subject_body_tuple(self):
        from app.core.email.templates import render_password_reset_email

        subject, body = render_password_reset_email("654321")

        assert isinstance(subject, str) and subject
        assert "654321" in body

    def test_verification_and_reset_templates_produce_visibly_different_subjects(self):
        """A user must be able to tell the two email types apart at a
        glance (Scenario 3.5's template-ownership point extends naturally
        to this) -- not a hard security requirement, but a template-
        quality one worth locking in now that both templates exist in the
        same module."""
        from app.core.email.templates import (
            render_password_reset_email,
            render_verification_email,
        )

        verify_subject, _ = render_verification_email("111111")
        reset_subject, _ = render_password_reset_email("111111")

        assert verify_subject != reset_subject
