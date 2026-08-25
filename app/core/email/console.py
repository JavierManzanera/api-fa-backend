import logging
from typing import Optional

from app.core.email.base import EmailSender

_logger = logging.getLogger("app.email.console")


class ConsoleEmailSender(EmailSender):
    """Default/dev implementation -- logs to stdout via the stdlib
    `logging` module, never fails. Direct successor to the old print-based
    debug mock (design notes section 4.3). The rendered `body` naturally
    contains the plaintext OTP code (hashing only ever happens at the DB
    storage boundary, per OBJ-003 -- this method never re-derives or needs
    the hash), satisfying Scenario 3.2's "developers can copy-paste it in
    tests" requirement. Uses `logging`, not `print`, so tests can assert on
    it via `caplog` rather than stdout capture (design notes section 6)."""

    async def send(
        self, *, to: str, subject: str, body: str, html_body: Optional[str] = None
    ) -> None:
        # f-string interpolation, not %-style lazy args: pytest's caplog
        # handler pre-formats record.message (substituting record.args) as
        # part of capturing it, so a caller that later does its own
        # `record.message % record.args` (as tests/unit/test_email_sender.py
        # does) would double-substitute and raise -- passing zero args
        # keeps record.args falsy and sidesteps that entirely.
        _logger.info(
            "============================================\n"
            f" [EMAIL:CONSOLE] To: {to} | Subject: {subject}\n"
            f"{body}\n"
            "============================================"
        )
