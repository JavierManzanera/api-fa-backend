from abc import ABC, abstractmethod
from typing import Optional


class EmailSendError(Exception):
    """Raised by any EmailSender implementation on a delivery failure (SMTP
    timeout, provider API error, etc.). Callers (e.g. /auth/register) MUST
    treat this as a hard failure -- per OBJ-005 Gate 1 decision 3, a failed
    send is never silently swallowed or queued. This is the ONLY failure
    signal any EmailSender implementation may use; a `send()` call that
    returns normally is the only success signal (no boolean return value to
    misinterpret)."""


class EmailSender(ABC):
    @abstractmethod
    async def send(
        self, *, to: str, subject: str, body: str, html_body: Optional[str] = None
    ) -> None:
        """Send one email. Must raise EmailSendError (or a subclass) on any
        failure to actually hand the message off for delivery -- never
        return normally on failure, never log-and-swallow. Implementations
        own their own retry policy internally, if any; from the caller's
        perspective this call either fully succeeds or raises."""
