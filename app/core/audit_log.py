"""Structured auth-event logging (OBJ-004 finding #10, part 1,
obj-004-design-notes.md section 4). Single owner of the auth-event log
shape, same "one module owns one concern" pattern as security.py (crypto)
and rate_limit.py (rate limiting).

Uses stdlib `logging`, not a new dependency -- emits one JSON-serialized
line per event via `logging.getLogger("app.audit")`. No new runtime
dependency (structlog was considered and rejected, design notes section
4.1) -- this project's established philosophy is minimal footprint for a
template meant to be forked broadly.

PII / secret-leakage rule (design notes section 4.3, non-negotiable):
`fields` must NEVER include a raw password, raw OTP code, raw JWT string, or
SECRET_KEY. Callers pass only safe identifiers (email, ip, user_id, jti,
family_id, outcome, reason, ...). `email` IS logged deliberately -- it is
the actor identity, standard in an authentication audit trail.
"""

import json
import logging
from datetime import datetime, timezone
from typing import Any

_logger = logging.getLogger("app.audit")


def log_auth_event(event: str, *, level: int = logging.INFO, **fields: Any) -> None:
    """Structured auth-event log line. `fields` must never include a raw
    password, OTP code, or JWT token string -- see this module's docstring
    (design notes section 4.3). Callers pass only safe identifiers (email,
    ip, user_id, jti, family_id, outcome, reason)."""
    payload = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event": event,
        **fields,
    }
    _logger.log(level, json.dumps(payload))
