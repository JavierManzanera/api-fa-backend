"""Pluggable email-delivery abstraction (OBJ-005 Story 3,
docs/api/obj-005-design-notes.md section 4).

Package layout:
- base.py -- the `EmailSender` ABC + `EmailSendError`.
- console.py -- `ConsoleEmailSender`, the default/dev implementation.
- templates.py -- email subject/body rendering, kept separate from both
  transport and business logic per Scenario 3.5.
"""
