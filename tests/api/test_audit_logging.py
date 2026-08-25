"""
OBJ-004 finding #10, part 1 -- structured auth-event logging. Drives the
real endpoints via the shared `client` fixture and inspects captured log
records (pytest's `caplog`) rather than stdout, per design notes section 4's
"stdlib logging... emitting structured (JSON) lines to stdout" mechanism --
`caplog` observes the logging call itself, independent of whether anything
is actually attached to stdout in the test process.

No Gherkin/AC doc exists for OBJ-004 -- see test_environment_settings.py's
docstring for the shared "derived from design notes" rationale. Scenario
derivation from obj-004-design-notes.md section 4.2's 12-event catalog
(reproduced there as a table: event, level, emitted-from, fields) -- one
test class per event, each asserting: the event fires exactly when its
"Emitted from" endpoint/code path is exercised, the documented fields are
present with correct values, and (for the three catalog rows marked
WARNING) the log level is actually WARNING, not INFO. Plus one dedicated,
explicitly security-critical class (TestNoRawSecretsInAnyLogRecord) for
section 4.3's "Never logged, under any event, by any field" rule -- the
task's own instruction not to skip this assertion.

Each `app.core.audit_log.log_auth_event(...)` call is expected to emit ONE
structured JSON line via `logging.getLogger("app.audit")`, per design notes
section 4.1's illustrative implementation (`_logger.log(level,
json.dumps(payload))` -- the log MESSAGE itself is the already-serialized
JSON string, not a %-style template with args). `_audit_events()` below
parses every captured "app.audit" record's `.getMessage()` as JSON and
filters by the `event` field.

FIELD-NAME COUPLING, flagged explicitly (same class of risk already
established elsewhere in this project for exact function/column names):
every field-name assertion below (`email`, `ip`, `user_id`, `reason`,
`purpose`, `attempts`, `jti`, `family_id`, `old_jti`, `new_jti`, `scope`,
`outcome`) is taken verbatim from design notes section 4.2's catalog table
-- if `developer` picks different field names with equivalent meaning,
update the assertions here, that alone is not a behavioral regression.

`auth.refresh.failure`'s four possible `reason` values (no_session/expired/
ver_mismatch/user_inactive) are NOT all independently tested -- only
`no_session` (TestRefreshFailureEvent), the branch most directly reachable
without depending on other endpoints' timing. Explicitly out of scope,
noted here rather than silently: the other three reasons almost certainly
share the same `log_auth_event` call-site pattern, but were not each given
a dedicated test given this pass's effort budget; a gap for a future pass
to close if desired, not a security-load-bearing omission (the event
firing AT ALL, and never carrying a secret, IS covered for the failure
path in general via TestNoRawSecretsInAnyLogRecord's refresh-adjacent
calls).

Today (red phase): `app.core.audit_log` does not exist, no endpoint emits
any structured log event, so every test below currently fails with zero
captured "app.audit" records (or, for endpoints whose surrounding behavior
also doesn't exist yet, an earlier status-code assertion failure first).

Requires Postgres -- see tests/README.md / tests/conftest.py.
"""

import json
import logging
import uuid

import pytest

from app.core import security

AUDIT_LOGGER_NAME = "app.audit"


@pytest.fixture(autouse=True)
def _capture_all_logs(caplog):
    """Root-level capture (not scoped to app.audit) so
    TestNoRawSecretsInAnyLogRecord can inspect every record from every
    logger, not just the audit one -- a secret leaking through some OTHER
    logger would be just as real a finding."""
    caplog.set_level(logging.INFO)


def _audit_events(caplog, event: str | None = None) -> list[dict]:
    events = []
    for record in caplog.records:
        if record.name != AUDIT_LOGGER_NAME:
            continue
        try:
            payload = json.loads(record.getMessage())
        except (ValueError, TypeError):
            continue
        if event is not None and payload.get("event") != event:
            continue
        events.append({"_level": record.levelname, **payload})
    return events


class TestRegisterEvent:
    """design notes section 4.2: auth.register, INFO, emitted from
    `register`, fields email/ip/outcome (success|duplicate). Beyond
    finding #10's literal list but a deliberate, non-Gate-1 addition
    (design notes section 4.2's own note).

    UPDATED by OBJ-007 (obj-007-design-notes.md section 2, 'Audit logging
    is exempt from the anti-enumeration constraint'): the HTTP response
    codes below changed (both branches now return 200, per
    tests/api/test_register_email_verification.py), but the internal
    audit-log outcome distinction (success vs. duplicate) is explicitly
    preserved unchanged -- these are internal-only observability, not part
    of the HTTP contract."""

    async def test_successful_registration_logs_success_outcome(self, client, api_prefix, caplog):
        resp = await client.post(
            f"{api_prefix}/auth/register",
            json={"email": "audit-register-new@example.com", "password": "ValidPass123!"},
        )
        assert resp.status_code == 200

        events = _audit_events(caplog, "auth.register")
        assert len(events) == 1
        assert events[0]["email"] == "audit-register-new@example.com"
        assert events[0]["outcome"] == "success"
        assert "ip" in events[0]

    async def test_duplicate_registration_logs_duplicate_outcome(self, client, api_prefix, user_factory, caplog):
        user, _ = await user_factory(email="audit-register-dup@example.com")

        resp = await client.post(
            f"{api_prefix}/auth/register",
            json={"email": user.email, "password": "AnotherValid123!"},
        )
        assert resp.status_code == 200, (
            "OBJ-007: the duplicate branch's HTTP response is now 200, "
            "identical to the success branch -- only the internal audit "
            "log (asserted below) still distinguishes the outcome"
        )

        events = _audit_events(caplog, "auth.register")
        assert len(events) == 1
        assert events[0]["outcome"] == "duplicate"
        assert events[0]["email"] == user.email


class TestLoginEvents:
    """design notes section 4.2: auth.login.success (INFO, email/ip/user_id)
    and auth.login.failure (INFO, email/ip/reason:
    invalid_credentials|inactive_user)."""

    async def test_successful_login_logs_success_with_user_id(self, client, api_prefix, user_factory, caplog):
        user, password = await user_factory(email="audit-login-success@example.com")

        resp = await client.post(
            f"{api_prefix}/auth/login", data={"username": user.email, "password": password}
        )
        assert resp.status_code == 200

        events = _audit_events(caplog, "auth.login.success")
        assert len(events) == 1
        assert events[0]["email"] == user.email
        assert events[0]["user_id"] == str(user.id)
        assert "ip" in events[0]

    async def test_wrong_password_logs_failure_with_invalid_credentials_reason(
        self, client, api_prefix, user_factory, caplog
    ):
        user, _ = await user_factory(email="audit-login-wrongpw@example.com")

        resp = await client.post(
            f"{api_prefix}/auth/login", data={"username": user.email, "password": "TotallyWrong123!"}
        )
        assert resp.status_code == 400

        events = _audit_events(caplog, "auth.login.failure")
        assert len(events) == 1
        assert events[0]["reason"] == "invalid_credentials"
        assert events[0]["email"] == user.email

    async def test_inactive_user_login_logs_failure_with_inactive_user_reason(
        self, client, api_prefix, user_factory, caplog
    ):
        user, password = await user_factory(email="audit-login-inactive@example.com", is_active=False)

        resp = await client.post(
            f"{api_prefix}/auth/login", data={"username": user.email, "password": password}
        )
        assert resp.status_code == 400

        events = _audit_events(caplog, "auth.login.failure")
        assert len(events) == 1
        assert events[0]["reason"] == "inactive_user"


class TestOtpRequestedEvent:
    """design notes section 4.2: auth.otp.requested, INFO, emitted from
    forgot_password, fields email/ip/purpose."""

    async def test_forgot_password_for_existing_user_logs_otp_requested(
        self, client, api_prefix, user_factory, caplog
    ):
        user, _ = await user_factory(email="audit-otp-requested@example.com")

        resp = await client.post(f"{api_prefix}/auth/forgot-password", json={"email": user.email})
        assert resp.status_code == 200

        events = _audit_events(caplog, "auth.otp.requested")
        assert len(events) == 1
        assert events[0]["email"] == user.email
        assert events[0]["purpose"] == "reset_password"
        assert "ip" in events[0]


class TestOtpFailedAttemptEvent:
    """design notes section 4.2: auth.otp.failed_attempt, INFO, emitted
    from _check_and_consume_otp, fields email/ip/purpose/attempts."""

    async def test_wrong_otp_guess_logs_failed_attempt_with_count(
        self, client, api_prefix, user_factory, verification_factory, caplog
    ):
        user, _ = await user_factory(email="audit-otp-failed@example.com")
        await verification_factory(email=user.email, code="123123")

        resp = await client.post(
            f"{api_prefix}/auth/verify-otp", json={"email": user.email, "otp": "000000"}
        )
        assert resp.status_code == 400

        events = _audit_events(caplog, "auth.otp.failed_attempt")
        assert len(events) == 1
        assert events[0]["email"] == user.email
        assert events[0]["purpose"] == "reset_password"
        assert events[0]["attempts"] == 1


class TestOtpLockoutEvent:
    """design notes section 4.2: auth.otp.lockout, WARNING (security
    signal), emitted from _check_and_consume_otp, fields email/ip/purpose.
    MAX_OTP_ATTEMPTS = 5 (OBJ-001 Gate 1, unchanged by this objective)."""

    MAX_OTP_ATTEMPTS = 5

    async def test_fifth_wrong_guess_logs_lockout_warning(
        self, client, api_prefix, user_factory, verification_factory, caplog
    ):
        user, _ = await user_factory(email="audit-otp-lockout@example.com")
        await verification_factory(email=user.email, code="456456")

        for _ in range(self.MAX_OTP_ATTEMPTS - 1):
            await client.post(
                f"{api_prefix}/auth/verify-otp", json={"email": user.email, "otp": "000000"}
            )
        assert _audit_events(caplog, "auth.otp.lockout") == [], (
            "lockout must not fire before the attempt budget is actually exhausted"
        )

        await client.post(
            f"{api_prefix}/auth/verify-otp", json={"email": user.email, "otp": "000000"}
        )

        events = _audit_events(caplog, "auth.otp.lockout")
        assert len(events) >= 1, "the 5th wrong guess must trigger auth.otp.lockout"
        assert events[0]["_level"] == "WARNING", (
            f"auth.otp.lockout must be logged at WARNING (genuine security "
            f"signal, design notes section 4.2) -- got {events[0]['_level']}"
        )
        assert events[0]["email"] == user.email


class TestPasswordResetSuccessEvent:
    """design notes section 4.2: auth.password_reset.success, INFO,
    emitted from reset_password, fields email/ip/user_id."""

    async def test_successful_reset_logs_success_with_user_id(
        self, client, api_prefix, user_factory, verification_factory, caplog
    ):
        user, _ = await user_factory(email="audit-reset-success@example.com")
        await verification_factory(email=user.email, code="789789")

        resp = await client.post(
            f"{api_prefix}/auth/reset-password",
            json={"email": user.email, "otp": "789789", "new_password": "BrandNewPass123!"},
        )
        assert resp.status_code == 200

        events = _audit_events(caplog, "auth.password_reset.success")
        assert len(events) == 1
        assert events[0]["email"] == user.email
        assert events[0]["user_id"] == str(user.id)


class TestRefreshSuccessEvent:
    """design notes section 4.2: auth.refresh.success, INFO, emitted from
    refresh_token, fields user_id/family_id/old_jti/new_jti."""

    async def test_successful_rotation_logs_all_four_fields(
        self, client, api_prefix, user_factory, caplog
    ):
        user, password = await user_factory(email="audit-refresh-success@example.com")
        login_resp = await client.post(
            f"{api_prefix}/auth/login", data={"username": user.email, "password": password}
        )
        old_refresh_token = login_resp.json()["refresh_token"]
        old_claims = security.decode_refresh_token_claims(old_refresh_token)

        refresh_resp = await client.post(
            f"{api_prefix}/auth/refresh", json={"refresh_token": old_refresh_token}
        )
        assert refresh_resp.status_code == 200
        new_claims = security.decode_refresh_token_claims(refresh_resp.json()["refresh_token"])

        events = _audit_events(caplog, "auth.refresh.success")
        assert len(events) == 1
        assert events[0]["user_id"] == str(user.id)
        assert events[0]["family_id"] == old_claims["jti"]  # login mints family_id == jti
        assert events[0]["old_jti"] == old_claims["jti"]
        assert events[0]["new_jti"] == new_claims["jti"]


class TestRefreshReuseDetectedEvent:
    """design notes section 4.2: auth.refresh.reuse_detected, WARNING
    (possible token theft), emitted from refresh_token, fields
    user_id/family_id/jti."""

    async def test_replaying_a_rotated_token_logs_reuse_warning(
        self, client, api_prefix, user_factory, caplog
    ):
        user, password = await user_factory(email="audit-refresh-reuse@example.com")
        login_resp = await client.post(
            f"{api_prefix}/auth/login", data={"username": user.email, "password": password}
        )
        old_refresh_token = login_resp.json()["refresh_token"]
        old_claims = security.decode_refresh_token_claims(old_refresh_token)

        # Rotate once (now-legitimate), then replay the ORIGINAL (dead) token.
        await client.post(f"{api_prefix}/auth/refresh", json={"refresh_token": old_refresh_token})
        caplog.clear()
        replay_resp = await client.post(
            f"{api_prefix}/auth/refresh", json={"refresh_token": old_refresh_token}
        )
        assert replay_resp.status_code == 401

        events = _audit_events(caplog, "auth.refresh.reuse_detected")
        assert len(events) == 1
        assert events[0]["_level"] == "WARNING", (
            f"reuse detection is a possible-token-theft signal and must be "
            f"WARNING (design notes section 4.2) -- got {events[0]['_level']}"
        )
        assert events[0]["user_id"] == str(user.id)
        assert events[0]["family_id"] == old_claims["jti"]
        assert events[0]["jti"] == old_claims["jti"]


class TestRefreshFailureEvent:
    """design notes section 4.2: auth.refresh.failure, INFO, emitted from
    refresh_token, fields ip/reason. Only the `no_session` reason is
    exercised here -- see this file's module docstring for the explicit
    scope note on the other three reason values."""

    async def test_refresh_with_no_matching_session_logs_no_session_reason(
        self, client, api_prefix, user_factory, caplog
    ):
        user, _ = await user_factory(email="audit-refresh-no-session@example.com")
        # A validly-SIGNED refresh token whose jti has no backing
        # refresh_sessions row at all (never issued via /auth/login).
        orphan_token = security.create_refresh_token(
            user.email, ver=user.token_version, jti=uuid.uuid4()
        )

        resp = await client.post(f"{api_prefix}/auth/refresh", json={"refresh_token": orphan_token})
        assert resp.status_code == 401

        events = _audit_events(caplog, "auth.refresh.failure")
        assert len(events) == 1
        assert events[0]["reason"] == "no_session"


class TestLogoutEvent:
    """design notes section 4.2: auth.logout, INFO, emitted from logout,
    fields jti (nullable)/ip."""

    async def test_logout_with_valid_session_logs_matching_jti(
        self, client, api_prefix, user_factory, caplog
    ):
        user, password = await user_factory(email="audit-logout-valid@example.com")
        login_resp = await client.post(
            f"{api_prefix}/auth/login", data={"username": user.email, "password": password}
        )
        refresh_token = login_resp.json()["refresh_token"]
        claims = security.decode_refresh_token_claims(refresh_token)

        resp = await client.post(f"{api_prefix}/auth/logout", json={"refresh_token": refresh_token})
        assert resp.status_code == 204

        events = _audit_events(caplog, "auth.logout")
        assert len(events) == 1
        assert events[0]["jti"] == claims["jti"]

    async def test_logout_with_malformed_token_logs_null_jti(self, client, api_prefix, caplog):
        resp = await client.post(
            f"{api_prefix}/auth/logout", json={"refresh_token": "not-a-real-jwt-at-all"}
        )
        assert resp.status_code == 204

        events = _audit_events(caplog, "auth.logout")
        assert len(events) == 1
        assert events[0]["jti"] is None, (
            "the no-op branch (no valid jti to revoke) must log jti=null, "
            "not omit the event or fabricate a value (design notes section "
            "4.2: 'jti (nullable -- the no-op branch has none)')"
        )


class TestRateLimitExceededEvent:
    """design notes section 4.2: auth.rate_limit.exceeded, WARNING,
    emitted from enforce_rate_limit, fields scope/ip/email."""

    FORGOT_PASSWORD_LIMIT = 5

    async def test_exceeding_forgot_password_limit_logs_warning(
        self, client, api_prefix, user_factory, caplog
    ):
        user, _ = await user_factory(email="audit-rate-limit@example.com")

        for _ in range(self.FORGOT_PASSWORD_LIMIT):
            await client.post(f"{api_prefix}/auth/forgot-password", json={"email": user.email})
        caplog.clear()
        resp = await client.post(f"{api_prefix}/auth/forgot-password", json={"email": user.email})
        assert resp.status_code == 429

        events = _audit_events(caplog, "auth.rate_limit.exceeded")
        assert len(events) == 1
        assert events[0]["_level"] == "WARNING"
        assert events[0]["scope"] == "forgot_password"
        assert events[0]["email"] == user.email


class TestNoRawSecretsInAnyLogRecord:
    """design notes section 4.3, task's own explicit instruction not to
    skip this assertion: 'Never logged, under any event, by any field:
    Raw password... Raw OTP code... Raw JWT string.' This class drives a
    full flow (register -> login -> forgot-password -> verify-otp ->
    reset-password -> refresh -> logout) using REAL secret values (the
    actual password, the actual OTP recovered from the recording EmailSender
    override, the actual issued JWTs) and asserts NONE of them appear as a substring
    in ANY captured log record's message, from ANY logger -- not just
    app.audit (a leak through some other logger, e.g. an errant debug
    print piped through logging, would be just as real a finding)."""

    async def test_full_flow_never_logs_a_raw_secret(
        self, client, api_prefix, user_factory, caplog
    ):
        import re

        from app.api import deps
        from app.main import app

        password = "SuperSecretPass987!"
        user, _ = await user_factory(email="audit-no-leak@example.com", password=password)

        login_resp = await client.post(
            f"{api_prefix}/auth/login", data={"username": user.email, "password": password}
        )
        assert login_resp.status_code == 200
        access_token = login_resp.json()["access_token"]
        refresh_token = login_resp.json()["refresh_token"]

        class _RecordingEmailSender:
            def __init__(self):
                self.calls = []

            async def send(self, *, to, subject, body, html_body=None):
                self.calls.append({"to": to, "subject": subject, "body": body})

        sender = _RecordingEmailSender()
        app.dependency_overrides[deps.get_email_sender] = lambda: sender

        fp_resp = await client.post(
            f"{api_prefix}/auth/forgot-password", json={"email": user.email}
        )
        assert fp_resp.status_code == 200
        assert len(sender.calls) == 1
        real_otp = re.search(r"\d{6}", sender.calls[0]["body"]).group()

        # One wrong guess (produces a failed_attempt log line) then the real one.
        await client.post(
            f"{api_prefix}/auth/verify-otp", json={"email": user.email, "otp": "000000"}
        )
        verify_resp = await client.post(
            f"{api_prefix}/auth/verify-otp", json={"email": user.email, "otp": real_otp}
        )
        assert verify_resp.status_code == 200

        # verify-otp doesn't consume the row (only reset-password does) --
        # reuse the same real_otp to actually reset the password.
        reset_resp = await client.post(
            f"{api_prefix}/auth/reset-password",
            json={"email": user.email, "otp": real_otp, "new_password": "AnotherNewPass456!"},
        )
        assert reset_resp.status_code == 200

        new_login_resp = await client.post(
            f"{api_prefix}/auth/login",
            data={"username": user.email, "password": "AnotherNewPass456!"},
        )
        assert new_login_resp.status_code == 200
        new_refresh_token = new_login_resp.json()["refresh_token"]
        new_access_token = new_login_resp.json()["access_token"]

        refresh_resp = await client.post(
            f"{api_prefix}/auth/refresh", json={"refresh_token": new_refresh_token}
        )
        assert refresh_resp.status_code == 200
        rotated_refresh_token = refresh_resp.json()["refresh_token"]

        # Reuse the now-dead new_refresh_token to also exercise the
        # reuse-detection WARNING log path.
        await client.post(f"{api_prefix}/auth/refresh", json={"refresh_token": new_refresh_token})

        await client.post(
            f"{api_prefix}/auth/logout", json={"refresh_token": rotated_refresh_token}
        )

        secrets_that_must_never_appear = {
            "raw password": password,
            "second raw password": "AnotherNewPass456!",
            "raw otp": real_otp,
            "original access token": access_token,
            "original refresh token": refresh_token,
            "post-reset access token": new_access_token,
            "post-reset refresh token": new_refresh_token,
            "rotated refresh token": rotated_refresh_token,
        }

        all_messages = "\n".join(record.getMessage() for record in caplog.records)

        for label, secret in secrets_that_must_never_appear.items():
            assert secret not in all_messages, (
                f"SECURITY: found the {label} ({secret!r}) verbatim in a "
                f"captured log record. Design notes section 4.3 is explicit: "
                f"raw passwords, OTPs, and JWTs must NEVER be logged, under "
                f"any event, by any field."
            )

        # Sanity check that this test actually exercised logging at all
        # (an empty caplog would make every assertion above vacuously true).
        assert len(caplog.records) > 0, (
            "no log records were captured at all -- this test's negative "
            "assertions would be meaningless without this sanity check"
        )
        assert len(_audit_events(caplog)) >= 5, (
            f"expected several distinct app.audit events across this flow, "
            f"got {len(_audit_events(caplog))} -- if this is 0, the "
            f"secrets-not-logged assertions above are passing vacuously "
            f"because nothing is being logged yet, not because logging is "
            f"actually secret-safe"
        )
