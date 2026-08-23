"""
OBJ-003 finding #5 -- timing side-channel / user enumeration via response
latency on `/auth/login` and `/auth/forgot-password`, plus the OBJ-002
Gate 3 SAST fold-in on `/auth/logout` (obj-003-design-notes.md section 3.3).

No Gherkin/AC doc exists for OBJ-003 -- see tests/unit/test_otp_hashing.py's
docstring for the full explanation of the derivation approach. Scenarios
here come directly from obj-003-design-notes.md section 3's explicit
testability guidance (section 3.4), which is itself an explicit answer to
this project's own established precedent that Scenario 2.6 in
docs/requirements/obj-001-critical-auth-hardening.md ("OTP timing side
channel... best-effort, not strictly enforceable") could not be reliably
wall-clock tested -- OBJ-003 generalizes that same precedent to
login/forgot-password/logout rather than re-litigating it:

  DELIBERATE, PER DESIGN NOTES: NO wall-clock timing assertions anywhere in
  this file. Section 3's own framing: "perfectly equal wall-clock time is
  not achievable or sensibly testable... the design below produces a
  STRUCTURAL guarantee... That guarantee is unit-testable via call-count/
  mock assertions... not via timing measurement." Section 3.4 gives the
  literal assertions to write; this file implements exactly those:

  - "/login with a nonexistent email: assert verify_password (or
    verify_password_or_dummy) is called exactly once, with
    DUMMY_PASSWORD_HASH as the target hash." ->
    TestLoginConstantTimeGuarantee.test_login_with_nonexistent_email_still_calls_verify_password_once,
    test_login_with_nonexistent_email_targets_the_dummy_hash
  - "/login with an existing email/wrong password: assert the same call
    happens once, with the real user's hashed_password as the target." ->
    test_login_with_existing_email_wrong_password_calls_verify_password_once_against_real_hash
    (this one, notably, should ALREADY PASS today -- see its docstring;
    kept as a regression anchor, same convention as OBJ-001/002's
    already-green baseline tests)
  - "/forgot-password (if Option A is adopted): same pattern, both
    branches." Gate 1 (dependency_graph.md, 2026-08-23) approved Option A
    (unconditional bcrypt-dummy tax on every call) -> both tests in
    TestForgotPasswordConstantTimeGuarantee. Per design notes section 3.2's
    Option A illustrative call (`verify_password_or_dummy(payload.email,
    None)`), the target hash is DUMMY_PASSWORD_HASH in BOTH branches
    (found or not) -- /forgot-password never verifies a real password, so
    unlike /login there is no "existing user -> real hash" branch here.
  - "/auth/logout with an invalid/unsigned token: assert db.execute and
    db.commit are each called exactly once (matching the valid-jti
    branch's call counts), not zero times." -> TestLogoutConstantTimeGuarantee.
    Includes a baseline valid-jti test (already-correct behavior, must not
    regress) plus malformed-token and wrong-type-token variants (both
    currently red).

Mocking technique: `unittest.mock.patch(..., wraps=<the real function>)` on
`app.core.security.verify_password`, and `unittest.mock.patch.object(
db_session, "execute"/"commit", wraps=...)` on the per-test AsyncSession the
`client` fixture already overrides `deps.get_db` with. `wraps=` means the
mock still calls through to the real implementation (the endpoint's actual
behavior, and the DB state after the call, are unaffected) while recording
call count/args -- this is a spy, not a stub; nothing about the underlying
mechanism under test is faked.

Requires Postgres (tests/api/**, per tests/conftest.py) for the DB-backed
call-count assertions; the pure verify_password call-count assertions don't
strictly need a live DB but run through the same `client`/`db_session`
fixtures as everything else in tests/api/ for consistency.
"""

from unittest.mock import patch

from app.core import security


async def _login(client, api_prefix, email, password):
    return await client.post(
        f"{api_prefix}/auth/login", data={"username": email, "password": password}
    )


class TestLoginConstantTimeGuarantee:
    async def test_login_with_nonexistent_email_still_calls_verify_password_once(
        self, client, api_prefix
    ):
        """The core fix for finding #5's dominant signal (design notes
        section 3, evidence): today, `if not user or not
        security.verify_password(...)` SHORT-CIRCUITS when `user` is None,
        so verify_password is called ZERO times for a nonexistent email --
        this is the actual enumeration oracle. Post-fix, it must be called
        exactly once regardless."""
        with patch(
            "app.core.security.verify_password", wraps=security.verify_password
        ) as mock_verify:
            resp = await _login(
                client, api_prefix, "definitely-does-not-exist@example.com", "whatever123!"
            )

        assert resp.status_code == 400
        assert mock_verify.call_count == 1, (
            f"security.verify_password must be called exactly ONCE for a "
            f"nonexistent email (obj-003-design-notes.md section 3.1) -- "
            f"was called {mock_verify.call_count} time(s). Today's code "
            f"short-circuits via `if not user or ...` and never calls it "
            f"at all when the user doesn't exist -- this IS finding #5's "
            f"dominant, most exploitable signal."
        )

    async def test_login_with_nonexistent_email_targets_the_dummy_hash(
        self, client, api_prefix
    ):
        """design notes section 3.1's specific mechanism: the target hash
        for a nonexistent user must be the precomputed
        `security.DUMMY_PASSWORD_HASH` module constant, not e.g. a
        freshly-generated throwaway hash per request (which would defeat
        the 'computed once at process startup, not per-request' cost
        rationale) or some other placeholder."""
        with patch(
            "app.core.security.verify_password", wraps=security.verify_password
        ) as mock_verify:
            await _login(
                client, api_prefix, "still-does-not-exist@example.com", "whatever123!"
            )

        assert mock_verify.call_count == 1
        called_target_hash = mock_verify.call_args.args[1]
        assert called_target_hash == security.DUMMY_PASSWORD_HASH, (
            "the bcrypt verify for a nonexistent user must target "
            "security.DUMMY_PASSWORD_HASH specifically (design notes "
            "section 3.1's precomputed-at-import-time dummy hash)"
        )

    async def test_login_with_existing_email_wrong_password_calls_verify_password_once_against_real_hash(
        self, client, api_prefix, user_factory
    ):
        """This scenario is UNCHANGED by the fix -- today's code already
        calls verify_password exactly once when the user exists (the
        short-circuit only skips the call for a NONEXISTENT user). Kept as
        an explicit regression anchor: the reordering in design notes
        section 3.1 must not accidentally add a second call, drop the
        call, or swap in the dummy hash for a real user. Expected to
        ALREADY PASS today -- same convention as OBJ-001/OBJ-002's
        already-green baseline tests documenting must-not-regress
        behavior."""
        user, password = await user_factory(email="timing-existing-user@example.com")

        with patch(
            "app.core.security.verify_password", wraps=security.verify_password
        ) as mock_verify:
            resp = await _login(client, api_prefix, user.email, "TotallyWrongPass1!")

        assert resp.status_code == 400
        assert mock_verify.call_count == 1
        called_target_hash = mock_verify.call_args.args[1]
        assert called_target_hash == user.hashed_password, (
            "for an EXISTING user, the bcrypt verify must target the "
            "user's own hashed_password, never the dummy hash"
        )


class TestForgotPasswordConstantTimeGuarantee:
    """Gate 1 (dependency_graph.md, 2026-08-23): Option A approved --
    unconditional bcrypt-dummy tax on EVERY /forgot-password call. Unlike
    /login, /forgot-password never has a real password to check, so per
    design notes section 3.2's illustrative call
    (`verify_password_or_dummy(payload.email, None)`), the target hash is
    DUMMY_PASSWORD_HASH in BOTH the found and not-found branches -- there
    is no 'existing user -> real hash' case here at all."""

    async def test_forgot_password_with_nonexistent_email_calls_verify_password_once(
        self, client, api_prefix
    ):
        with patch(
            "app.core.security.verify_password", wraps=security.verify_password
        ) as mock_verify:
            resp = await client.post(
                f"{api_prefix}/auth/forgot-password",
                json={"email": "fp-nonexistent@example.com"},
            )

        assert resp.status_code == 200
        assert mock_verify.call_count == 1, (
            f"security.verify_password must be called exactly ONCE on "
            f"/forgot-password for a nonexistent email (Gate-1-approved "
            f"Option A, design notes section 3.2) -- was called "
            f"{mock_verify.call_count} time(s). Today's code has NO "
            f"password-verification call anywhere in this handler at all."
        )

    async def test_forgot_password_with_existing_email_calls_verify_password_once(
        self, client, api_prefix, user_factory
    ):
        user, _ = await user_factory(email="fp-existing@example.com")

        with patch(
            "app.core.security.verify_password", wraps=security.verify_password
        ) as mock_verify:
            resp = await client.post(
                f"{api_prefix}/auth/forgot-password", json={"email": user.email}
            )

        assert resp.status_code == 200
        assert mock_verify.call_count == 1, (
            "the SAME unconditional dummy-work call must also fire for an "
            "EXISTING email -- Option A applies uniformly to both branches, "
            "otherwise the found/not-found asymmetry the fix targets would "
            "just move rather than close"
        )

    async def test_forgot_password_always_targets_the_dummy_hash_never_a_real_one(
        self, client, api_prefix, user_factory
    ):
        """The one property that distinguishes /forgot-password's
        constant-time mechanism from /login's: even for an EXISTING user,
        the dummy-work call must target DUMMY_PASSWORD_HASH, never that
        user's real hashed_password -- /forgot-password has no legitimate
        reason to ever pass a real password hash into a verify call at
        all."""
        user, _ = await user_factory(email="fp-existing-target@example.com")

        with patch(
            "app.core.security.verify_password", wraps=security.verify_password
        ) as mock_verify:
            await client.post(f"{api_prefix}/auth/forgot-password", json={"email": user.email})

        assert mock_verify.call_count == 1
        called_target_hash = mock_verify.call_args.args[1]
        assert called_target_hash == security.DUMMY_PASSWORD_HASH, (
            "even for an existing email, /forgot-password's dummy-work "
            "call must target DUMMY_PASSWORD_HASH -- it must never verify "
            "against a real user's hashed_password (no password is being "
            "checked here at all, only padding the response cost)"
        )


class TestLogoutConstantTimeGuarantee:
    """obj-003-design-notes.md section 3.3, folding in the OBJ-002 Gate 3
    SAST finding: '/auth/logout only touches the database when jti is not
    None... an invalid/malformed/unsigned token returns immediately with
    no DB round-trip.' Fix: the jti-is-None branch performs an
    equivalent-shaped no-op (`select(1)`) plus an unconditional commit, so
    BOTH branches make exactly one db.execute call and one db.commit call.
    """

    async def _login_and_get_refresh_token(self, client, api_prefix, user_factory, email):
        user, password = await user_factory(email=email)
        resp = await _login(client, api_prefix, user.email, password)
        assert resp.status_code == 200, resp.text
        return resp.json()["refresh_token"]

    async def test_logout_with_valid_refresh_token_touches_db_exactly_once_each(
        self, client, api_prefix, user_factory, db_session
    ):
        """Baseline / regression anchor: the valid-jti branch already does
        exactly one execute + one commit today (the revoke UPDATE +
        commit) -- expected to ALREADY PASS, must not regress once the
        no-op branch is added alongside it."""
        refresh_token = await self._login_and_get_refresh_token(
            client, api_prefix, user_factory, "timing-logout-valid@example.com"
        )

        with patch.object(
            db_session, "execute", wraps=db_session.execute
        ) as mock_execute, patch.object(
            db_session, "commit", wraps=db_session.commit
        ) as mock_commit:
            resp = await client.post(
                f"{api_prefix}/auth/logout", json={"refresh_token": refresh_token}
            )

        assert resp.status_code == 204
        assert mock_execute.call_count == 1
        assert mock_commit.call_count == 1

    async def test_logout_with_malformed_token_touches_db_same_as_valid_branch(
        self, client, api_prefix, db_session
    ):
        with patch.object(
            db_session, "execute", wraps=db_session.execute
        ) as mock_execute, patch.object(
            db_session, "commit", wraps=db_session.commit
        ) as mock_commit:
            resp = await client.post(
                f"{api_prefix}/auth/logout", json={"refresh_token": "not-a-jwt-at-all"}
            )

        assert resp.status_code == 204
        assert mock_execute.call_count == 1, (
            f"a malformed token must still cause exactly ONE db.execute "
            f"call (the section 3.3 no-op `select(1)`), matching the "
            f"valid-jti branch's call count -- was called "
            f"{mock_execute.call_count} time(s). Today's code returns "
            f"immediately with NO db interaction at all for this branch, "
            f"which is exactly the timing side-channel being closed."
        )
        assert mock_commit.call_count == 1, (
            "a malformed token must still cause exactly ONE db.commit "
            "call, matching the valid-jti branch -- design notes section "
            "3.3 explicitly moves commit() outside the `if` so both "
            "branches call it unconditionally"
        )

    async def test_logout_with_wrong_type_token_touches_db_same_as_valid_branch(
        self, client, api_prefix, user_factory, db_session
    ):
        """A well-formed, correctly-signed ACCESS token (no `jti` claim)
        submitted as the refresh_token body field -- same 'jti is None'
        branch as the malformed-token case above, via a different route
        (extract_jti_if_present succeeds at the JWT level but finds no
        `jti` claim to return)."""
        user, password = await user_factory(email="timing-logout-wrong-type@example.com")
        login_resp = await _login(client, api_prefix, user.email, password)
        assert login_resp.status_code == 200, login_resp.text
        access_token = login_resp.json()["access_token"]

        with patch.object(
            db_session, "execute", wraps=db_session.execute
        ) as mock_execute, patch.object(
            db_session, "commit", wraps=db_session.commit
        ) as mock_commit:
            resp = await client.post(
                f"{api_prefix}/auth/logout", json={"refresh_token": access_token}
            )

        assert resp.status_code == 204
        assert mock_execute.call_count == 1, (
            "a well-formed access token (wrong type, no jti) submitted to "
            "/auth/logout must still cause exactly ONE db.execute call, "
            "matching the valid-jti branch"
        )
        assert mock_commit.call_count == 1
