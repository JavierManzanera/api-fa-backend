# OBJ-005: Email Verification Flow — User Stories & Acceptance Criteria

**Objective:** Remediate audit finding #11 (Low severity) — implement a real `/verify-email` flow, enforce `is_verified` at login, and establish a pluggable email-sender abstraction to replace the current print-based mock.

**Traces to:** `docs/security/audit-report.md` § Hallazgo #11.

**Audit context:** Currently:
- `is_verified` field exists on `User` but is created as `False` in `/register` and never set to `True` anywhere.
- No `/verify-email` endpoint exists to transition the field.
- `/login` never consults `is_verified`, so unverified users can log in.
- Email sending for password reset (`/forgot-password`, part of OBJ-003's Phase 3) uses a print-based debug mock that does not actually send emails.

**Product Decision Required (Gate 1):** Explicitly confirm the enforcement policy for unverified users at login (see "Open Product Decisions" section below).

**Quick index:** 3 stories, 24 Gherkin scenarios total (email verification flow, login/refresh
enforcement, pluggable email sender). All 5 open product decisions this doc poses (login
enforcement policy, token mechanism, resend behavior, email-failure handling, delivery seam) were
resolved by Gate 1 (2026-08-23) and `docs/api/obj-005-design-notes.md` — notably, Gate 1 chose to
**reuse the existing 6-digit OTP infrastructure**, the opposite of this doc's own recommended
long-random-link-token option; read the design-notes doc for the actual answers, this doc only
states the original options as posed. Jump to: "Story 1: User email verification flow", "Story 2:
Login endpoint enforces email verification per policy", "Story 3: Email-sender abstraction",
"Edge Cases & Security Considerations", "Open Product Decisions (Gate 1 Confirmation Required)".

---

## Story 1: User email verification flow enables secure account activation

**Narrative:**

As a **developer consuming this auth template in a new project**, I want the system to verify that a user controls the email address they provide at registration, so that the email cannot be used as an account identifier by an attacker without proof of delivery, and so that legitimate users have a mechanism to correct a typo before being locked in.

As a **user who just registered**, I want to receive a verification token or link via email, submit it to the system to prove I control that email, so that my account is fully activated and cannot be used by someone who merely knows my email.

As a **developer configuring the auth template for production**, I want the email-sending mechanism to be pluggable (SMTP, SES, SendGrid, etc.), so that I can swap in the real provider for my infrastructure without changing business logic.

**Acceptance Criteria:**

### Scenario 1.1: Registration creates user with `is_verified=False` and generates verification token
```gherkin
Given a user submits POST /register with email and password
When the registration is successful (201)
Then:
  - A new User row is created with is_verified=False
  - A new Verification row is created with purpose="email_verification" (or "email", implementation choice)
  - A verification token (design TBD: HMAC-based, symmetric encryption, or reuse existing OTP structure)
    is generated and stored (hashed per OBJ-003 hardening: no plaintext at rest)
  - An email is sent to the registered address containing the verification token/link
    (exact transport TBD: magic link, code, token in URL, etc. — see "Token Mechanism" note below)
  - The response body contains only user.id, user.email, and is_verified=False
    (no token/secret leaked in HTTP response)
```

### Scenario 1.2: Verify endpoint with valid token sets `is_verified=True`
```gherkin
Given a user has received a verification token via email (from Scenario 1.1)
When the user sends POST /verify-email with the verification token/code
Then the response status is 200
And the User.is_verified field is updated to True
And the Verification row is marked as consumed (or deleted, per design choice)
  — and cannot be reused
And the response contains user.id, user.email, is_verified=True
```

### Scenario 1.3: Verification with expired token is rejected
```gherkin
Given a verification token that was issued 24 hours ago (TTL TBD, design choice)
When a user attempts to submit this token to POST /verify-email
Then the response status is 400 (or 401)
And the response detail indicates "token expired" or "verification code no longer valid"
And the User.is_verified remains False
And no new tokens are issued
```

### Scenario 1.4: Verification with invalid/tampered token is rejected
```gherkin
Given an attacker who attempts to guess or forge a verification token
When the attacker sends POST /verify-email with an invalid token
Then the response status is 400 (or 401)
And the response detail indicates "invalid token" or "code not recognized"
And the User.is_verified remains False
And the invalid attempt is logged (audit trail for abuse detection)
```

### Scenario 1.5: Verification token cannot be reused after successful verification
```gherkin
Given a user has successfully verified their email with a token (Scenario 1.2)
When the same user (or an attacker who obtained that token) attempts to use it again
  in another POST /verify-email request
Then the response status is 400
And the response indicates "token already used" or "verification code invalid"
And no side effects occur (e.g., is_verified does not toggle back to False)
```

### Scenario 1.6: Resend verification email (cold-start recovery)
```gherkin
Given a user who registered but has not yet verified their email
When the user (or support staff on their behalf) requests to resend the verification email
  via POST /resend-verification-email (or /verify-email with a resend flag, implementation choice)
  with their email address
Then the response status is 200
And a fresh verification token is generated and sent to the email
And the previous unverified token (if any) becomes invalid (soft invalidation: marked expired,
  not deleted, per OBJ-001's pattern for OTP lockout)
And subsequent verify requests must use the fresh token, not the old one
```

### Scenario 1.7: Resend verification is rate-limited and cooldown-protected
```gherkin
Given a user requests verification email resend multiple times in quick succession
When the user sends more than K requests (e.g., 3 per minute) to POST /resend-verification-email
  within the same window
Then requests after the Kth are rejected with status 429
And the user is instructed to retry after a delay (Retry-After header)
And the rate limit applies per email, not per session/user_id (to not leak whether an email is registered)
```

### Scenario 1.8: Plaintext token never leaked in HTTP response or logs
```gherkin
Given a verification token is generated and sent via email
When the user submits the token to POST /verify-email
And the token is validated against the stored hash in the Verification row
Then:
  - The plaintext token is never present in any HTTP response body
  - The plaintext token is never logged at debug/info/warn level (only anonymized reference)
  - Any error message does not reveal whether the token was close-to-valid
    (all invalid tokens resolve to the same generic error message)
```

---

## Story 2: Login endpoint enforces email verification per policy

**Narrative:**

As a **security architect**, I want the system to enforce a configurable policy at login time: users with `is_verified=False` are either **blocked entirely** (stronger security posture, no unverified access) or **warned but allowed** (softer UX, weaker enforcement, optionally with degraded privileges). This decision directly impacts user onboarding friction vs. account takeover resistance.

As a **developer of a downstream project**, I want the policy to be a clear, settable constant (not a code branch with conditional logic scattered across files), so that audits and threat modeling can verify the exact enforcement in production.

**Acceptance Criteria (both policy options described below — choose one at Gate 1):**

### Option A: Block Unverified (Strict Security Posture)

#### Scenario 2.A.1: Unverified user cannot obtain access token on login
```gherkin
Given a user with is_verified=False
When the user submits POST /login with their email and correct password
Then the response status is 403 (or 401, design choice: auth failure vs. permission failure)
And the response detail indicates "email not verified" or "please verify your email before logging in"
And no access token or refresh token is issued
And the user is instructed to check their email and complete verification
And no difference in response time/status between wrong password and unverified
  (prevent timing side-channel enumeration of unverified accounts)
```

#### Scenario 2.A.2: Verified user obtains tokens on login normally
```gherkin
Given a user with is_verified=True
When the user submits POST /login with their email and correct password
Then the response status is 200
And the response contains access_token, refresh_token, user.is_verified=True
And the user can immediately call protected endpoints
```

#### Scenario 2.A.3: Verified user retains access after reverting to unverified (auditing gate, not re-verification)
```gherkin
Given a user with is_verified=True and an active valid access token
When (hypothetically, via admin endpoint or debugging scenario) the user's is_verified is reset to False
Then:
  - The user's existing access token remains valid until its natural exp (this is not a token-level revocation)
  - The user cannot obtain a new access token via /login (blocked by Scenario 2.A.1)
  - The refresh token also cannot be used to refresh (see Scenario 2.A.4)
And the behavior is symmetric with OBJ-002's password-reset revocation (one-way: verification becomes a prerequisite for new sessions, not a revocation of existing ones)
```

#### Scenario 2.A.4: Unverified user cannot refresh even with valid refresh token
```gherkin
Given a user with is_verified=False who somehow holds a valid refresh token
  (e.g., from before their verification was revoked, per Scenario 2.A.3)
When the user sends POST /auth/refresh with that token
Then the response status is 403 (or 401)
And the response indicates "email not verified" or "user account not verified"
And no new access token is issued
```

### Option B: Warn But Allow (Softer UX, Optional Degraded Access)

#### Scenario 2.B.1: Unverified user can obtain tokens but with warning flag
```gherkin
Given a user with is_verified=False
When the user submits POST /login with their email and correct password
Then the response status is 200
And the response contains access_token, refresh_token
And the response body includes a flag: is_verified=False (or a warning field)
And the access token's payload includes a claim indicating the user is unverified
  (e.g., "email_verified": False, so the token itself carries this signal)
And the client is expected to display a UI warning: "Please verify your email"
And the user can call protected endpoints, but those endpoints MAY check the token's is_verified
  claim and choose to deny certain operations (e.g., no payment processing, read-only mode)
```

#### Scenario 2.B.2: Verified user retains full access
```gherkin
Given a user with is_verified=True
When the user submits POST /login with their email and correct password
Then the response status is 200
And the response contains access_token, refresh_token, is_verified=True
And the user has unrestricted access to all endpoints
```

#### Scenario 2.B.3: Protected endpoints MAY check token's is_verified claim
```gherkin
Given an endpoint /api/protected that requires is_verified=True per business logic
When an unverified user (holding an access token with is_verified=False)
  calls that endpoint
Then the endpoint can reject with 403 "email not verified"
  OR allow the request but log a warning
(The exact behavior is application-specific, outside the scope of the auth template.
 This scenario documents that the mechanism exists so downstream projects CAN enforce it.)
```

---

## Story 3: Email-sender abstraction enables pluggable delivery mechanisms

**Narrative:**

As a **developer maintaining this auth template**, I want the email-sending logic to be abstracted behind a simple interface, so that different projects can wire in SMTP, SES, SendGrid, or even a mock/console sender without forking the template or modifying business logic.

As a **developer of a downstream project**, I want to be able to swap in my infrastructure's email provider (e.g., production SES, staging console, CI/test mock) by setting a single config parameter, so that the same codebase works across environments.

**Acceptance Criteria:**

### Scenario 3.1: Email abstraction interface is defined
```gherkin
Given the email-sending mechanism is abstracted
When the system needs to send an email (registration verification, password reset, etc.)
Then there exists an abstract base class or protocol EmailSender with a method like:
  async send_email(to: str, subject: str, body: str, html_body: str = None) -> bool
  or
  async send_transactional_email(template_id: str, recipient: str, context: dict) -> bool
(Exact signature TBD by solution-architect; the point is it's not hardcoded logic.)
```

### Scenario 3.2: Default implementation (print-to-console) for development/testing
```gherkin
Given no email provider is configured in the environment
When the system attempts to send an email (e.g., on /register or /forgot-password)
Then the system falls back to a ConsoleEmailSender (or DebugEmailSender)
  that prints to stdout/logging with the email details (recipient, subject, body)
And this is the current behavior, now moved into the abstraction
And the message includes the full plaintext verification token/code so developers can copy-paste it in tests
```

### Scenario 3.3: SMTP/SendGrid/SES provider is pluggable
```gherkin
Given environment variables configure which email provider to use:
  EMAIL_PROVIDER=smtp (or "sendgrid", "ses", "console", implementation choice)
  EMAIL_FROM=noreply@example.com
  (plus provider-specific credentials: SMTP_HOST/PORT, SENDGRID_API_KEY, AWS_SES_*, etc.)
When the application starts
Then the correct EmailSender subclass is instantiated via dependency injection
  and registered as a singleton
And business logic (auth endpoints) calls the injected sender without caring about provider choice
```

### Scenario 3.4: Email send failure does not silently succeed
```gherkin
Given an email provider is configured but unreachable (SMTP timeout, API error, etc.)
When the system attempts to send a verification email to a new /register user
Then:
  - The send attempt returns an error/exception (not a silent success)
  - The /register endpoint either:
    a) Rejects the registration (rollback user creation, return 503 "temporarily unavailable"), OR
    b) Queues the email for retry and continues (idempotent: user exists, email pending)
  - The response to the client is NOT "registration successful, go verify" if the email wasn't actually sent
  - This is a critical business logic point: plaintext verification tokens must not be emitted in an HTTP response,
    so if the email fails, the user has no way to proceed (design point: decide queuing strategy before Phase 3)
```

### Scenario 3.5: Email template/content is configurable
```gherkin
Given an email sender is configured
When the system sends a verification email, password reset email, etc.
Then the email subject, body, and sender name are either:
  a) Loaded from environment variables or a config file (not hardcoded in code), OR
  b) Passed as template parameters (EmailSender.send_transactional_email(template_id="verify_email", ...))
And the verification link/token is injected into the template (e.g., https://app.example.com/verify?code=<TOKEN>)
And the template is never written inline in Python strings (maintainability + multi-language support)
```

### Scenario 3.6: No plaintext token in outbound email logs or monitoring
```gherkin
Given an email is sent with a verification token
When the system logs or monitors the email-send event
Then:
  - The plaintext token is not logged (only metadata: recipient, status, timestamp)
  - If email logs are retained externally (e.g., SendGrid activity feed), the token in the email
    body is treated as sensitive and the implementation/operations are aware of this
    (this is an implementation/deployment note, not a test-checkable AC, but worth documenting)
```

---

## Edge Cases & Security Considerations

### Token Mechanism (Design Question for solution-architect)

The AC above deliberately avoid specifying the exact verification token format because this is an architectural choice, not a business requirement:

**Options:**
1. **Reuse existing OTP infrastructure** (from OBJ-001/003): Generate a 6-digit code, store HMAC-hashed, reuse `Verification` table with `purpose="email_verification"`. Pros: single code path, leverages existing rate-limiting/lockout. Cons: 6-digit space is weaker for email (user copies manually vs. OTP on phone), less typical UX.

2. **Long random token** (industry standard): Generate a 32-64 byte random token (e.g., `secrets.token_urlsafe(48)`), store HMAC-hashed, reuse `Verification` table. Pros: strong space, typical UX (click link or copy-paste long token). Cons: longer storage, different UX from password-reset OTP.

3. **Separate mechanism** (HMAC-based link): Mint a time-limited HMAC over `(user_id, email, timestamp)` — validate on submission without a DB lookup (stateless). Pros: no DB row needed. Cons: doesn't leverage existing lockout/rate-limit structure, weaker feedback on token validity (can't distinguish "expired" from "never-existed").

**Recommendation:** Option 2 (long random token, stored with HMAC hash in `Verification` table, reuse rate-limit/lockout from OBJ-001). This aligns with OBJ-003's hardening (HMAC at rest, constant-time comparison) and provides strongest UX/security balance.

### Interaction with OBJ-001/003 Verification Table

- The `Verification` table already exists for password-reset OTPs (`purpose="reset_password"`).
- Email verification can reuse the same table with `purpose="email_verification"`.
- **Same-table sharing does NOT imply shared lockout counters**: a failed email-verification attempt should not decrement the user's password-reset OTP budget, and vice versa. The lockout/rate-limit logic in `_check_and_consume_otp` (OBJ-001 Phase 3) filters by `purpose` — this naturally isolates the two flows.
- **Index consideration**: if using long tokens, a composite index `(email, purpose, expires_at)` (already recommended by database-architect for OBJ-001's redesign) also serves email-verification queries well.

### Timing Side-Channels

- Email verification token validation should use constant-time comparison (already required for password reset per OBJ-003, apply same rigor here).
- Do NOT leak whether a token was "close to valid" — all invalid tokens resolve to the same error message (same pattern as OTP handling in OBJ-001).

### Resend Cooldown (Story 1, Scenario 1.7)

- The `resend-verification-email` endpoint should be rate-limited to prevent abuse (e.g., 3 requests/minute per email).
- Additionally, it should enforce a resend cooldown (e.g., 60 seconds) to avoid email flooding by a user who misclicked.
- Reuse the `enforce_rate_limit` infrastructure from OBJ-001 with a new `scope="email_verification_resend"`.

### Multi-Device Verification

- Scenario: user registers on Device A, verification email sent to their address. They switch to Device B, click the link, verify. Device A and Device C (both still holding unverified session data) should detect that is_verified is now True on the next request (either via a fresh call to `get_current_user` that re-reads the `User` row, or via a token refresh that carries the new `is_verified` claim).
- This is automatic if the access token is stateless (verified on each request via `get_current_user` reading `user.is_verified` from the DB), but worth testing end-to-end.

### Pre-OBJ-005 Unverified Users in Production

- If this template was already running in production with unverified users accumulating in the database, and OBJ-005 implements Option A (block unverified), a migration/policy decision is needed: does the enforcement apply to all users or only new registrations?
- **Out of scope for this objective**, but worth noting as a downstream consideration.

---

## Traceability

| Story | Audit Finding | OBJ-005 Scope | Notes |
|---|---|---|---|
| 1: Email verification flow | #11 — no `/verify-email` endpoint | New endpoint + verification mechanism | Closes the "dead code" gap for `is_verified` field |
| 2: Enforce at login | #11 — `login` doesn't check `is_verified` | Enforcement policy + conditional logic | Closes the "unverified access" gap |
| 3: Email-sender abstraction | Current implementation: print mock | Pluggable abstraction layer | Enables production-ready email handling for all flows |

---

## Open Product Decisions (Gate 1 Confirmation Required)

The following decisions must be explicitly resolved by the user/product owner before Phase 2 test-writing begins:

1. **Login enforcement policy (CRITICAL):**
   - **Option A:** Block unverified users entirely (403, no tokens issued).
   - **Option B:** Allow unverified users but mark them as unverified in the token (200, tokens issued, token includes `is_verified=False`).
   - **Recommendation:** Option A (stricter security posture). Reasoning: this is an auth template for building production-ready systems; unverified accounts are a common fraud/enumeration vector, and forcing verification upfront prevents them from entering active sessions. Option B trades off security for marginally better UX (users can explore the app while verifying email). For a reusable, hardened template, Option A sets a better default and downstream projects can weaken it if their threat model permits.
   - **Acceptance:** must be explicitly documented in the Gate 1 sign-off; tests will be written to cover the chosen option.

2. **Token mechanism for email verification:**
   - Short 6-digit OTP (reuse OBJ-001 infrastructure) vs. long random token (new storage/UX)?
   - **Recommendation:** Long random token (32-64 bytes, stored HMAC-hashed). Reasoning: aligns with modern email-verification UX (click link or copy token), naturally distinguishes from password-reset OTP, leverages OBJ-003's hardening pattern.

3. **Email resend policy:**
   - Should resend requests require the user to be authenticated (logged in), or allow unauthenticated resend (user provides email)?
   - **Recommendation:** Unauthenticated resend (user provides email). Reasoning: user may have lost their session cookie/token and still need to verify; prevents forcing a full re-login to resend a verification email.

4. **Email send failure handling:**
   - If the email provider fails (SMTP timeout, API error), should `/register` fail (return 503, rollback user creation), or succeed (user created, email queued for async retry)?
   - **Recommendation:** Fail the registration (return 503 or 502). Reasoning: verification token cannot be sent to the user, so they have no path to verify. Queuing adds complexity and creates "stuck" accounts (user exists, but no way to activate). If email is truly critical, fail loudly and immediately.

5. **Verification link URL structure:**
   - Should the token be a query parameter (`/verify?code=ABC123`), a path parameter (`/verify/ABC123`), or sent in request body (user copy-pastes)?
   - **Recommendation:** Query parameter (`/verify?code=ABC123`), sent in email as clickable link. Reasoning: best UX, standard pattern. Body would require copy-paste (friction), path parameter is less standard for email links.

---

## Implementation Notes

- All acceptance criteria assume **synchronous verification** (immediate response). Async behaviors (e.g., background email-send retry) may be captured in a future objective if needed.
- The email-sender abstraction should be registered as a FastAPI dependency (via `Depends()`), not imported directly in business logic, to keep concerns separated and enable testing with mock senders.
- Email templates should be stored externally (config files, env vars, or database, not hardcoded in Python) to allow translation/customization without code changes.
- The resend endpoint should be added in OBJ-005 Phase 3 (implementation), not Phase 1 (this spec) — though it's mentioned in Scenario 1.6 for completeness.

---

## Summary of Deferred Decisions

1. **Email provider choice** (Story 3): Specific implementation (SMTP, SendGrid, AWS SES, etc.) is an infra/deployment decision, out of scope. The abstraction in Phase 3 must be generic enough to support all.

2. **Token format** (Story 1, see "Token Mechanism" above): OAT or long random, picked by solution-architect per Gate 1 decision.

3. **Verification link generation** (Story 1.2): URL structure (query param, path param, email body link) is a frontend/UX decision.

4. **Email template content and localization** (Story 3.5): Template management strategy (env var, config file, database) decided by solution-architect.

5. **Audit logging for email-send events** (Story 3.6): Whether to log email-send success/failure, and at what level (info, audit trail), decided by security-specialist.

---

## Test Coverage Roadmap (for QA Phase 2)

Once these AC are approved, `qa-engineer` will write:

1. **Email verification flow tests (Story 1):**
   - Registration creates unverified user (Scenario 1.1)
   - Valid token verifies email (Scenario 1.2)
   - Expired token rejected (Scenario 1.3)
   - Invalid token rejected (Scenario 1.4)
   - Token reuse rejected (Scenario 1.5)
   - Resend generates fresh token (Scenario 1.6)
   - Resend rate-limited (Scenario 1.7)
   - No plaintext token in responses (Scenario 1.8)

2. **Login enforcement tests (Story 2) — one branch per policy option:**
   - **If Option A (Block):**
     - Unverified user blocked at login (Scenario 2.A.1)
     - Verified user logs in normally (Scenario 2.A.2)
     - Existing token remains valid if user unverified later (Scenario 2.A.3)
     - Refresh with unverified user fails (Scenario 2.A.4)
   - **If Option B (Warn/Allow):**
     - Unverified user can log in with warning flag (Scenario 2.B.1)
     - Verified user logs in fully (Scenario 2.B.2)
     - Protected endpoints can check `is_verified` claim (Scenario 2.B.3)

3. **Email-sender abstraction tests (Story 3):**
   - Abstract interface is defined and can be instantiated (Scenario 3.1)
   - Console/debug sender works by default (Scenario 3.2)
   - Provider can be swapped via config (Scenario 3.3)
   - Failed email send is not silently swallowed (Scenario 3.4)
   - Email content is templated (Scenario 3.5)
   - No plaintext token in logs (Scenario 3.6)

4. **Integration tests:**
   - End-to-end registration + email-send + verification + login flow
   - Resend on expired token, then verify successfully
   - Multi-device: verify on Device B, Device A sees user as verified
   - Token reuse + rate limit interaction
