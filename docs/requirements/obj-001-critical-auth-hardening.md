# OBJ-001: Critical Auth Hardening — User Stories & Acceptance Criteria

**Objective:** Remediate audit findings #1, #2, and #4 (Critical/High severity) to close unauthenticated account-takeover and JWT-type-confusion attack vectors.

**Traces to:** `docs/security/audit-report.md` § Hallazgos #1, #2, #4.

---

## Story 1: Refresh tokens cannot be used as access tokens

**Narrative:**

As a **developer consuming this auth template in a new project**, I want the framework to enforce strict type separation between refresh and access tokens, so that if a refresh token is leaked (XSS, log exposure, stolen device), an attacker cannot immediately use it to call protected endpoints.

As an **attacker with a leaked refresh token**, I want to send it as `Authorization: Bearer <refresh_token>` against protected endpoints, so that I can extend my access window from the natural 30-minute access token lifetime to the 7-day refresh token lifetime.

**Acceptance Criteria:**

### Scenario 1.1: Access token accepted on protected endpoint
```gherkin
Given a valid, non-expired access token
When I send a request to a protected endpoint with "Authorization: Bearer <access_token>"
Then the response status is 200 (or the appropriate success status for that endpoint)
And the endpoint processes the request normally
```

### Scenario 1.2: Refresh token rejected on protected endpoint
```gherkin
Given a valid, non-expired refresh token (issued by /refresh)
When I send a request to a protected endpoint with "Authorization: Bearer <refresh_token>"
Then the response status is 401
And the response contains an error indicating "invalid token type" or "insufficient privileges"
And the protected endpoint does not execute its business logic
```

### Scenario 1.3: Refresh token accepted on /refresh endpoint only
```gherkin
Given a valid, non-expired refresh token
When I send a POST request to /refresh with "Authorization: Bearer <refresh_token>"
Then the response status is 200
And the response contains a new access token and a new refresh token
```

### Scenario 1.4: Access token rejected on /refresh endpoint
```gherkin
Given a valid, non-expired access token (not a refresh token)
When I send a POST request to /refresh with "Authorization: Bearer <access_token>"
Then the response status is 401
And the response contains an error indicating "refresh token required" or "invalid token type"
And no new tokens are issued
```

### Scenario 1.5: Forged token with malicious type claim rejected
```gherkin
Given an attacker who crafts a JWT with a tampered "type" or "refresh" claim using a guessed SECRET_KEY
When the attacker sends this token as "Authorization: Bearer <forged_token>"
Then the response status is 401
And the endpoint rejects the token (either cryptographic signature verification fails, or type validation fails before trust is granted)
```

---

## Story 2: OTP rate limiting and attempt lockout prevent brute-force account takeover

**Narrative:**

As a **developer consuming this auth template**, I want the OTP flow to be protected against brute-force enumeration, so that an attacker cannot feasibly reset a user's password by trying all 10⁶ OTP combinations in the 10-minute validity window.

As an **attacker with a target email (obtained via enumeration or public list)**, I want to send thousands of requests to `/verify-otp` or `/reset-password` with sequential OTP guesses, and I want those requests to be rate-limited or cause account lockout so that I cannot compromise the account in a reasonable time window.

**Acceptance Criteria:**

### Scenario 2.1: OTP valid within TTL and correct code accepted
```gherkin
Given a user requests /forgot-password for their email
And an OTP is generated and remains valid (not expired, not already consumed)
When the user submits the correct OTP to /verify-otp within the TTL (10 minutes)
Then the response status is 200
And the OTP is marked as verified (can be used in subsequent /reset-password)
```

### Scenario 2.2: OTP rejected after TTL expires
```gherkin
Given an OTP that was issued 10 minutes and 1 second ago
When the user submits this OTP to /verify-otp
Then the response status is 400 (or 401)
And the error message indicates "OTP expired"
And the OTP cannot be used
```

### Scenario 2.3: OTP rejected after maximum attempt count exceeded
```gherkin
Given an OTP issued for a user
And the user has already submitted 5 incorrect OTP guesses (N=5, configurable)
When the user submits the 6th incorrect OTP
Then the response status is 429 (or 403)
And the error message indicates "too many failed attempts" or "account temporarily locked"
And the OTP record is marked as locked/consumed
And subsequent requests with any OTP (even the correct one) are rejected for this verification session
```

### Scenario 2.4: Rate limiting per IP+email prevents distributed brute force
```gherkin
Given an endpoint (/forgot-password, /verify-otp, /reset-password) that initiates or validates an OTP
When an attacker sends more than K requests (configurable, e.g., 10 per minute) from the same IP to the same email target
Then requests after the Kth are rejected with status 429
And the client is instructed to retry after a delay (e.g., "Retry-After: 60")
And the rate limit applies even if the guesses are varied (different OTP values)
```

### Scenario 2.5: OTP consumed after successful verification (no reuse)
```gherkin
Given an OTP that has already been used successfully in a /verify-otp or /reset-password request
When the attacker submits the same OTP again in another request
Then the response status is 400 (or 401)
And the error message indicates "OTP already used" or "code no longer valid"
```

### Scenario 2.6: OTP does not leak in timing differences (prevent oracle)
```gherkin
Given two requests: one with a valid OTP and one with an invalid OTP (both within TTL)
When both requests are made to /verify-otp for the same email with similar network conditions
Then the response latency is indistinguishable (within acceptable statistical bounds, e.g., ±50ms)
And an attacker cannot reliably distinguish a valid OTP from invalid via timing side-channels
```

### Scenario 2.7: Multiple concurrent OTP requests from same user do not bypass lockout
```gherkin
Given a user has already submitted 4 failed OTP guesses (out of 5 allowed)
And the user has submitted a 5th failed guess
When an attacker sends 10 rapid requests in parallel with different OTP guesses
Then all requests after the 5th fail with status 429 or 403
And the account/OTP record remains locked
And no subsequent request (even with the correct OTP) succeeds until the lockout window expires or is manually reset
```

### Scenario 2.8: Cryptographically secure OTP generation (no predictability)
```gherkin
Given 100 OTPs generated in sequence
When an observer analyzes the distribution of OTP values
Then the OTPs appear uniformly random across the 0-999999 range (6-digit space)
And there is no detectable sequential pattern or bias that would allow an attacker to predict the next OTP
```

---

## Story 3: SECRET_KEY validated at startup to prevent weak/default secrets

**Narrative:**

As a **developer deploying this template to production**, I want the application to reject startup if `SECRET_KEY` is unset, too short, or still contains the placeholder value from `.env.example`, so that I cannot accidentally sign JWTs with a known or weak secret that an attacker can forge tokens for.

As an **attacker who gains read access to a dev machine with a cloned repository**, I want to check if the developer simply copied `.env.example` to `.env` without changing the placeholder, so that I can forge valid JWTs and impersonate any user.

**Acceptance Criteria:**

### Scenario 3.1: Valid SECRET_KEY permits startup
```gherkin
Given SECRET_KEY is set in .env to a valid value (e.g., generated via secrets.token_urlsafe(64))
And the length is >= 32 characters
And it does not match any known placeholder
When the application starts
Then startup succeeds
And the application is ready to accept requests
And JWTs are signed with this SECRET_KEY
```

### Scenario 3.2: Missing SECRET_KEY causes startup failure
```gherkin
Given SECRET_KEY is not set in .env (or is an empty string)
When the application attempts to start
Then startup fails with a clear error message like "SECRET_KEY must be set and non-empty"
And the application does not start (does not bind to port, does not initialize)
And logs indicate the misconfiguration
```

### Scenario 3.3: SECRET_KEY shorter than 32 characters causes startup failure
```gherkin
Given SECRET_KEY is set to a value with length < 32 (e.g., "short_key")
When the application attempts to start
Then startup fails with a clear error message like "SECRET_KEY must be at least 32 characters"
And the application does not start
```

### Scenario 3.4: Placeholder from .env.example causes startup failure
```gherkin
Given SECRET_KEY is set to the exact value from .env.example: "your_secret_key_here"
When the application attempts to start
Then startup fails with a clear error message like "SECRET_KEY must not be the default placeholder. Generate a new one with: secrets.token_urlsafe(64)"
And the application does not start
```

### Scenario 3.5: Case-sensitive placeholder detection
```gherkin
Given SECRET_KEY is set to a variation of the placeholder (e.g., "Your_Secret_Key_Here" or "YOUR_SECRET_KEY_HERE")
When the application attempts to start
Then either:
  a) The startup fails (if the check is case-insensitive), OR
  b) The startup succeeds (if the check is case-sensitive and this is legitimately different)
And the behavior is explicitly documented
```

### Scenario 3.6: Forged JWT with weak SECRET_KEY can be detected as invalid
```gherkin
Given an attacker who knows SECRET_KEY is the placeholder "your_secret_key_here"
And the attacker crafts a JWT signed with that known key
When the attacker sends this token as "Authorization: Bearer <forged_token>"
Then:
  a) If the application started: the signature verification succeeds (attacker succeeds — bad scenario, preventable by Scenario 3.4)
  b) If Scenario 3.4 prevented startup: the application never runs with a weak SECRET_KEY, so this attack is prevented at the source
```

### Scenario 3.7: Multiple known placeholders blocked
```gherkin
Given the application maintains a list of known unsafe values:
  - "your_secret_key_here"
  - "change_me"
  - "secret"
  - Any value matching the regex pattern "^(your_)?secret(key)?.*" (if applicable)
When SECRET_KEY is set to any of these values
Then startup fails with an error message indicating the value is a known placeholder or insecure pattern
And the application does not start
```

### Scenario 3.8: SECRET_KEY rotation does not require restart to apply (TBD)
```gherkin
Given an application running with an old valid SECRET_KEY
And SECRET_KEY is updated in .env to a new valid value
When the .env file is reloaded (mechanism TBD: file watch, manual reload endpoint, next restart)
Then:
  - Tokens signed before the rotation remain valid if verified against the old key, OR
  - The application supports multiple valid keys during a transition period, OR
  - A restart is required and is the only supported path (implementation detail)
And the documentation is explicit about the rotation process
```

---

## Product Decisions Required

The following ambiguities require explicit product/engineering decision before implementation:

1. **OTP Attempt Limit (Scenario 2.3):** How many failed attempts before lockout? (Suggested: 5-10, industry default 3-6.)

2. **OTP Lockout Duration:** After exceeding attempt limit, how long until a user can retry?
   - Option A: Fixed duration (e.g., 15 minutes).
   - Option B: Exponential backoff (e.g., 1 min, then 2 min, then 5 min, capped at 1 hour).
   - Option C: Manual unlock only (operator intervention or email reset link).

3. **Rate Limit Scope & Threshold (Scenario 2.4):**
   - Requests per minute per IP+email combination?
   - Separate thresholds for `/forgot-password` (initiate), `/verify-otp` (validate), `/reset-password` (execute)?
   - Suggested: 10 requests/min per IP+email on all three endpoints.

4. **OTP Length & TTL (Scenario 2.8):**
   - Current: 6 digits (10⁶ = 1,000,000 combinations), 10-minute TTL.
   - Alternative: 8 digits (10⁸), 5-minute TTL (trades UX for security).
   - Decision: keep as-is or adjust?

5. **SECRET_KEY Placeholder Detection (Scenario 3.4-3.7):**
   - Exact string match on `.env.example`'s placeholder only, or broader list?
   - Suggested list:
     - `"your_secret_key_here"`
     - `"change_me"`
     - `"secret"`
     - Any all-lowercase variant of the above.
   - Regex pattern or hardcoded list?

6. **Refresh Token Type Representation (Story 1):**
   - Option A: Add explicit `"type": "access"|"refresh"` claim to both token types, validate in `get_current_user`.
   - Option B: Keep `"refresh": true` claim, validate it's absent/false in `get_current_user`.
   - Recommended: Option A (explicit type is fail-closed and clearer in logs/debugging).

---

## Implementation Notes

- All acceptance criteria assume **synchronous validation** (immediate response). Async behaviors (e.g., background audit logging) may be captured in a later objective.
- OTP hashing (Story 2, Scenario 2.8 defense-in-depth) is deferred to OBJ-003 (data hardening) but should not delay OBJ-001's lockout and rate-limit controls.
- Timing side-channel mitigation (Scenario 2.6) is a best-effort goal; exact latency parity is not strictly enforceable at the acceptance-criteria level but should be part of the implementation review.
- `SECRET_KEY` validation (Story 3) is a **startup-time gate** — the application must not proceed to listen on the network if this check fails.
