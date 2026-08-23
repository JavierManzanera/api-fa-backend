# OBJ-002: Session & Token Lifecycle — User Stories & Acceptance Criteria

**Objective:** Remediate audit finding #3 (High severity) — implement token revocation, refresh token rotation, and password-reset invalidation to prevent stolen tokens from remaining valid for up to 7 days after a password change.

**Traces to:** `docs/security/audit-report.md` § Hallazgo #3.

**Audit context:** Currently:
- No `/logout` endpoint exists.
- `/refresh` returns the same `refresh_token` it received (no rotation).
- `reset_password` only updates `hashed_password`; no `token_version` or `security_stamp` exists to invalidate previously-issued tokens.
- A stolen refresh token remains valid for its full 7-day lifetime even after the user changes their password out of security concern.

---

## Story 1: Logout endpoint invalidates the current session

**Narrative:**

As a **user aware my session may be compromised**, I want a `/logout` endpoint that immediately invalidates my current refresh token, so that if I suspect a security breach I can revoke active sessions without waiting for token expiry.

As a **developer securing downstream applications**, I want the logout operation to invalidate at least the refresh token submitted with the logout request, preventing it from being used in a subsequent `/refresh` call (whether by an attacker who also obtained that token, or as a side effect of the user's own decision to log out).

**Acceptance Criteria:**

### Scenario 1.1: Logout succeeds with valid refresh token
```gherkin
Given a user has an active session with a valid, non-expired refresh token
When the user sends a POST request to /logout with their refresh token in the request body
  (or as Authorization header, implementation choice)
Then the response status is 200
And the response message indicates successful logout
And the refresh token is marked as revoked (added to a revocation store/blacklist)
```

### Scenario 1.2: Revoked refresh token rejected on subsequent /refresh attempt
```gherkin
Given a user has logged out and their refresh token is now revoked
When the user (or an attacker holding that token) attempts to use the revoked token
  in a subsequent POST /refresh request
Then the response status is 401
And the response detail indicates "token revoked", "token invalid", or "session expired"
And no new access token is issued
```

### Scenario 1.3: Logout attempt with already-expired refresh token is handled gracefully
```gherkin
Given a refresh token that has already expired naturally (passed its exp claim)
When a user sends a POST request to /logout with this expired token
Then the response status is either 200 (idempotent success) or 401
  (implementation choice: allow optional logout with expired tokens for UX)
And the request does not crash or expose internal error details
```

### Scenario 1.4: Logout attempt with invalid/malformed refresh token
```gherkin
Given an invalid, tampered, or malformed refresh token
When a user sends a POST request to /logout with this token
Then the response status is 401
And the response indicates the token is invalid
And the logout request does not insert garbage into the revocation store
```

### Scenario 1.5: Logout without credentials returns 401
```gherkin
Given a user sends a POST request to /logout without any token in the Authorization header
  or request body
Then the response status is 401
And the response detail indicates credentials are required
```

**Product decision required:** Should logout invalidate **only the submitted refresh token** (single-session revocation), or **all refresh tokens** for that user (full logout across devices)? For a multi-device user, the former allows selective per-device logout; the latter provides a "panic button" to revoke all sessions at once. Recommend documenting the choice and its UX implications.

---

## Story 2: Refresh token rotation with reuse detection and session binding

**Narrative:**

As a **security architect**, I want each `/refresh` call to issue a new refresh token and invalidate the old one, so that if a refresh token is stolen, the attacker can only use it once — the moment the user (or an attacker) uses it legitimately, a fresh token is issued and the old one becomes useless.

As an **attacker who stole a refresh token**, I want to use it in `/refresh` before the legitimate user does, so I can keep extending my access indefinitely. If I detect that the legitimate user has also tried to refresh with the same token (and succeeded), I want the system to alert the account owner that a token-reuse pattern suggests a compromise.

**Acceptance Criteria:**

### Scenario 2.1: /refresh rotates the refresh token and issues a new one
```gherkin
Given a user with a valid, non-expired refresh token (call it "token_v1")
When the user sends a POST request to /refresh with token_v1
Then the response status is 200
And the response contains:
  - A new access token
  - A new refresh token (call it "token_v2"), which is different from token_v1
And the user's session is now bound to token_v2 (token_v1 is retired)
```

### Scenario 2.2: Attempt to reuse a rotated refresh token fails
```gherkin
Given a user has already called /refresh once with token_v1, receiving token_v2
And token_v1 is now retired (revoked) in the system
When the same user (or an attacker) attempts to use token_v1 again in a second /refresh call
Then the response status is 401
And the error detail indicates "token revoked" or "invalid refresh token"
And no new tokens are issued
```

### Scenario 2.3: Race condition — attacker uses stolen token before legitimate user
```gherkin
Given a refresh token "token_v1" is stolen by an attacker and also held by the legitimate user
And both the attacker and the legitimate user attempt to use token_v1 in /refresh
  in rapid succession (within milliseconds, overlapping requests)
When the first request (attacker or user, timing-dependent) is processed successfully
  and receives a new token_v2 and marks token_v1 as revoked
And the second request (legitimate user or attacker) arrives while the first is
  still processing, or immediately after
Then:
  - The first request succeeds and receives token_v2
  - The second request fails with 401 "token revoked" or "token invalid"
  - The legitimate user's session is now on token_v2 (the attacker cannot use
    token_v1 anymore)
  - (Ideally: the legitimate user should be notified of the suspicious reuse
    pattern, e.g., via audit log or flagged login event — see Story 2.4 below)
```

**Product decision required (CRITICAL):** When a refresh token is reused (i.e., an attacker attempts to use a token that has already been rotated), should the system:

A. **Option 1 (Minimal):** Simply reject the reuse attempt (401) and leave other tokens/sessions alone. The user's current session (on the rotated token) remains valid.

B. **Option 2 (Conservative):** Detect reuse as a potential compromise signal and invalidate **all refresh tokens** for that user, forcing a re-login globally. This requires the user to explicitly re-authenticate to re-establish a session.

C. **Option 3 (Strict):** Invalidate all access and refresh tokens, **and** log a security event for manual review / alert the user immediately (via email or push notification) that suspicious activity was detected.

Recommend Option 2 (conservative) for a hardened auth template: it balances security (actual compromise likely if a token is being reused) with UX (the user can immediately re-login). Option 1 is simpler but leaves a potentially-compromised session alive. Option 3 requires email/notification infra (out of scope for this template). **Confirm choice before OBJ-002 Phase 3 starts.**

### Scenario 2.4: Multiple concurrent sessions — each rotates independently
```gherkin
Given a user has logged in from two devices (Device A and Device B)
  and holds two independent refresh tokens: token_session_A and token_session_B
When Device A calls /refresh with token_session_A
Then:
  - A new token_session_A_v2 is issued and returned to Device A
  - token_session_A is revoked
  - token_session_B remains valid and unaffected on Device B
  - The user can still use token_session_B to refresh from Device B
```

**Product decision required:** Should each session (per device/client) rotate independently (Scenario 2.4 above), or should refreshing from one device invalidate all other sessions? The former preserves multi-device usability; the latter is more aggressive but simplifies the compromise detection (any refresh implies that device is legitimate). Recommend independent rotation per session, unless the user explicitly logs out or a reuse is detected. **Confirm choice before OBJ-002 Phase 3 starts.**

### Scenario 2.5: Refresh token issued before OBJ-002 implementation (no session/family ID) is handled
```gherkin
Given a refresh token that was issued by the old /refresh implementation
  (before this objective, when /refresh echoed back the same token without rotation)
  and thus has no "session_id" or "family_id" field in its JWT payload
When a user attempts to use this legacy token in /refresh
Then the system should either:
  (a) Reject it cleanly (401) with a message like "legacy token, please re-login"
  (b) Accept it, issue a new token with full session tracking,
      and from that point forward track rotation normally
Recommendation: Option (b) is kinder to users who have been away and are returning
  to active sessions; Option (a) is simpler to implement. Decide based on UX priorities.
  Implementation must be idempotent (calling /refresh with the same legacy token
  twice does not create two separate new tokens).
```

---

## Story 3: Password reset invalidates all previously-issued tokens

**Narrative:**

As a **user concerned about a password compromise**, I want changing my password via `/reset-password` to immediately invalidate all my existing access and refresh tokens, so that even if an attacker obtained a token before the reset, it becomes useless immediately.

As a **developer of the auth template**, I want a simple, queryable mechanism to invalidate tokens on password change that doesn't require storing every single token ever issued, so I can implement this efficiently in SQL.

**Acceptance Criteria:**

### Scenario 3.1: Password reset succeeds and token invalidation is triggered
```gherkin
Given a user has completed /reset-password with a valid OTP and new password
When the backend updates the user's hashed_password in the database
Then simultaneously (or immediately after):
  - A token_version counter on the user record is incremented (or a timestamp
    security_stamp is updated)
  - All tokens (access and refresh) issued with the previous token_version value
    are considered invalid
  - The user's session must re-authenticate to obtain new tokens
```

### Scenario 3.2: Attempt to use an old access token after password reset fails
```gherkin
Given a user has obtained an access token before calling /reset-password
  (e.g., obtained via login or /refresh)
And the user then calls /reset-password and changes their password
  (their token_version is now V+1)
When the user attempts to use the pre-reset access token in a request
  to a protected endpoint (e.g., GET /auth/me)
Then the response status is 401
And the response detail indicates "token invalid", "session expired",
  or "token version mismatch"
And the endpoint does not process the request
```

### Scenario 3.3: Attempt to use an old refresh token after password reset fails
```gherkin
Given a user has obtained a refresh token before calling /reset-password
And the user then calls /reset-password and changes their password
When the user attempts to use the pre-reset refresh token in a POST /refresh call
Then the response status is 401
And the response detail indicates token is invalid
And no new access token is issued
```

### Scenario 3.4: Multiple sessions simultaneously — all access and refresh tokens invalidated
```gherkin
Given a user with multiple active sessions (Device A, Device B, Device C),
  each holding valid access and refresh tokens issued with the same token_version V
When the user (via any device, or via a forgot-password + reset-password flow)
  calls POST /reset-password and changes their password
Then:
  - token_version on the user record is incremented to V+1
  - All access and refresh tokens with payload.token_version == V become invalid
  - Sessions on Device A, B, and C are all immediately invalidated
  - Attempts to call any protected endpoint or /refresh fail with 401
  - All three devices must re-authenticate (via login) to obtain new V+1 tokens
```

### Scenario 3.5: Token version/security_stamp is immutable in JWT payload (cannot be forged)
```gherkin
Given an attacker who obtains the SECRET_KEY and crafts a forged access token
  with a false token_version claim (e.g., carrying V+1 when the user's actual V is 0)
When the attacker sends this forged token with token_version==V+1 to a protected endpoint
Then the backend must:
  - Decode the JWT successfully (signature validates with SECRET_KEY)
  - Extract the token_version claim from the payload
  - Query the database for the user's current token_version
  - Compare the two: forged_token_version (V+1) vs. user.token_version (V+1)
  - Since they match, the token appears valid...
    --> ARCHITECTURAL NOTE: This is a known gap if token_version alone is used.
        The fix is to also record a timestamp (e.g., user.password_reset_at)
        and validate that the token's iat (issued-at) claim occurred AFTER
        that timestamp. If iat < password_reset_at, reject the token.
        (This prevents an attacker from reusing the OLD token_version value
         by simply claiming the NEW one — the iat timestamp proves when the
         token was actually issued relative to the password change event.)
```

**Implementation note:** To prevent the attack in Scenario 3.5, the token validation path must check not only that `token.token_version == user.token_version`, but also that `token.iat > user.last_password_reset_at` (or use a server-side revocation list keyed by `(user_id, issued_before_timestamp)`). The architecture must be decided before Phase 2 test-writing, so tests can cover both the happy path and the edge case. **This decision is deferred to solution-architect in Phase 1 — do not implement without clarifying the iat-based validation strategy.**

### Scenario 3.6: Logout followed by password reset — both revocation mechanisms are independent
```gherkin
Given a user has two refresh tokens: token_A (from Device A) and token_B (from Device B)
When the user calls /logout from Device A (revoking token_A in the revocation store)
  and then calls /reset-password (incrementing token_version, invalidating both
  token_A and token_B by version)
Then:
  - token_A is doubly revoked (both in the revocation store AND via version mismatch)
  - token_B is also invalidated (only via version mismatch, not directly in revocation store)
  - Both devices must re-authenticate
  - No inconsistency or data duplication occurs
```

---

## Edge Cases & Security Considerations

### Timing & race conditions

**Refresh token stolen and used by attacker before legitimate user:**
- If an attacker obtains refresh token T and calls `/refresh` at timestamp t1, receiving token T_new and revoking T.
- And the legitimate user calls `/refresh` with the same T at timestamp t2 (where t2 > t1, but the requests may overlap in the app's processing order due to async/concurrency).
- The second request (legitimate user) should fail with 401 after the first request completes, since T is already revoked.
- This is testable via concurrent-request simulation (see Story 2.3 for the exact scenario).

### Token version overflow or wraparound

- If `token_version` is an integer and resets to 0 after some max value, an attacker who knew a token from "before the reset" could potentially craft a token claiming the new `token_version` after many password resets.
- Recommend using a large integer (64-bit) or a timestamp (e.g., `password_reset_at` as UNIX timestamp), which naturally never overflows in practice.

### Multiple password resets in rapid succession

- If a user calls `/reset-password` twice in rapid succession (e.g., t1 and t2, milliseconds apart), the token_version must be incremented atomically for each one.
- Tests must confirm that two sequential /reset-password calls with valid OTPs (one per call) both succeed and each increments the version correctly, not idempotently.

### Pre-OBJ-002 legacy tokens (no version claim)

- Tokens issued before this objective was implemented will not have a `token_version` claim in the JWT payload.
- When validating, the code must handle `payload.get("token_version", None)` — if None, either:
  - Reject all legacy tokens immediately (force re-login everywhere) — safest but harsh UX.
  - Accept legacy tokens as valid (treat missing claim as `version == user.current_version`) — simpler but requires the user's current version to match at least once; once any password reset happens, all legacy tokens invalidate anyway.
- Recommendation: Accept legacy tokens initially (option 2), so active users aren't kicked out mid-session. Once they reset their password, the version check kicks in and legacy tokens become invalid. **Document this in the AC so tests cover both cases.**

### Distributed systems & clock skew

- If `iat` (issued-at) timestamp is used to validate "token issued after password reset," ensure that token validation compares `token.iat` against `user.password_reset_at` with a small clock-skew tolerance (e.g., ±5 seconds).
- Reason: If a `/refresh` call and a `/reset-password` call happen at the same millisecond on different servers with slightly out-of-sync clocks, the comparison might incorrectly reject a valid refresh that was legitimately issued before the reset.

---

## Traceability

| Story | Audit Finding | OBJ-002 Scope | Notes |
|---|---|---|---|
| 1: Logout | #3 — no `/logout` exists | New endpoint + revocation mechanism | Closes the "no way to revoke tokens" gap for active users |
| 2: Refresh rotation | #3 — `/refresh` doesn't rotate | Token rotation + reuse detection | Closes the "stolen token usable forever" gap at the technology level |
| 3: Password reset invalidation | #3 — `reset_password` doesn't invalidate tokens | Token version/security stamp | Closes the "reset password doesn't help" gap — ensures password change is actually a revocation event |

---

## Summary of Decisions Deferred to Phase 1 (solution-architect + security-specialist)

1. **Revocation store choice** (Story 1): Redis-backed blacklist, PostgreSQL `revoked_tokens` table, or JWT `jti` (JWT ID) claim + allowlist? Recommend PostgreSQL table for consistency with existing OBJ-001 design (rate limiter table, no new external dependency).

2. **Logout scope** (Story 1): Single-session revocation (per token) or multi-session revocation (all tokens for the user)? Recommend single-session per the narrative, unless product requires "panic logout."

3. **Refresh token reuse response** (Story 2): Reject reuse silently (Option 1), or invalidate all refresh tokens on detected reuse (Option 2), or trigger alerts (Option 3)? **Recommend Option 2 — conservative and blocks the attack.**

4. **Multi-device session rotation** (Story 2): Independent rotation per session, or global invalidation on any refresh? Recommend independent per-session, unless product prefers "one device active at a time."

5. **Legacy token handling** (Story 2.5, Story 3.6): Reject pre-OBJ-002 tokens immediately, or accept them and let password reset invalidate them? Recommend the latter for better UX.

6. **Token version validation strategy** (Story 3.5): Use only `token_version` comparison, or combine with `iat > password_reset_at` check? **Recommend the latter — see implementation note in Scenario 3.5.**

7. **Clock skew tolerance** (Security Considerations): How many seconds of tolerance for `iat` validation in distributed deployments? Recommend 5-10 seconds, configurable.

---

## Test Coverage Roadmap (for QA Phase 2)

Once these AC are approved, `qa-engineer` will write:

1. **Logout tests:**
   - Valid logout with refresh token (Scenario 1.1)
   - Revoked token rejected on /refresh (Scenario 1.2)
   - Logout with expired token (Scenario 1.3)
   - Logout with invalid token (Scenario 1.4)
   - Logout without credentials (Scenario 1.5)

2. **Refresh rotation tests:**
   - Rotation succeeds, new token issued (Scenario 2.1)
   - Reuse of rotated token fails (Scenario 2.2)
   - Race condition simulation — one request wins, other blocked (Scenario 2.3)
   - Multi-device independent sessions (Scenario 2.4)
   - Legacy token handling (Scenario 2.5)

3. **Password reset invalidation tests:**
   - Token version increments on reset (Scenario 3.1)
   - Old access token rejected after reset (Scenario 3.2)
   - Old refresh token rejected after reset (Scenario 3.3)
   - Multi-session simultaneous invalidation (Scenario 3.4)
   - Token version + iat validation (Scenario 3.5)
   - Logout + reset interaction (Scenario 3.6)

4. **Integration & edge case tests:**
   - Concurrent refresh + reset (race condition)
   - Token version wraparound (if applicable)
   - Clock skew tolerance
   - Revocation store cleanup (if using table with TTL)

---

## Files Changed (Expected, Phase 1 reconnaissance)

Based on OBJ-001's pattern and this objective's scope, the following will likely be added/modified in Phase 3:

- `app/models/user.py` — add `token_version` (int) and `last_token_revocation_at` (datetime) or `last_password_reset_at` (datetime) fields.
- `app/models/revoked_tokens.py` (new) — model for logout/revocation store, if using Postgres table (PKs: user_id, refresh_token_jti or hash; TTL cleanup as per OBJ-006).
- `app/core/security.py` — update `create_refresh_token` to include `token_version` in JWT payload; update `verify_refresh_token` to check revocation store and version.
- `app/core/token_revocation.py` (new) — utilities for checking/adding revoked tokens, managing TTL.
- `app/api/deps.py` — update `get_current_user` to validate `token_version` and `iat` against user record.
- `app/api/v1/endpoints/auth.py` — add `/logout` endpoint; update `/refresh` to rotate token and check reuse; update `/reset-password` to increment `token_version`.
- `docs/api/openapi.yaml` — add `/logout` endpoint spec, update `/refresh` and `/reset-password` contracts to document revocation behavior.
- `docs/api/obj-002-design-notes.md` (new) — architectural choices (revocation store, iat validation, multi-device handling, etc.) documented for implementation.

---

## Open Questions for User/Product (Confirmation Needed at Phase 1 Gate)

1. Which revocation strategy: Redis, Postgres table, or JWT `jti` + allowlist?
2. Should logout invalidate one session or all sessions?
3. If a rotated refresh token is reused: silently reject (Option 1), invalidate all tokens (Option 2), or alert user (Option 3)?
4. Should refresh rotation be per-session (multi-device) or global (one active session)?
5. Should pre-OBJ-002 tokens (no version claim) be accepted initially, or rejected immediately?
6. Must the `iat` timestamp validation be implemented alongside `token_version`, or is version check alone sufficient for this template's threat model?
