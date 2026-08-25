-- OBJ-006: scheduled cleanup for `rate_limit_hits` (unbounded growth, flagged by
-- database-architect at OBJ-001 Gate 3, confirmed independently by qa-engineer and
-- security-specialist -- see .ai-context/dependency_graph.md OBJ-001 sections and
-- docs/security/audit-report.md Gate 3 - Verificacion OBJ-001).
--
-- Retention: 1 hour. The rate limiter's widest window used by any of the three
-- OTP-adjacent endpoints is 60s (see MAX_OTP_ATTEMPTS-adjacent constants in
-- app/api/v1/endpoints/auth.py); 1 hour is generous slack for clock skew and
-- manual debugging, not a tuned value -- see obj-006-migration-plan.md "Gate 1
-- open questions" for the adjustable-but-recommended framing.
--
-- MUST run outside the hot request path (app/core/rate_limit.py's
-- enforce_rate_limit is called on every login-adjacent request; adding a DELETE
-- there adds latency/lock contention for zero benefit to the request itself --
-- this was already ruled out in the OBJ-001 database-architect review).
--
-- No FK dependency: rate_limit_hits has no self-referential or child-table
-- pointers, so this DELETE has no ON DELETE-behavior prerequisite (unlike
-- refresh_sessions -- see cleanup_refresh_sessions.sql).

DELETE FROM rate_limit_hits
WHERE created_at < now() - interval '1 hour';
