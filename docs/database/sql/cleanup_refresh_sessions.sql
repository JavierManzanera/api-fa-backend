-- OBJ-006: scheduled cleanup for `refresh_sessions` (unbounded growth, flagged by
-- database-architect at OBJ-002 Gate 3 -- see .ai-context/dependency_graph.md
-- OBJ-002 "database-architect informal schema review", section 5).
--
-- *** DO NOT deploy this job before migration 0004 (refresh_sessions FK
-- ON DELETE fix) has landed. *** Without it, deleting a row still pointed at by
-- a newer row's `replaced_by` column raises a foreign-key violation
-- (refresh_sessions_replaced_by_fkey, current default is NO ACTION/RESTRICT).
-- See obj-006-migration-plan.md migration 0004 for the ALTER TABLE that adds
-- `ON DELETE SET NULL` on replaced_by (and `ON DELETE CASCADE` on user_id).
--
-- Retention floor: >= REFRESH_TOKEN_EXPIRE_DAYS (currently 7, see .env.example).
-- This is NOT a short window like rate_limit_hits's. Revoked/expired rows here
-- are load-bearing evidence for reuse-detection (see app/api/v1/endpoints/auth.py
-- /auth/refresh's family-revoke branch): if a stolen, already-rotated refresh
-- token is replayed, detecting that requires the old revoked row to still
-- exist. Deleting it too early silently downgrades "revoke the whole
-- compromised family" to "reject this one token, leave the rest of the family
-- valid" -- a real security regression, not just a UX one.
--
-- IMPORTANT: the `interval '7 days'` literal below MUST be kept in sync with
-- Settings.REFRESH_TOKEN_EXPIRE_DAYS (app/core/config.py) by whoever deploys
-- this job. This hardcoded-literal risk is exactly why
-- obj-006-migration-plan.md recommends an app-level scheduler (which can read
-- settings.REFRESH_TOKEN_EXPIRE_DAYS directly and never drift) over pg_cron
-- (which cannot see app config at all) -- see that doc's "Cleanup job
-- scheduling mechanism" section for the full tradeoff. If pg_cron is chosen
-- anyway, this literal must be updated by hand whenever
-- REFRESH_TOKEN_EXPIRE_DAYS changes.

DELETE FROM refresh_sessions
WHERE (revoked_at IS NOT NULL AND revoked_at < now() - interval '7 days')
   OR (revoked_at IS NULL AND expires_at < now() - interval '7 days');
