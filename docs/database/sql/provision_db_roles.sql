-- OBJ-006: DDL/DML role separation (audit-report.md finding #14).
-- Provisioning script -- NOT wired into Alembic, NOT run automatically by
-- any code path yet. See obj-006-migration-plan.md "DDL vs. DML role
-- separation" for the full design and the local-dev-vs-real-deployment
-- split.
--
-- Deliberately kept OUT of Alembic's migration history: CREATE ROLE is a
-- cluster-level (not database-level) operation, typically requires
-- superuser, and -- more importantly -- a real deployment's passwords must
-- never be literal strings committed to a migration file tracked in git.
-- This script uses psql variables (`:'migrator_password'`) that must be
-- supplied at run time (`psql -v migrator_password=... -v app_password=...`)
-- from a secrets manager, never hardcoded. Run ONCE per environment by an
-- operator with superuser/CREATEROLE rights, before the first
-- `alembic upgrade head` against that environment.
--
-- GREENFIELD-SAFE BY DESIGN (fixed 2026-08-25, OBJ-011): this script does
-- role creation + cluster/schema-level grants ONLY -- it does NOT grant DML
-- on the 4 app tables, and does NOT assume those tables already exist.
-- DML grants (SELECT/INSERT/UPDATE/DELETE on users, verifications,
-- rate_limit_hits, refresh_sessions) plus the ALTER DEFAULT PRIVILEGES
-- future-proofing are supplied by Alembic migration
-- `0007_grant_dml_role_privileges`, which runs after this script as part of
-- `alembic upgrade head` and grants once the tables actually exist --
-- whether they got there via this migration chain from empty (a genuine
-- greenfield deploy) or already existed from a prior `create_all` (the
-- baseline-only cutover scenario this script originally documented). Either
-- way, the correct order is:
--   1. psql -v migrator_password=... -v app_password=... -f provision_db_roles.sql
--   2. alembic upgrade head   (or `alembic stamp 0001_baseline_current_schema`
--      first, if cutting over a database that already has the 4 tables from
--      `create_all`, then `alembic upgrade head` from there)
-- This mirrors the pattern already proven in CI's
-- `scripts/ci/role_separation_bootstrap.sql`, which does the identical
-- schema-level-grants-only split for the same reason (a throwaway CI
-- Postgres always starts empty). Previously this script also carried an
-- inline DML-grant block guarded as "for standalone use against an
-- environment that hasn't run Alembic migrations yet" -- that block
-- silently assumed the 4 tables already existed and failed outright
-- (`ERROR: relation "users" does not exist`) against a true greenfield
-- database. Removed as redundant with, and narrower than, what migration
-- 0007 already does correctly for both scenarios -- see
-- obj-006-migration-plan.md's OBJ-011 addendum for verification detail.

-- --- One-time role creation (superuser) ---------------------------------

CREATE ROLE fa_migrator LOGIN PASSWORD :'migrator_password';
CREATE ROLE fa_app LOGIN PASSWORD :'app_password';

-- Migrator: owns/creates the schema. Scope this to the target database only
-- (not GRANT ALL ON DATABASE, which also implies CONNECT/TEMP rights beyond
-- what's needed) -- adjust :'target_db' for the environment.
GRANT CREATE, CONNECT ON DATABASE :"target_db" TO fa_migrator;
GRANT CREATE ON SCHEMA public TO fa_migrator;

-- App role: connect + DML only, no CREATE anywhere. Postgres < 15 grants
-- CREATE on the `public` schema to PUBLIC by default -- explicitly revoke it
-- so fa_app (and every other future role) can't create objects either.
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
GRANT CONNECT ON DATABASE :"target_db" TO fa_app;
GRANT USAGE ON SCHEMA public TO fa_app;

-- --- DML grants + ALTER DEFAULT PRIVILEGES: intentionally NOT here -------
--
-- Supplied by Alembic migration 0007_grant_dml_role_privileges instead,
-- which runs GRANT SELECT, INSERT, UPDATE, DELETE ON users, verifications,
-- rate_limit_hits, refresh_sessions TO fa_app, plus the equivalent
-- ALTER DEFAULT PRIVILEGES FOR ROLE fa_migrator IN SCHEMA public future-
-- proofing for tables created by later migrations. Run `alembic upgrade
-- head` (see header comment above) immediately after this script to apply
-- those grants -- do not duplicate them here, and do not skip that step.
--
-- fa_app must NOT be able to alter/drop the tables it operates on. No
-- explicit REVOKE is needed for that beyond what's already true by
-- default: the DML grants migration 0007 issues never include
-- ALTER/DROP/TRUNCATE/REFERENCES/TRIGGER, and fa_app is never made the
-- owner of any table (fa_migrator is, implicitly, as the role that
-- CREATEs them via Alembic) -- ownership is what would grant those rights
-- implicitly, and fa_app has none.
