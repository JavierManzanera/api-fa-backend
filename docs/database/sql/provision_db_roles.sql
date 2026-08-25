-- OBJ-006: DDL/DML role separation (audit-report.md finding #14).
-- Illustrative provisioning script -- NOT wired into Alembic, NOT run
-- automatically by any code path yet. See obj-006-migration-plan.md
-- "DDL vs. DML role separation" for the full design and the local-dev-vs-
-- real-deployment split.
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
-- Grants (as opposed to role creation) for the existing 4 tables are instead
-- proposed as a real Alembic migration (0007 in obj-006-migration-plan.md,
-- not authored yet -- Phase 1 design only) so future migrations that add new
-- tables can extend them automatically via ALTER DEFAULT PRIVILEGES below.

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

-- --- DML grants on the 4 existing tables (superseded by migration 0007 once
--     that lands -- kept here too so this script is usable standalone against
--     an environment that hasn't run Alembic migrations yet, e.g. a fresh
--     baseline-only cutover). ---
GRANT SELECT, INSERT, UPDATE, DELETE ON users, verifications, rate_limit_hits, refresh_sessions TO fa_app;

-- Future-proofing: any table fa_migrator creates from here on automatically
-- grants DML to fa_app, so migration authors never have to remember a manual
-- GRANT step per new table.
ALTER DEFAULT PRIVILEGES FOR ROLE fa_migrator IN SCHEMA public
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO fa_app;

-- fa_app must NOT be able to alter/drop the tables it operates on. No
-- explicit REVOKE needed here beyond what's already true by default: DML
-- grants above never included ALTER/DROP/TRUNCATE/REFERENCES/TRIGGER, and
-- fa_app was never made the owner of any table (fa_migrator is, implicitly,
-- as the role that CREATEs them) -- ownership is what would grant those
-- rights implicitly, and fa_app has none.
