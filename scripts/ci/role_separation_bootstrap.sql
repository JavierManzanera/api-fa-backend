-- CI-only role bootstrap (OBJ-006, devops-engineer, 2026-08-25).
--
-- This is a NARROWER subset of docs/database/sql/provision_db_roles.sql
-- (database-architect's owned artifact -- the real operator script for
-- staging/production) -- it exists here, separately, because
-- provision_db_roles.sql's later block (GRANT SELECT/INSERT/UPDATE/DELETE
-- ON users, verifications, rate_limit_hits, refresh_sessions TO fa_app +
-- ALTER DEFAULT PRIVILEGES) assumes those 4 tables already exist. That
-- holds for the scenario that script documents itself as covering ("a
-- fresh baseline-only cutover" -- i.e. a database that already has the
-- tables via Base.metadata.create_all, being cut over to Alembic) but NOT
-- for a genuinely empty database, which is what every CI run starts from.
--
-- So CI only runs the role-creation + cluster/schema-level grant
-- statements here (mirrors provision_db_roles.sql lines 22-38 exactly,
-- values changed from psql variables to literals since this only ever
-- runs against a throwaway CI Postgres, never a real credential). Table
-- creation + the DML grant to fa_app are then supplied by
-- `alembic upgrade 0007_grant_dml_role_privileges`, run immediately after
-- this script as fa_migrator -- see .github/workflows/ci.yml's
-- role-separation-smoke-test job.
--
-- NOTE for whoever eventually does a real staging/production cutover: this
-- same empty-database chicken-and-egg gap likely applies there too if the
-- target environment has never run create_all (a genuinely greenfield
-- deploy, not a cutover from an existing dev/test create_all'd database).
-- Flagged as a real gap in provision_db_roles.sql's documented scope, not
-- silently worked around there -- see this file's sibling note in
-- docs/database/obj-006-migration-plan.md's devops-engineer addendum.
CREATE ROLE fa_migrator LOGIN PASSWORD 'ci_migrator_pw';
CREATE ROLE fa_app LOGIN PASSWORD 'ci_app_pw';

GRANT CREATE, CONNECT ON DATABASE api_fa_test TO fa_migrator;
GRANT CREATE ON SCHEMA public TO fa_migrator;

REVOKE CREATE ON SCHEMA public FROM PUBLIC;
GRANT CONNECT ON DATABASE api_fa_test TO fa_app;
GRANT USAGE ON SCHEMA public TO fa_app;
