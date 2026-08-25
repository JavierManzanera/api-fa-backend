#!/usr/bin/env bash
# CI role-separation smoke test (OBJ-006, devops-engineer, 2026-08-25).
#
# Run AFTER scripts/ci/role_separation_bootstrap.sql and
# `alembic upgrade 0007_grant_dml_role_privileges` (as fa_migrator) have
# already provisioned the roles + migrated schema. Asserts the actual
# security property finding #14 exists for: fa_app (the role the running
# app connects as) can do ordinary DML, and genuinely cannot escalate to
# schema-modifying access, even if it tries.
#
# Exits non-zero (and prints which check failed) the moment any assertion
# is violated -- this is a real regression check, not just documentation.
set -euo pipefail

PGHOST="${PGHOST:-localhost}"
PGPORT="${PGPORT:-5433}"
PGDATABASE="${PGDATABASE:-api_fa_test}"

psql_as_fa_app() {
  PGPASSWORD="ci_app_pw" psql -h "$PGHOST" -p "$PGPORT" -U fa_app -d "$PGDATABASE" -v ON_ERROR_STOP=1 -c "$1"
}

echo "[1/4] fa_app SELECT on all 4 tables must succeed..."
psql_as_fa_app "SELECT count(*) FROM users; SELECT count(*) FROM verifications; SELECT count(*) FROM rate_limit_hits; SELECT count(*) FROM refresh_sessions;" \
  || { echo "FAIL: fa_app could not SELECT from one or more of the 4 tables (expected to succeed)"; exit 1; }

echo "[2/4] fa_app INSERT/UPDATE/DELETE on users must succeed..."
psql_as_fa_app "INSERT INTO users (id, email, hashed_password, is_active, is_verified, token_version) VALUES (gen_random_uuid(), 'ci-role-check@example.com', 'x', true, true, 0); UPDATE users SET is_active=false WHERE email='ci-role-check@example.com'; DELETE FROM users WHERE email='ci-role-check@example.com';" \
  || { echo "FAIL: fa_app could not INSERT/UPDATE/DELETE on users (expected to succeed)"; exit 1; }

echo "[3/4] fa_app CREATE TABLE must FAIL..."
if psql_as_fa_app "CREATE TABLE ci_should_not_exist (id int);" >/tmp/role_check_create.log 2>&1; then
  echo "FAIL: fa_app was able to CREATE TABLE -- role separation is NOT enforced"
  cat /tmp/role_check_create.log
  exit 1
fi

echo "[4/4] fa_app ALTER TABLE must FAIL..."
if psql_as_fa_app "ALTER TABLE users ADD COLUMN ci_should_not_exist int;" >/tmp/role_check_alter.log 2>&1; then
  echo "FAIL: fa_app was able to ALTER TABLE -- role separation is NOT enforced"
  cat /tmp/role_check_alter.log
  exit 1
fi

echo "All role-separation checks passed: fa_app has DML, no DDL."
