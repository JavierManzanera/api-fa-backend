"""refresh_sessions_partial_unique_active_family

Revision ID: 0008_refresh_sess_partial_uniq
Revises: 0007_grant_dml_role_privileges
Create Date: 2026-08-23

OBJ-006 (database-architect), the "optional partial-unique-index defense"
surfaced (not in the original backlog) during Phase 1 design -- see
docs/database/obj-006-migration-plan.md section 5 / Gate-1 open question
#7. Included in this migration sequence per the user's explicit Gate 1
inclusion decision (.ai-context/dependency_graph.md OBJ-006 row: "Gate 1
now APPROVED -- all 7 decisions locked").

    CREATE UNIQUE INDEX ux_refresh_sessions_family_id_active
        ON refresh_sessions (family_id) WHERE revoked_at IS NULL;

Intent: at most one active (`revoked_at IS NULL`) row may exist per
`family_id` at any time. Turns the rotation-path TOCTOU gap already
flagged at OBJ-001/OBJ-002 Gate 3 (`_check_and_consume_otp`/
`enforce_rate_limit`/`/auth/refresh`'s unlocked read-then-write races --
see obj-006-migration-plan.md section 5) from a silent "two valid
children" failure into a loud constraint-violation failure for this one
table, as defense-in-depth alongside (not instead of) the app-code locking
fix that same section already flags as `developer` territory.

*** CRITICAL FINDING FROM THIS AUTHORSHIP PASS'S OWN VERIFICATION -- READ
BEFORE APPLYING TO ANY DATABASE BACKING THE CURRENT APP CODE ***

This migration is INCOMPATIBLE with the CURRENT `/auth/refresh` rotation
implementation as of OBJ-002 (app/api/v1/endpoints/auth.py, the
`_issue_tokens_and_session` + inline revoke block around line ~390-403).
That handler, in order, within a single transaction:
  1. INSERTs the new `refresh_sessions` row (new jti, SAME family_id,
     `revoked_at` = NULL) and flushes it.
  2. THEN sets the OLD row's `revoked_at = now()` and `replaced_by =
     new_jti`, and commits.

Between steps 1 and 2, TWO rows with the same `family_id` and
`revoked_at IS NULL` are simultaneously visible within that same
transaction -- Postgres unique-index enforcement checks against the
transaction's own already-flushed rows, so step 1's INSERT itself raises
`duplicate key value violates unique constraint
"ux_refresh_sessions_family_id_active"` and aborts the rotation. This is
NOT a concurrency edge case -- it reproduces on every single-threaded
rotation, deterministically, confirmed by running this project's own
`tests/api/test_refresh_rotation.py` suite (including
`test_reuse_detected_revokes_entire_token_family`) against a database
migrated through 0008. See the OBJ-006 database-architect section of
.ai-context/dependency_graph.md for the full verification write-up.

This migration is still authored and included in the sequence per the
Gate-1 decision -- the file exists and is correct DDL for what it claims
to do -- but it must NOT be deployed against any environment running
today's rotation handler. Required before this is safe to apply:
`developer` must reorder that handler to revoke-then-insert (flush the old
row's `revoked_at`/`replaced_by` update BEFORE inserting the new row,
instead of after), in the same coordinated pass that eventually also does
the app-code TOCTOU locking fix from section 5. Do not run
`alembic upgrade head` (which includes this migration) against a
production or shared dev database until that reorder has landed and been
verified. `devops-engineer`: do not include migration 0008 in any
automated deploy step until this dependency_graph.md flag is cleared by a
developer pass.

Risk: Low as pure DDL; HIGH as an app-compatibility hazard for the reason
above. Reversible.

*** RESOLVED (2026-08-25, OBJ-010) ***
`developer` reordered `/auth/refresh`'s rotation handler to
revoke->insert->link in commit f1758a5 -- see
docs/database/obj-006-migration-plan.md's "FIXED" note under this same
CRITICAL finding for the reproduction/fix detail. `database-architect`
re-verified independently (OBJ-010, same date): fresh `alembic upgrade
head` applies cleanly and the full test suite passes (281 passed) against
a head-migrated schema. CI's schema-drift job is unpinned from 0007 to
head accordingly (`.github/workflows/ci.yml`). This migration is now safe
to deploy anywhere running the current rotation handler; the warning above
is left in place as the historical record of why it was blocked, not as a
live restriction.
"""
from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0008_refresh_sess_partial_uniq"
down_revision: Union[str, None] = "0007_grant_dml_role_privileges"
branch_labels: Union[str, None] = None
depends_on: Union[str, None] = None


def upgrade() -> None:
    op.create_index(
        "ux_refresh_sessions_family_id_active",
        "refresh_sessions",
        ["family_id"],
        unique=True,
        postgresql_where=sa.text("revoked_at IS NULL"),
    )


def downgrade() -> None:
    op.drop_index(
        "ux_refresh_sessions_family_id_active",
        table_name="refresh_sessions",
        postgresql_where=sa.text("revoked_at IS NULL"),
    )
