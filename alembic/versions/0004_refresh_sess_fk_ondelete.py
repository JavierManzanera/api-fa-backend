"""refresh_sessions_fk_on_delete

Revision ID: 0004_refresh_sess_fk_ondelete
Revises: 0003_refresh_sess_composite_idx
Create Date: 2026-08-23

OBJ-006 (database-architect), backlog item #5, sourced from the OBJ-002
Gate 3 database-architect review (.ai-context/dependency_graph.md).

**Hard prerequisite for the `refresh_sessions` cleanup job**
(docs/database/sql/cleanup_refresh_sessions.sql) -- do NOT schedule that
job before this migration lands, or a purge will intermittently fail with
an FK violation once a rotation chain is long enough that a purge-eligible
row is still pointed at by a newer row's `replaced_by`.

- `user_id` -> `ON DELETE CASCADE`: if a future "delete account" endpoint
  is ever added, session rows for a deleted user should go with it (no
  orphaned rows referencing a nonexistent user).
- `replaced_by` -> `ON DELETE SET NULL`: a purge job must be able to
  delete an old row even if a newer row still points back at it via this
  self-FK -- `replaced_by` is audit-trail-only (the reuse-detection state
  machine only needs `family_id`/`revoked_at`), never required for
  correctness.

Constraint names (`refresh_sessions_user_id_fkey`,
`refresh_sessions_replaced_by_fkey`) match the explicit names given in
migration 0001's `create_table` call, so this migration does not depend on
guessing Postgres's default unnamed-constraint naming convention.

Risk: Low-Medium (constraint semantics change, no data rewritten). Fully
reversible -- downgrade restores the original NO ACTION behavior.
"""
from typing import Sequence, Union

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0004_refresh_sess_fk_ondelete"
down_revision: Union[str, None] = "0003_refresh_sess_composite_idx"
branch_labels: Union[str, None] = None
depends_on: Union[str, None] = None


def upgrade() -> None:
    op.drop_constraint(
        "refresh_sessions_user_id_fkey", "refresh_sessions", type_="foreignkey"
    )
    op.create_foreign_key(
        "refresh_sessions_user_id_fkey",
        "refresh_sessions",
        "users",
        ["user_id"],
        ["id"],
        ondelete="CASCADE",
    )

    op.drop_constraint(
        "refresh_sessions_replaced_by_fkey", "refresh_sessions", type_="foreignkey"
    )
    op.create_foreign_key(
        "refresh_sessions_replaced_by_fkey",
        "refresh_sessions",
        "refresh_sessions",
        ["replaced_by"],
        ["id"],
        ondelete="SET NULL",
    )


def downgrade() -> None:
    op.drop_constraint(
        "refresh_sessions_replaced_by_fkey", "refresh_sessions", type_="foreignkey"
    )
    op.create_foreign_key(
        "refresh_sessions_replaced_by_fkey",
        "refresh_sessions",
        "refresh_sessions",
        ["replaced_by"],
        ["id"],
    )

    op.drop_constraint(
        "refresh_sessions_user_id_fkey", "refresh_sessions", type_="foreignkey"
    )
    op.create_foreign_key(
        "refresh_sessions_user_id_fkey",
        "refresh_sessions",
        "users",
        ["user_id"],
        ["id"],
    )
