"""refresh_sessions_composite_index

Revision ID: 0003_refresh_sess_composite_idx
Revises: 0002_verif_composite_idx
Create Date: 2026-08-23

OBJ-006 (database-architect), backlog item #4, sourced from the OBJ-002
Gate 3 database-architect review (.ai-context/dependency_graph.md).

Upgrades the single-column `family_id` index to a composite
`(family_id, revoked_at)`, matching the family-wide bulk-revoke query used
by reuse detection (`_revoke_active_sessions`, app/api/v1/endpoints/
auth.py): `UPDATE ... WHERE revoked_at IS NULL AND family_id = :fid`.
Lower priority than 0002 in practice (today's rotation chains are short
enough that the single-column index is a non-issue), but cheap and correct
to land while this migration sequence is already touching the table for
0004.

Low risk, trivially reversible.
"""
from typing import Sequence, Union

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0003_refresh_sess_composite_idx"
down_revision: Union[str, None] = "0002_verif_composite_idx"
branch_labels: Union[str, None] = None
depends_on: Union[str, None] = None


def upgrade() -> None:
    op.drop_index("ix_refresh_sessions_family_id", table_name="refresh_sessions")
    op.create_index(
        "ix_refresh_sessions_family_id_revoked_at",
        "refresh_sessions",
        ["family_id", "revoked_at"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(
        "ix_refresh_sessions_family_id_revoked_at", table_name="refresh_sessions"
    )
    op.create_index(
        "ix_refresh_sessions_family_id", "refresh_sessions", ["family_id"], unique=False
    )
