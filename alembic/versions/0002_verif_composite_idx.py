"""verifications_composite_index

Revision ID: 0002_verif_composite_idx
Revises: 0001_baseline_current_schema
Create Date: 2026-08-23

OBJ-006 (database-architect), backlog item #1, sourced from the OBJ-001
Gate 3 database-architect review (.ai-context/dependency_graph.md).

`_check_and_consume_otp` (app/api/v1/endpoints/auth.py) filters on
`email == X AND purpose == Y AND expires_at > now()` -- `code` is compared
in Python after fetch, not in the SQL WHERE clause. Today there is only a
single-column index on `email`; locked-out/expired `Verification` rows are
kept (not deleted -- see OBJ-001 Phase 3 design notes), so a single email
can accumulate many dead rows across `reset_password`/`verify_email`
purposes over time. A composite index matching the actual query shape
avoids that in-memory-filter degradation. Leftmost-prefix means any query
that only filters on `email` keeps working, so the single-column index is
redundant once this lands, not just superseded.

Low risk, trivially reversible.
"""
from typing import Sequence, Union

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0002_verif_composite_idx"
down_revision: Union[str, None] = "0001_baseline_current_schema"
branch_labels: Union[str, None] = None
depends_on: Union[str, None] = None


def upgrade() -> None:
    op.drop_index("ix_verifications_email", table_name="verifications")
    op.create_index(
        "ix_verifications_email_purpose_expires_at",
        "verifications",
        ["email", "purpose", "expires_at"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(
        "ix_verifications_email_purpose_expires_at", table_name="verifications"
    )
    op.create_index(
        "ix_verifications_email", "verifications", ["email"], unique=False
    )
