"""timestamp_default_convergence

Revision ID: 0005_timestamp_default_conv
Revises: 0004_refresh_sess_fk_ondelete
Create Date: 2026-08-23

OBJ-006 (database-architect), backlog item #7 (OPTIONAL -- Gate 1 flagged
this as low-stakes/droppable, but the user's Gate 1 approval kept it in
the sequence), sourced from the OBJ-002 Gate 3 database-architect review.

Three different precedents currently exist for how a table gets its
`created_at`/`issued_at`:
- `Verification.created_at`: Python-side default AND `server_default=
  func.now()` (belt and suspenders).
- `RateLimitHit.created_at`: neither -- always caller-supplied.
- `RefreshSession.issued_at`: Python-side default only, no server_default.

Converges the other two onto `Verification`'s pattern (the most defensive
of the three -- protects against ORM-bypassing direct-SQL inserts, and
every real construction site already goes through the ORM, so this is a
pure safety net, never actually exercised by current code paths: no
direct-SQL insert exists anywhere in app/).

Purely additive -- does not touch any existing row's data, does not change
any Python-side behavior (an explicit value passed by the ORM always takes
precedence over a column default). Low risk, reversible.
"""
from typing import Sequence, Union

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0005_timestamp_default_conv"
down_revision: Union[str, None] = "0004_refresh_sess_fk_ondelete"
branch_labels: Union[str, None] = None
depends_on: Union[str, None] = None


def upgrade() -> None:
    op.execute("ALTER TABLE rate_limit_hits ALTER COLUMN created_at SET DEFAULT now()")
    op.execute("ALTER TABLE refresh_sessions ALTER COLUMN issued_at SET DEFAULT now()")


def downgrade() -> None:
    op.execute("ALTER TABLE refresh_sessions ALTER COLUMN issued_at DROP DEFAULT")
    op.execute("ALTER TABLE rate_limit_hits ALTER COLUMN created_at DROP DEFAULT")
