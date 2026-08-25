"""rate_limit_hit_ip_to_inet

Revision ID: 0006_rate_limit_hit_ip_inet
Revises: 0005_timestamp_default_conv
Create Date: 2026-08-23

OBJ-006 (database-architect), backlog item #8 (OPTIONAL, HIGHER RISK --
the user explicitly chose to include this and accept the data-cast risk
at Gate 1, see .ai-context/dependency_graph.md OBJ-006 "Phase 1
deliverables" row), sourced from the OBJ-001 Gate 3 database-architect
review.

Casts `rate_limit_hits.ip` from `String` to native Postgres `inet`
(validates IPv4/IPv6 shape at write time, more compact storage). `ip` is
always populated from `request.client.host` (app/core/rate_limit.py), so
this should hold in practice -- but the whole point of this migration
being flagged as the highest-risk one in the sequence is that "should hold
in practice" is not the same as "guaranteed", especially against a
database with real accumulated traffic.

FAILURE PATH (deliberately explicit, not left to a raw Postgres cast
error): before altering the column type, this migration runs the exact
validation query proposed in docs/database/obj-006-migration-plan.md
(migration 0006 section) against every existing row. If ANY row's `ip`
value is not IPv4/IPv6-shaped, the migration raises a RuntimeError with
the offending row count/sample and stops -- no ALTER TABLE is attempted,
no partial state is left behind (the check runs before any DDL in this
migration). Operator remediation, per that error message: either delete
the offending rows (they are rate-limit audit rows already subject to a
1-hour retention policy -- see docs/database/sql/
cleanup_rate_limit_hits.sql) or correct them, then re-run
`alembic upgrade head`. This migration deliberately does NOT auto-delete
or auto-mutate rows itself -- silently discarding rate-limit history is
itself a security-relevant decision that should not happen inside a
schema migration without an operator's explicit say-so.

ROLLBACK: `downgrade()` casts back to `character varying` via
`ip::text`, which is always safe (inet -> text never fails) -- so once
this migration succeeds, reverting it carries none of the forward-cast
risk.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql as pg

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0006_rate_limit_hit_ip_inet"
down_revision: Union[str, None] = "0005_timestamp_default_conv"
branch_labels: Union[str, None] = None
depends_on: Union[str, None] = None

# Same shape check proposed in obj-006-migration-plan.md migration 0006:
# hex digits, colons, dots only -- a coarse IPv4/IPv6 shape gate, not a
# full RFC-compliant parser (Postgres's own `::inet` cast is the real
# authority; this is just to fail loudly and cheaply beforehand instead of
# mid-ALTER).
_VALIDATION_QUERY = "SELECT id, ip FROM rate_limit_hits WHERE ip !~ '^[0-9a-fA-F:.]+$'"


def upgrade() -> None:
    bind = op.get_bind()
    invalid_rows = bind.execute(sa.text(_VALIDATION_QUERY)).fetchall()
    if invalid_rows:
        sample = [(str(r[0]), r[1]) for r in invalid_rows[:5]]
        raise RuntimeError(
            "Migration 0006_rate_limit_hit_ip_inet aborted: "
            f"{len(invalid_rows)} row(s) in rate_limit_hits have an `ip` "
            "value that is not IPv4/IPv6-shaped and would fail the "
            "`ip::inet` cast (Postgres would raise "
            "'invalid input syntax for type inet'). Sample (id, ip): "
            f"{sample}. This is a Gate-1-approved, deliberately accepted "
            "data-cast risk (see docs/database/obj-006-migration-plan.md "
            "section 'Gate-1 open questions' #5) -- it is NOT auto-fixed "
            "here because silently deleting or mutating rate-limit audit "
            "rows is itself a security-relevant decision that belongs to "
            "an operator, not this migration. To proceed: inspect the "
            "offending rows, then either delete them (already subject to "
            "the 1-hour retention policy in "
            "docs/database/sql/cleanup_rate_limit_hits.sql) or correct "
            "them, then re-run `alembic upgrade head`. No schema change "
            "has been made by this aborted attempt -- the ALTER TABLE "
            "below never ran."
        )

    op.alter_column(
        "rate_limit_hits",
        "ip",
        existing_type=sa.String(),
        type_=pg.INET(),
        postgresql_using="ip::inet",
        nullable=False,
    )


def downgrade() -> None:
    op.alter_column(
        "rate_limit_hits",
        "ip",
        existing_type=pg.INET(),
        type_=sa.String(),
        postgresql_using="ip::text",
        nullable=False,
    )
