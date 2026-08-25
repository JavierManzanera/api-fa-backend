"""grant_dml_role_privileges

Revision ID: 0007_grant_dml_role_privileges
Revises: 0006_rate_limit_hit_ip_inet
Create Date: 2026-08-23

OBJ-006 (database-architect), part of finding #14 (DDL/DML role
separation, docs/security/audit-report.md lines 130-134). Full role design
in docs/database/obj-006-migration-plan.md section 3.

Depends on `fa_migrator`/`fa_app` roles already existing in the target
environment, provisioned ONCE, OUTSIDE Alembic, by an operator running
docs/database/sql/provision_db_roles.sql (role *creation* is
cluster-level, typically needs superuser, and must never have a real
password committed to a migration file tracked in git -- see that script's
own header). This migration only issues GRANTs, assuming the roles exist.

**Local/test environments deliberately do not have these roles** (see
obj-006-migration-plan.md section 3, "Local dev/test -- keep the existing
pattern, don't force separation" -- role separation adds real friction to
the single-developer/ephemeral-DB dev loop for no real security benefit
there). Since `alembic upgrade head` must keep working unmodified in that
environment (this project's established throwaway-Postgres/
docker-compose.test.yml pattern), this migration checks for the roles'
existence first and no-ops (with a printed notice, not a silent skip) if
either is missing, rather than failing the whole upgrade chain. This is a
database-architect implementation decision made during this authorship
pass, on top of the original design doc, which had not fully worked out
this ordering interaction -- flagged explicitly here and in the OBJ-006
dependency_graph.md section for `devops-engineer`.

Keeping this as a real migration (rather than only in the standalone
provisioning script) means the grant state is versioned/auditable
alongside the schema itself, and automatically re-applies if an
environment's database is ever rebuilt from migration history. Must run
under `fa_migrator` (or another role with GRANT rights on these tables) --
will fail if run under `fa_app` itself, which is the intended fail-safe
(the DML role can never grant itself more than it already has).

Risk: Low (grants only, no schema/data change). Reversible.
"""
from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0007_grant_dml_role_privileges"
down_revision: Union[str, None] = "0006_rate_limit_hit_ip_inet"
branch_labels: Union[str, None] = None
depends_on: Union[str, None] = None

_ROLES = ("fa_app", "fa_migrator")


def _role_exists(bind, role_name: str) -> bool:
    return (
        bind.execute(
            sa.text("SELECT 1 FROM pg_roles WHERE rolname = :role"), {"role": role_name}
        ).first()
        is not None
    )


def upgrade() -> None:
    bind = op.get_bind()
    if any(not _role_exists(bind, role) for role in _ROLES):
        print(
            "[0007_grant_dml_role_privileges] fa_app/fa_migrator roles not "
            "found in this database -- skipping GRANT statements. Expected "
            "in local/test environments per obj-006-migration-plan.md "
            "section 3, which deliberately does not require role "
            "separation there. To exercise role separation, run "
            "docs/database/sql/provision_db_roles.sql first, then re-run "
            "`alembic upgrade head` (or just this migration via "
            "`alembic upgrade 0007_grant_dml_role_privileges`)."
        )
        return

    op.execute(
        "GRANT SELECT, INSERT, UPDATE, DELETE "
        "ON users, verifications, rate_limit_hits, refresh_sessions "
        "TO fa_app"
    )
    op.execute(
        "ALTER DEFAULT PRIVILEGES FOR ROLE fa_migrator IN SCHEMA public "
        "GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO fa_app"
    )


def downgrade() -> None:
    bind = op.get_bind()
    if any(not _role_exists(bind, role) for role in _ROLES):
        return

    op.execute(
        "ALTER DEFAULT PRIVILEGES FOR ROLE fa_migrator IN SCHEMA public "
        "REVOKE SELECT, INSERT, UPDATE, DELETE ON TABLES FROM fa_app"
    )
    op.execute(
        "REVOKE SELECT, INSERT, UPDATE, DELETE "
        "ON users, verifications, rate_limit_hits, refresh_sessions "
        "FROM fa_app"
    )
