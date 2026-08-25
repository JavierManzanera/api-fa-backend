"""rate_limit_hits_email_created_at_ip_idx

Revision ID: 0009_rl_email_created_at_idx
Revises: 0008_refresh_sess_partial_uniq
Create Date: 2026-08-25

database-architect follow-up for OBJ-014 (docs/api/obj-014-design-notes.md
section 4), originally flagged one objective earlier by OBJ-013
(docs/api/obj-013-design-notes.md section 4) and never applied until now.
Full before/after EXPLAIN ANALYZE verification and the reasoning below are
also recorded in docs/database/obj-006-migration-plan.md (OBJ-014 section,
appended by this pass) -- this docstring is the condensed version.

WHAT THIS ADDS

    CREATE INDEX ix_rate_limit_hits_scope_email_created_at_ip
        ON rate_limit_hits (scope, email, created_at, ip);

Nothing else changes. The existing `ix_rate_limit_hits_scope_ip_email_
created_at (scope, ip, email, created_at)` index (migration 0001) is left
exactly as-is -- not dropped, not modified. See "why not a single widened
index" below for why this is two indexes, not one merged 4-column index.

WHY: TWO QUERY SHAPES NEEDED, ONE WAS ALREADY SERVED

`enforce_rate_limit` (app/core/rate_limit.py) runs, per request:

  1. IP-only COUNT: scope=?, ip=?, created_at > window_start (no email
     predicate) -- unchanged since OBJ-013.
  2. Email-only COUNT: scope=?, email=?, created_at > window_start (no ip
     predicate) -- this is the HOT path, runs on literally every request
     to every one of the 6 rate-limited endpoints.
  3. NEW (OBJ-014, narrow-band only -- only runs when the email tally is
     already in the last `RATE_LIMIT_EMAIL_RESERVED_SLOTS` hits before
     `limit`): EXISTS check, scope=?, email=?, ip=?, created_at >
     window_start -- all three of scope/email/ip are equality predicates.

The existing index (scope, ip, email, created_at) already serves shape 1
optimally (its own leading two columns) AND, verified empirically, also
already serves shape 3 optimally: EXPLAIN ANALYZE against a seeded 220k+
row table showed Postgres using this exact index for the new EXISTS query
at cost 4.45 / 3-4 buffer hits, because scope/ip/email are ALL
equality-constrained in that query -- Postgres's planner matches an
equality-only prefix regardless of the literal declared column order
(scope, ip, email is functionally interchangeable with scope, email, ip
when every one of those three predicates is `=`, not a range). No new
index was needed for shape 3 at all.

Shape 2 (the actual hot path) is NOT served by the existing index: `ip` is
unconstrained in that query but sits between the two constrained columns
and `created_at`, which breaks the index's ability to use `created_at` as
a contiguous range boundary -- Postgres has to visit every `ip` subgroup
under (scope, email) and filter `created_at` per-row (cheap per row since
it's index-only, but the row COUNT visited is unbounded by the time
window). Confirmed empirically: 365 buffer hits / cost ~1981 for a
freshly-attacked email (9 rows) against ~200k background rows, and cost
237 even for a moderate 20k-row single-email history -- versus cost 4-13 /
3-4 buffer hits once this migration's new index is in place. This is the
query that runs on every single request, so this is the one that actually
needed a new index.

WHY THE NEW INDEX'S COLUMN ORDER IS (scope, email, created_at, ip), NOT
(scope, email, ip, created_at) AS obj-014-design-notes.md SECTION 4
SUGGESTED

The design doc's own suggested order relocates the exact same structural
problem the current index has for shape 2 -- from "ip before email"
(current index) to "ip before created_at, after email" (design doc's
suggestion) -- it narrows the scan to one email's rows first, which does
help, but STILL forces a scan across every ip subgroup within that email
before created_at can filter, instead of using created_at as a genuine
b-tree range boundary. Verified by seeding one email with ~20k rows spread
across 200 distinct IPs over a 2-hour span (most outside the 60s window)
and comparing the two orderings head-to-head against the identical query:
(scope, email, ip, created_at) -- cost 237.50, 147 buffer accesses.
(scope, email, created_at, ip) -- cost 12.90, 138 buffer accesses (mostly
    planning-time catalog lookups; ~10x cheaper at execution).
Both orderings serve the EXISTS check (shape 3) identically well (cost
4.45 either way) since ip is a pure equality predicate in that query
regardless of which side of `created_at` it sits on -- trailing it after
`created_at` costs shape 3 nothing (Postgres still uses the index-only
covering column to filter without a heap fetch), while leading it before
`created_at` actively costs shape 2 an order of magnitude. `ip` is kept as
a trailing column (not dropped from the index) so this index can also
serve as an index-only-scan source for a future `COUNT(DISTINCT ip)`
"distinct_ip_count_for_email" observability query if `developer` implements
obj-014-design-notes.md section 2.7 (currently a `developer`-side choice
whether to fold that into the existing EXISTS query or issue it
separately) -- costs nothing extra for shape 2's own performance.

WHY NOT A SINGLE WIDENED INDEX INSTEAD OF TWO

The design doc's §4 preferred widening the existing index in place, over
adding a second, narrower one, IF the existing OBJ-013 recommendation had
already been applied by the time this migration landed -- it had not
(confirmed: no such index exists as of migration 0008/head). With no
prior narrower index to widen, and given the empirical finding above that
`ip` needs to sit on the OPPOSITE side of `created_at` from where the
existing index already puts it relative to `email` to serve shape 2 well,
a single 4-column index cannot simultaneously be `(scope, ip, email,
created_at)`-shaped (best for shape 1) and `(scope, email, created_at,
ip)`-shaped (best for shape 2) -- these orderings serve different leading
equality columns. Two indexes, each matching one hot-or-cold query shape,
is the correct call here, not a stacking anti-pattern: shape 3 (the only
query that could have justified widening) turned out to already be served
by the first index for free.

ROLLBACK: plain `DROP INDEX`, no data risk -- this migration adds
nothing but an index.
"""
from typing import Sequence, Union

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0009_rl_email_created_at_idx"
down_revision: Union[str, None] = "0008_refresh_sess_partial_uniq"
branch_labels: Union[str, None] = None
depends_on: Union[str, None] = None


def upgrade() -> None:
    op.create_index(
        "ix_rate_limit_hits_scope_email_created_at_ip",
        "rate_limit_hits",
        ["scope", "email", "created_at", "ip"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(
        "ix_rate_limit_hits_scope_email_created_at_ip",
        table_name="rate_limit_hits",
    )
