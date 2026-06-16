-- AP-012 / Plan 006: signed global hash chain across all events.
--
-- global_seq (migration 017) is declared CACHE 100, so under a connection pool
-- it is non-contiguous by design: it gives a total order, not a gapless count.
-- The per-work-item prev_event_hash (migration 017 era) cannot detect deletion
-- of a whole work item or truncation of the genesis prefix across work items.
--
-- This adds a global hash chain: every event binds prev_global_event_hash =
-- sha256(prev.canonical_envelope || prev.signature) of the immediately
-- preceding event in append order, into its signed envelope. Completeness
-- becomes a hash walk that is immune to global_seq gaps.

ALTER TABLE events ADD COLUMN prev_global_event_hash BYTEA;

-- events_archive mirrors events (see migration 027) — keep the columns aligned.
ALTER TABLE events_archive ADD COLUMN prev_global_event_hash BYTEA;

-- Single-row head pointer, serialised via SELECT ... FOR UPDATE so concurrent
-- appends across work items chain onto one line (no forks). head_hash is
-- sha256(head.canonical_envelope || head.signature) — the value the next
-- appended event chains from.
CREATE TABLE event_chain_head (
    id            BOOLEAN PRIMARY KEY DEFAULT TRUE,
    head_hash     BYTEA NOT NULL,
    head_event_id UUID  NOT NULL,
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT event_chain_head_singleton CHECK (id)
);
