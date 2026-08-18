-- 0.6.0 P2.2 (WI-293): `principal_keys` becomes a projection of signed trust-log
-- events. TRUST-DOMAIN.md §5.9, as amended by RECONCILIATION.md overlay change 3.
--
-- Forward migration only (ARCHITECTURE-0.6.0.md:799 — never rewrite old
-- migrations). Migration number: 045 is claimed by the concurrent P1.4 branch, so
-- this package takes 046. A gap in the sequence is harmless — the runner discovers
-- files and computes `missing = available - applied` (see _migrations.py), so it
-- does not require contiguity — but the gap is deliberate and recorded here rather
-- than left to look like a mistake.
--
-- Provenance semantics:
--
--   source_event_hash NOT NULL      => post-cutover row, projected from the signed
--                                      trust-log enrolment/rotation event named here
--   source_event_hash NULL          => pre-cutover row, reported `legacy_unsourced`
--
-- The columns are deliberately NULLABLE at the database level. The contract says
-- `source_event_hash` and `acceptance_event_hash` "become NOT NULL for every row
-- created after cutover; pre-cutover rows keep NULL and are reported
-- legacy_unsourced" — which is a *row-vintage* rule, not a table-wide constraint. A
-- table-wide NOT NULL would be unenforceable without either rewriting or deleting
-- the legacy rows, and deleting them is precisely the defect §5.9 names ("a rebuild
-- that empties them is a defect, and one that invents them is worse"). The
-- post-cutover requirement is enforced in code, where the appliers refuse to write
-- a row without a source event
-- (_principal_keys._require_source_event_hash -> PRINCIPAL_KEYS_PROJECTION_WRITE_REFUSED),
-- and audited by `regista doctor`'s trust:projection_consistent:<project> check.

ALTER TABLE principal_keys
    ADD COLUMN IF NOT EXISTS trust_domain_id uuid;

-- The trust-log enrolment/rotation event this row projects.
ALTER TABLE principal_keys
    ADD COLUMN IF NOT EXISTS source_event_hash text;

-- The project-local `principal_key_accepted` event (§5.8). Populated by P1.7's
-- acceptance path; NULL here means "no acceptance recorded yet", never "accepted".
ALTER TABLE principal_keys
    ADD COLUMN IF NOT EXISTS acceptance_event_hash text;

ALTER TABLE principal_keys
    ADD COLUMN IF NOT EXISTS projection_version int NOT NULL DEFAULT 1;

-- A rebuild resolves rows by (principal_id, source_event_hash); the partial index
-- keeps that lookup cheap without indexing the legacy NULL rows.
CREATE INDEX IF NOT EXISTS ix_principal_keys_source_event
    ON principal_keys (source_event_hash)
    WHERE source_event_hash IS NOT NULL;

-- Two rows may never claim the same source event for the same principal: the
-- projection is a function of the event log, so a second row from one event means
-- the projection diverged from its source.
CREATE UNIQUE INDEX IF NOT EXISTS uq_principal_keys_source_event
    ON principal_keys (principal_id, source_event_hash)
    WHERE source_event_hash IS NOT NULL;

COMMENT ON COLUMN principal_keys.source_event_hash IS
    'Trust-log principal_key_enrolled/_rotated event this row projects (TRUST-DOMAIN.md '
    'section 5.9). NULL => pre-cutover row, reported legacy_unsourced, never lifecycle '
    'evidence. Never overwritten by a revocation: revocation flips status, it does not '
    'change which event introduced the key.';

COMMENT ON COLUMN principal_keys.acceptance_event_hash IS
    'Project-local principal_key_accepted event (TRUST-DOMAIN.md section 5.8). NULL means '
    'no acceptance is recorded, never that the key is accepted.';

COMMENT ON TABLE principal_keys IS
    'PROJECTION of signed trust-log lifecycle events, not an authority. No verifier '
    'resolves a key from this table for a v6 event (TRUST-DOMAIN.md section 5.9 rule 1); '
    'doing so is the S6 defect. Retained for v4/v5 legacy verification, where using it '
    'forces applicability = LEGACY_PARTIAL. Rebuildable with '
    '`regista trust rebuild-projection --project <p>`.';
