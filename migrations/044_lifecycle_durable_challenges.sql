-- Plan 031: durable challenge consumption + typed approval evidence.
--
-- Two changes the durable lifecycle needs to consume challenges across
-- processes/restarts and to reason about approval evidence by kind rather
-- than by a free-form string:
--
-- 1. lifecycle_challenges.kind binds a challenge to its protocol domain
--    ('possession' or 'effective'). A possession proof can never consume an
--    effective challenge and vice versa, even though both share one table.
--    Existing rows default to 'possession'. An effective challenge created
--    before this migration is rejected after upgrade and must be reissued;
--    challenges expire after five minutes, so no durable operation is lost.
-- 2. lifecycle_approvals.evidence_verified records whether a registered
--    approval verifier actually validated the step-up evidence. NULL means no
--    verifier was configured (evidence accepted on consumer trust, the
--    historical behavior); true/false is the verifier's verdict.

ALTER TABLE lifecycle_challenges
    ADD COLUMN IF NOT EXISTS kind TEXT NOT NULL DEFAULT 'possession';

ALTER TABLE lifecycle_challenges
    DROP CONSTRAINT IF EXISTS chk_lifecycle_challenge_kind;
ALTER TABLE lifecycle_challenges
    ADD CONSTRAINT chk_lifecycle_challenge_kind CHECK (
        kind IN ('possession', 'effective')
    );

ALTER TABLE lifecycle_approvals
    ADD COLUMN IF NOT EXISTS evidence_verified BOOLEAN;
