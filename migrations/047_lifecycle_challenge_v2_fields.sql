-- 0.6.0 P2.2 review fix B1 (WI-293): persist the v2 possession-challenge fields.
--
-- TRUST-DOMAIN.md §5.5 upgrades the possession challenge to v2, which adds
-- `trust_domain_id` and `enrollment_request_digest` to the challenge object. Both
-- are inside the JCS body the proof signs, so a challenge rehydrated from the
-- database MUST carry them or `submit_possession` would verify against different
-- bytes than the client signed — a durable-restart-only failure, which is the worst
-- kind to leave latent.
--
-- Migration number: 045 is claimed by the concurrent P1.4 branch and 046 by this
-- package's projection columns, so this takes 047. The runner discovers files and
-- computes `missing = available - applied`; it does not require contiguity.
--
-- Nullable: challenges issued before this migration have neither value, and a
-- pre-genesis project has no trust domain at all. Null is "not recorded", never
-- "empty string" — the JCS body distinguishes them.

ALTER TABLE lifecycle_challenges
    ADD COLUMN IF NOT EXISTS trust_domain_id uuid;

ALTER TABLE lifecycle_challenges
    ADD COLUMN IF NOT EXISTS enrollment_request_digest text;

-- The verified possession signature, recorded when the challenge is consumed. The
-- §5.5 payload must carry it, and `commit()` may run on a DIFFERENT instance from
-- the one that verified the proof (Plan 031's durable cross-instance property), so
-- process-local state cannot supply it.
ALTER TABLE lifecycle_challenges
    ADD COLUMN IF NOT EXISTS proof_signature text;

COMMENT ON COLUMN lifecycle_challenges.proof_signature IS
    'Base64 possession signature verified at submit_possession, replayed into the '
    'section 5.5 payload at commit. Recorded so a cross-instance commit can name the '
    'proof it rests on.';

COMMENT ON COLUMN lifecycle_challenges.trust_domain_id IS
    'v2 possession challenge field (TRUST-DOMAIN.md section 5.5). Part of the signed '
    'challenge body; a rehydrated challenge must reproduce it exactly.';

COMMENT ON COLUMN lifecycle_challenges.enrollment_request_digest IS
    'v2 possession challenge field (TRUST-DOMAIN.md section 5.5): sha256 over the '
    'canonical enrolment request the challenge is bound to.';
