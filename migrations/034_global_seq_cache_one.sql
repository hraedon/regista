-- Plan 024: Fix global_seq ordering divergence under concurrent appends.
--
-- events_global_seq_seq was created with CACHE 100 (migration 017), meaning
-- each backend caches a block of 100 sequence values.  When sessions
-- interleave their appends, global_seq order can diverge from the actual
-- append (chain-link) order, producing false "global_chain_broken" warnings
-- in replay.
--
-- The append path calls nextval AFTER acquiring the event_chain_head FOR
-- UPDATE lock, so with CACHE 1 every nextval round-trips to the sequence
-- server and values are assigned in lock-acquisition order — matching the
-- chain-link order established under the same lock.
--
-- This does not alter existing data (the chain links are correct; the
-- replay verifier has been fixed to walk by hash links, not global_seq
-- sort).  It only prevents future global_seq ordering divergence.

ALTER SEQUENCE events_global_seq_seq CACHE 1;
