-- WI-315: v6 epoch-boundary guard (database-level defense-in-depth).
--
-- The v6 epoch boundary is enforced in library code today: once the project has
-- opened its v6 epoch (``project_identity`` populated), ``_genesis.check_legacy_append``
-- and ``admit_legacy_append`` refuse a legacy (v1-v5) writer with ``V6_EPOCH_OPEN``.
-- Nothing at the DATABASE level, however, stops a direct ``events`` insert that
-- bypasses the library. A stale/misconfigured 0.5.5 client -- whose
-- ``check_migrations_current`` passes against a store that is AHEAD of its own library
-- -- repointed at a 0.6.0 v6 schema would append v1-v5 rows straight into the opened
-- v6 chain, silently corrupting it. During a fleet cutover (many agents moving from
-- 0.5.5 to 0.6.0 against a shared store) that is the primary corruption hazard.
--
-- This trigger is the missing DB-level guard. Once the epoch is open, every
-- ``events`` INSERT must carry a v6 ``canonical_envelope``: a JCS-canonical JSON
-- object with ``"type":"regista.event"`` and ``"version":6``. Anything else is
-- refused:
--
--   * a NULL envelope -- v1-v4 predate the ``canonical_envelope`` column population,
--     so they never carried one; and
--   * a populated-but-non-v6 envelope -- 0.5.5 DOES populate ``canonical_envelope``
--     (via ``sign_event``), but with a v5 envelope that has no top-level
--     ``type``/``version``. The NULL-only check a naive reading suggests is therefore
--     INSUFFICIENT: it would let a 0.5.5 client's v5 row through. The discriminator
--     that actually catches the named threat is "is a v6 envelope", not "is not NULL".
--
-- The guard deliberately does NOT fire before the epoch is open:
--   * pre-genesis legacy appends are still refused by the library with
--     ``GENESIS_REQUIRED`` (this trigger must not change that failure form); and
--   * the genesis event itself is inserted while ``project_identity`` is still empty
--     (``append_v6_genesis`` writes the ``events`` row first, then the
--     ``project_identity`` row), so genesis is never gated here -- it would pass the
--     v6-envelope check anyway, but the epoch-not-open short-circuit means it is never
--     even evaluated.
--
-- This is additive defense-in-depth; it does not replace the library-level
-- ``check_legacy_append`` logic.

CREATE OR REPLACE FUNCTION regista_enforce_v6_epoch_boundary()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    envelope_json jsonb;
BEGIN
    -- Only guard once the project has opened its v6 epoch. Before genesis the
    -- library refuses legacy appends with GENESIS_REQUIRED, and the genesis event
    -- lands while project_identity is still empty.
    IF NOT EXISTS (SELECT 1 FROM project_identity WHERE id = TRUE) THEN
        RETURN NEW;
    END IF;

    -- Fail closed: a v1-v4 insert never populated canonical_envelope at all.
    IF NEW.canonical_envelope IS NULL THEN
        RAISE EXCEPTION 'v6 epoch boundary violation: refusing an events insert with no v6 canonical_envelope after the project opened its v6 epoch (event_id=%)', NEW.event_id
            USING ERRCODE = 'RG315';
    END IF;

    -- A populated envelope must decode to a v6 envelope. A v5/legacy client (e.g.
    -- 0.5.5) populates canonical_envelope with an envelope that has no top-level
    -- "type"/"version"; only a v6 envelope carries type=regista.event, version=6.
    -- A non-decodable envelope is treated as a violation (fail closed).
    BEGIN
        envelope_json := convert_from(NEW.canonical_envelope, 'UTF8')::jsonb;
    EXCEPTION WHEN others THEN
        RAISE EXCEPTION 'v6 epoch boundary violation: canonical_envelope is not a decodable v6 envelope after the project opened its v6 epoch (event_id=%)', NEW.event_id
            USING ERRCODE = 'RG315';
    END;

    IF envelope_json->>'type' IS DISTINCT FROM 'regista.event'
       OR envelope_json->>'version' IS DISTINCT FROM '6' THEN
        RAISE EXCEPTION 'v6 epoch boundary violation: refusing a non-v6 events insert (type=%, version=%) after the project opened its v6 epoch (event_id=%)', envelope_json->>'type', envelope_json->>'version', NEW.event_id
            USING ERRCODE = 'RG315';
    END IF;

    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS events_enforce_v6_epoch_boundary ON events;

CREATE TRIGGER events_enforce_v6_epoch_boundary
    BEFORE INSERT ON events
    FOR EACH ROW
    EXECUTE FUNCTION regista_enforce_v6_epoch_boundary();
