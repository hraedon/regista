-- P1.4 (docs/0.6.0/IMPLEMENTATION-PLAN.md): drop the tables of the deleted
-- subsystems — RFC 3161 timestamping (tsp_batches, migration 016),
-- transparency-log anchoring (anchor_receipts, migration 041) and archive
-- segment sealing (event_segments, migration 039).
--
-- Zero rows exist in any of these tables estate-wide (anchor_receipts and
-- event_segments verified in docs/0.6.0/preflight-s1.json — all 26 schemas
-- report affected_segments: [] and affected_anchors: []; tsp_batches per the
-- P1.4 estate survey), so the guards below should never fire. They
-- exist because a drop that silently discards rows would destroy audit
-- evidence: if any table is nonempty the migration REFUSES with error
-- P14_DROP_REFUSED_NONEMPTY and the operator must export and adjudicate the
-- rows first. Strict by default; loosening later is cheaper than tightening.
--
-- Migration history is append-only: 016/017/022/039/040/041/042 still create
-- and alter these tables on a fresh store, and this migration then drops
-- them. That is the designed cost of an immutable chain.

DO $$
DECLARE
    tbl text;
    n bigint;
BEGIN
    FOREACH tbl IN ARRAY ARRAY['tsp_batches', 'anchor_receipts', 'event_segments']
    LOOP
        IF to_regclass(tbl) IS NOT NULL THEN
            EXECUTE format('SELECT count(*) FROM %I', tbl) INTO n;
            IF n > 0 THEN
                RAISE EXCEPTION
                    'P14_DROP_REFUSED_NONEMPTY: table % holds % row(s); the P1.4 preflight established zero rows estate-wide, so a nonempty table is evidence that must be exported and adjudicated, not dropped. Nothing was dropped.',
                    tbl, n
                    USING ERRCODE = 'check_violation';
            END IF;
            EXECUTE format('DROP TABLE %I', tbl);
        END IF;
    END LOOP;
END
$$;
