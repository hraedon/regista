"""WI-224 lineage-in-claim bookkeeping: retired under WI-305 A/C.

The claim ops' ``actor_metadata={"model_lineage": ...}`` lineage vehicle is a
v5-only mechanic that the v6 envelope refuses at ingress (producer fields must
not appear in actor.metadata, ``V6-ENVELOPE.md`` §1.8). The surviving invariants
— an agent's claim counts it as an author for separation of duties, and a
claimed, worked item's cross-lineage review passes only when the reviewer is
genuinely distinct — carry forward over the v6 vehicles in
``tests/test_wi305_v6_review_gate.py`` (author and reviewer lineage via the
signed process-level ``producer`` block) and
``tests/test_wi305_reviewer_lineage_payload.py``.
Each retired node is recorded in ``tests/retired_tests_ledger.json``.
"""
