from __future__ import annotations

import uuid

import pytest

from substrate._timestamping import (
    TSAConfig,
    compute_merkle_root,
    merkle_proof,
    verify_merkle_proof,
)


class TestMerkleTree:
    def test_root_deterministic(self):
        ids = [uuid.uuid4() for _ in range(4)]
        root1 = compute_merkle_root(ids)
        root2 = compute_merkle_root(ids)
        assert root1 == root2

    def test_single_event(self):
        uid = uuid.uuid4()
        root = compute_merkle_root([uid])
        assert isinstance(root, bytes)
        assert len(root) == 32

    def test_empty_raises(self):
        with pytest.raises(ValueError, match="event_ids must not be empty"):
            compute_merkle_root([])

    def test_inclusion_proof(self):
        ids = [uuid.uuid4() for _ in range(8)]
        root = compute_merkle_root(ids)
        target = ids[3]
        proof = merkle_proof(ids, target)
        assert verify_merkle_proof(root, target, proof)

    def test_exclusion_fails(self):
        ids = [uuid.uuid4() for _ in range(8)]
        root = compute_merkle_root(ids)
        bad = uuid.uuid4()
        proof = merkle_proof(ids, ids[0])
        assert not verify_merkle_proof(root, bad, proof)

    def test_odd_count(self):
        ids = [uuid.uuid4() for _ in range(5)]
        root = compute_merkle_root(ids)
        for uid in ids:
            proof = merkle_proof(ids, uid)
            assert verify_merkle_proof(root, uid, proof)

    def test_power_of_two(self):
        ids = [uuid.uuid4() for _ in range(16)]
        root = compute_merkle_root(ids)
        proof = merkle_proof(ids, ids[7])
        assert verify_merkle_proof(root, ids[7], proof)


class TestTSAConfig:
    def test_defaults(self):
        cfg = TSAConfig(tsa_url="https://example.com/tsr")
        assert cfg.tsa_url == "https://example.com/tsr"
        assert cfg.batch_size == 1000
        assert cfg.interval_seconds == 3600.0

    def test_custom_batch_size(self):
        cfg = TSAConfig(tsa_url="https://example.com/tsr", batch_size=500)
        assert cfg.batch_size == 500
