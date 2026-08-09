#!/usr/bin/env python3
"""Generate byte-level conformance vectors for the regista 0.6.0 cryptographic epoch.

Gate 0, P0.3.  This script is the single source of the frozen hash fixtures every
implementation of 0.6.0 must reproduce.  It is **read-only with respect to the spec**:
it imports only the vendored RFC 8785 canonicalizer and PyNaCl, and every domain
tag, length-framing rule and canonical-order choice comes from ``V6-ENVELOPE.md`` and
its sibling specs (listed in the ``DOMAINS`` table below), not from this file.

Reproduce from a clean checkout::

    python3 tools/make_v6_vectors.py
    pytest tests/test_v6_vectors.py

The generator writes one JSON file per case into ``tests/vectors/v6/`` plus a
``manifest.json`` listing every case, its hash domain and its expected digest.
The test module regenerates the same bytes and compares; it also flips one byte in
each input and asserts the digest changes (the fail-then-pass half of P0.3's
acceptance criterion).

The test key is 32 bytes of 0x01 — NEVER usable in production.  It exists so every
byte below is reproducible by an implementer with no private material.

Design rules followed here, all from the frozen spec set:

* Domain tags are ``\\x00``-terminated ASCII, prepended to the hashed input
  (``V6-ENVELOPE.md`` §6.1).  The terminator matters: without it, tags where one
  is a prefix of another (``regista.event.hash.v1`` / ``regista.event.hash.v10``)
  could be made to collide by shifting a byte from the tag into the message.
* Length-framing uses ``uint64be`` (8 bytes, big-endian, unsigned) wherever two
  variable-length byte strings are concatenated (``V6-ENVELOPE.md`` §5.3).
* JCS key ordering is by UTF-16BE code unit, applied at every object level
  (``_vendor/rfc8785.py:164``).  Declaration order in this file is irrelevant.
* The number rule is magnitude-based: ``|v| < 2**53`` for every number in
  ``payload`` and ``actor.metadata`` (``V6-ENVELOPE.md`` §2.5, amended by P0.2).
"""

from __future__ import annotations

import hashlib
import json
import struct
import sys
import uuid
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tests"))

import nacl.signing as _nacl

from regista._jcs import canonicalize

SEED = bytes([0x01]) * 32
SK = _nacl.SigningKey(SEED)
PUB = bytes(SK.verify_key)
SECOND_SEED = bytes([0x02]) * 32
SK2 = _nacl.SigningKey(SECOND_SEED)
PUB2 = bytes(SK2.verify_key)

DOMAINS = {
    "event_signing": b"regista.event.v6\x00",
    "event_hash": b"regista.event.hash.v1\x00",
    "workflow_definition": b"regista.workflow-definition.v1\x00",
    "delegation_signing": b"regista.action-delegation.v1\x00",
    "delegation_hash": b"regista.action-delegation.hash.v1\x00",
    "trust_genesis_core": b"regista.trust-genesis.core.v1\x00",
    "trust_genesis_signing": b"regista.trust-genesis.v1\x00",
    "trust_checkpoint": b"regista.trust-checkpoint.v1\x00",
    "checkpoint": b"regista.checkpoint.v1\x00",
    "producer_policy": b"regista.producer-policy.v1\x00",
    "estate_catalog": b"regista.estate-catalog.v1\x00",
    "bundle_member": b"regista.bundle.member.v1\x00",
    "bundle_node": b"regista.bundle.node.v1\x00",
    "review_subject_state": b"regista.review-subject.state.v1\x00",
    "review_subject": b"regista.review-subject.v1\x00",
}


def u64be(n: int) -> bytes:
    return struct.pack(">Q", n)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def digest_str(data: bytes) -> str:
    return "sha256:" + sha256_hex(data)


def domain_digest(domain: bytes, *parts: bytes) -> str:
    return digest_str(domain + b"".join(parts))


def domain_digest_framed(domain: bytes, payload: bytes) -> str:
    return digest_str(domain + u64be(len(payload)) + payload)


def fingerprint(public_key: bytes) -> str:
    return "ed25519:sha256:" + sha256_hex(public_key)


def key_id_from_pub(public_key: bytes) -> str:
    return "pk_" + sha256_hex(public_key)[:16]


TEST_KEY_ID = key_id_from_pub(PUB)
TEST_KEY_ID_2 = key_id_from_pub(PUB2)
TEST_FINGERPRINT = fingerprint(PUB)
TEST_FINGERPRINT_2 = fingerprint(PUB2)

PROJECT_INSTANCE_ID = "9f1c6a2e-3d5b-4c8a-9e07-1b2d3f4a5c6d"
TRUST_DOMAIN_ID = "018f3a5c-7b21-4e6d-8f90-a1b2c3d4e5f6"
ENTITY_ID = "7e4d2c1a-9b8f-4e3d-a2c1-5f6e7d8c9b0a"
EVENT_ID = "3b9c1d7e-5f42-4a8b-9c1d-0e2f3a4b5c6d"
EVENT_ID_2 = "4c0d2e8f-6053-5b9c-0d2e-1f3a4b5c6d7e"
WORKFLOW_ENTITY_ID = str(
    uuid.uuid5(
        uuid.NAMESPACE_OID,
        f"regista.workflow:{PROJECT_INSTANCE_ID}:agent-notes:3",
    )
)


def sign_event(envelope_obj: dict[str, Any]) -> tuple[bytes, bytes, str, str]:
    canonical = canonicalize(envelope_obj)
    sig_input = DOMAINS["event_signing"] + canonical
    signature = SK.sign(sig_input).signature
    event_hash = digest_str(DOMAINS["event_hash"] + u64be(len(canonical)) + canonical + signature)
    payload_canonical_hash = digest_str(sig_input)
    return canonical, signature, event_hash, payload_canonical_hash


def legacy_event_hash(canonical: bytes, signature: bytes) -> str:
    return digest_str(canonical + signature)


def make_v6_envelope(
    *,
    entity_kind: str = "work_item",
    entity_id: str = ENTITY_ID,
    entity_seq: int = 17,
    transition: str = "note_added",
    payload: dict[str, Any] | None = None,
    workflow: dict[str, Any] | None = None,
    key_binding_event_hash: str | None = "sha256:" + "5a" * 32,
    previous_entity_event_hash: str | None = "sha256:" + "35" * 32,
    previous_project_event_hash: str | None = "sha256:" + "73" * 32,
    actor_principal_id: str = "agent:01J8ZC4M9QK3V7XN2R6TB5HFAD",
    actor_kind: str = "agent",
    actor_metadata: dict[str, Any] | None = None,
    producer_harness: str = "claude-code",
    producer_harness_version: str = "1.0.0",
    producer_model: str | None = "claude-opus-5",
    producer_model_lineage: str | None = "anthropic/claude-opus-5",
    auth_mode: str = "direct",
    auth_credentials: list[dict[str, str]] | None = None,
    event_id: str = EVENT_ID,
    occurred_at: str = "2026-08-08T12:34:56.123456Z",
    project_instance_id: str = PROJECT_INSTANCE_ID,
    trust_domain_id: str = TRUST_DOMAIN_ID,
) -> dict[str, Any]:
    if auth_credentials is None:
        auth_credentials = []
    if actor_metadata is None:
        actor_metadata = {}
    return {
        "type": "regista.event",
        "version": 6,
        "project_instance_id": project_instance_id,
        "trust_domain_id": trust_domain_id,
        "event_id": event_id,
        "entity": {"kind": entity_kind, "id": entity_id},
        "entity_seq": entity_seq,
        "actor": {
            "principal_id": actor_principal_id,
            "kind": actor_kind,
            "metadata": actor_metadata,
        },
        "signing": {
            "scheme_id": "ed25519",
            "key_id": TEST_KEY_ID,
            "key_binding_event_hash": key_binding_event_hash,
        },
        "authorization": {"mode": auth_mode, "credentials": auth_credentials},
        "workflow": workflow,
        "occurred_at": occurred_at,
        "transition": transition,
        "payload": payload,
        "chain": {
            "hash_algorithm": "sha-256",
            "previous_entity_event_hash": previous_entity_event_hash,
            "previous_project_event_hash": previous_project_event_hash,
        },
        "producer": {
            "harness": producer_harness,
            "harness_version": producer_harness_version,
            "model": producer_model,
            "model_lineage": producer_model_lineage,
        },
    }


def case_v6_envelope_basic() -> dict[str, Any]:
    wf = {
        "name": "agent-notes",
        "version": 3,
        "definition_hash": "sha256:" + "cf" * 32,
        "registration_event_hash": "sha256:" + "1c" * 32,
    }
    env = make_v6_envelope(payload={"note": "hello", "seq": 17}, workflow=wf)
    canonical, signature, event_hash, pch = sign_event(env)
    return {
        "category": "v6-envelope",
        "description": "The canonical 16-key v6 envelope with producer block (WI-277).",
        "input": {
            "envelope_declaration_order": env,
            "signing_seed_hex": SEED.hex(),
        },
        "expected": {
            "canonical_bytes": canonical.decode(),
            "canonical_len": len(canonical),
            "canonical_sha256": sha256_hex(canonical),
            "signature_input_sha256": sha256_hex(DOMAINS["event_signing"] + canonical),
            "signature_hex": signature.hex(),
            "event_hash": event_hash,
            "payload_canonical_hash": pch,
        },
    }


def case_v6_envelope_no_model() -> dict[str, Any]:
    env = make_v6_envelope(
        transition="link_created",
        payload={"link_type": "blocks"},
        workflow=None,
        producer_model=None,
        producer_model_lineage=None,
        actor_principal_id="service:agent-notes",
        actor_kind="system",
    )
    canonical, signature, event_hash, pch = sign_event(env)
    return {
        "category": "v6-envelope",
        "description": "A service-principal event with no model producer (model: null).",
        "input": {"envelope_declaration_order": env, "signing_seed_hex": SEED.hex()},
        "expected": {
            "canonical_bytes": canonical.decode(),
            "canonical_len": len(canonical),
            "canonical_sha256": sha256_hex(canonical),
            "signature_hex": signature.hex(),
            "event_hash": event_hash,
            "payload_canonical_hash": pch,
        },
    }


def case_bootstrap_trust_genesis() -> dict[str, Any]:
    env = make_v6_envelope(
        entity_kind="trust_domain",
        entity_id=TRUST_DOMAIN_ID,
        entity_seq=1,
        transition="trust_domain_established",
        payload={"trust_domain_core_digest": "sha256:" + "0a" * 32},
        workflow=None,
        key_binding_event_hash=None,
        previous_entity_event_hash=None,
        previous_project_event_hash=None,
        actor_principal_id="human:itadmin",
        actor_kind="human",
        producer_model=None,
        producer_model_lineage=None,
    )
    canonical, _signature, event_hash, pch = sign_event(env)
    return {
        "category": "bootstrap",
        "description": "Bootstrap A: trust_domain_established — first v6 event, null key binding.",
        "input": {"envelope_declaration_order": env, "signing_seed_hex": SEED.hex()},
        "expected": {
            "canonical_bytes": canonical.decode(),
            "canonical_len": len(canonical),
            "event_hash": event_hash,
            "payload_canonical_hash": pch,
        },
    }


def case_bootstrap_cutover_checkpoint() -> dict[str, Any]:
    legacy_canonical = b'{"old":"legacy-head"}'
    legacy_sig = bytes(range(64))
    legacy_head = legacy_event_hash(legacy_canonical, legacy_sig)
    env = make_v6_envelope(
        entity_kind="project",
        entity_id=PROJECT_INSTANCE_ID,
        entity_seq=1,
        transition="project_cryptographic_epoch_started",
        payload={
            "previous_epoch": {
                "event_count": 1000,
                "scheme_counts": {"hmac-sha256": 800, "ed25519": 200},
                "genesis_event_hash": legacy_head,
                "head_event_hash": legacy_head,
                "head_hash_construction": "sha256(canonical_envelope||signature)",
                "max_global_seq": 1000,
            },
            "bootstrap_key_acceptance": {
                "principal_id": "agent:mvmcc03",
                "fingerprint": TEST_FINGERPRINT,
                "trust_event_hash": "sha256:" + "0b" * 32,
                "trust_log_checkpoint": {
                    "checkpoint_seq": 1,
                    "head_event_hash": "sha256:" + "0c" * 32,
                    "document_digest": "sha256:" + "0d" * 32,
                },
                "scopes": ["may_accept_keys", "may_sign_checkpoints"],
            },
            "trust_domain_core_digest": "sha256:" + "0a" * 32,
            "genesis_document_digest": "sha256:" + "0e" * 32,
            "trust_log_checkpoint": {
                "checkpoint_seq": 1,
                "head_event_hash": "sha256:" + "0c" * 32,
                "document_digest": "sha256:" + "0d" * 32,
            },
        },
        workflow=None,
        key_binding_event_hash=None,
        previous_entity_event_hash=None,
        previous_project_event_hash=legacy_head,
    )
    canonical, _signature, event_hash, pch = sign_event(env)
    return {
        "category": "bootstrap",
        "description": "Bootstrap B: cutover checkpoint — legacy head in previous_project_event...",
        "input": {
            "envelope_declaration_order": env,
            "signing_seed_hex": SEED.hex(),
            "legacy_head_construction": "sha256(canonical_envelope||signature)",
            "legacy_head_hash": legacy_head,
        },
        "expected": {
            "canonical_bytes": canonical.decode(),
            "canonical_len": len(canonical),
            "event_hash": event_hash,
            "payload_canonical_hash": pch,
        },
    }


def case_bootstrap_project_initialized() -> dict[str, Any]:
    env = make_v6_envelope(
        entity_kind="project",
        entity_id="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        entity_seq=1,
        transition="project_initialized",
        payload={
            "previous_epoch": {
                "event_count": 0,
                "scheme_counts": {},
                "genesis_event_hash": None,
                "head_event_hash": None,
                "head_hash_construction": "sha256(canonical_envelope||signature)",
                "max_global_seq": None,
            },
            "bootstrap_key_acceptance": {
                "principal_id": "agent:mvmcc03",
                "fingerprint": TEST_FINGERPRINT,
                "trust_event_hash": "sha256:" + "0b" * 32,
                "trust_log_checkpoint": {
                    "checkpoint_seq": 1,
                    "head_event_hash": "sha256:" + "0c" * 32,
                    "document_digest": "sha256:" + "0d" * 32,
                },
                "scopes": ["may_accept_keys", "may_sign_checkpoints"],
            },
            "trust_domain_core_digest": "sha256:" + "0a" * 32,
            "genesis_document_digest": "sha256:" + "0e" * 32,
            "trust_log_checkpoint": {
                "checkpoint_seq": 1,
                "head_event_hash": "sha256:" + "0c" * 32,
                "document_digest": "sha256:" + "0d" * 32,
            },
        },
        workflow=None,
        key_binding_event_hash=None,
        previous_entity_event_hash=None,
        previous_project_event_hash=None,
    )
    canonical, _signature, event_hash, pch = sign_event(env)
    return {
        "category": "bootstrap",
        "description": "Bootstrap C: project_initialized — genesis of a v6-native project, empt...",
        "input": {"envelope_declaration_order": env, "signing_seed_hex": SEED.hex()},
        "expected": {
            "canonical_bytes": canonical.decode(),
            "canonical_len": len(canonical),
            "event_hash": event_hash,
            "payload_canonical_hash": pch,
        },
    }


def case_fingerprint() -> dict[str, Any]:
    return {
        "category": "fingerprint",
        "description": "Ed25519 key fingerprint: ed25519:sha256:<SHA256(raw_pubkey)> (TRUST-DOM...",
        "input": {
            "public_key_hex": PUB.hex(),
            "seed_hex": SEED.hex(),
        },
        "expected": {
            "fingerprint": TEST_FINGERPRINT,
        },
    }


def case_fingerprint_second_key() -> dict[str, Any]:
    return {
        "category": "fingerprint",
        "description": "Second Ed25519 key fingerprint — proves fingerprints are key-distinct.",
        "input": {
            "public_key_hex": PUB2.hex(),
            "seed_hex": SECOND_SEED.hex(),
        },
        "expected": {
            "fingerprint": TEST_FINGERPRINT_2,
        },
    }


def case_version_aware_event_hash() -> dict[str, Any]:
    env_obj = make_v6_envelope(payload={"v": 6})
    canonical = canonicalize(env_obj)
    signature = SK.sign(DOMAINS["event_signing"] + canonical).signature
    v6_event_hash = digest_str(
        DOMAINS["event_hash"] + u64be(len(canonical)) + canonical + signature
    )
    legacy_hash = legacy_event_hash(canonical, signature)
    return {
        "category": "version-aware-event-hash",
        "description": "v6 event_hash (domain-tagged + length-framed) vs legacy sha256(env||sig...",
        "input": {
            "canonical_bytes": canonical.decode(),
            "signature_hex": signature.hex(),
        },
        "expected": {
            "v6_event_hash": v6_event_hash,
            "legacy_event_hash": legacy_hash,
        },
    }


def case_legacy_seam_checkpoint() -> dict[str, Any]:
    legacy_canonical = canonicalize({"type": "legacy", "event_id": "old-1"})
    legacy_sig = SK.sign(legacy_canonical).signature
    legacy_head = legacy_event_hash(legacy_canonical, legacy_sig)
    checkpoint_env = make_v6_envelope(
        entity_kind="project",
        entity_id=PROJECT_INSTANCE_ID,
        entity_seq=1,
        transition="project_cryptographic_epoch_started",
        payload={
            "previous_epoch": {"head_hash_construction": "sha256(canonical_envelope||signature)"}
        },
        workflow=None,
        key_binding_event_hash=None,
        previous_entity_event_hash=None,
        previous_project_event_hash=legacy_head,
    )
    _canonical, _signature, event_hash, _pch = sign_event(checkpoint_env)
    return {
        "category": "legacy-seam",
        "description": "The one v6 event whose previous_project_event_hash is a legacy-domain h...",
        "input": {
            "legacy_canonical_bytes": legacy_canonical.decode(),
            "legacy_signature_hex": legacy_sig.hex(),
            "checkpoint_envelope": checkpoint_env,
        },
        "expected": {
            "legacy_head_hash": legacy_head,
            "checkpoint_event_hash": event_hash,
        },
    }


def merkle_leaf(scope_ordinal: int, event_hash_hex: str) -> str:
    eh = bytes.fromhex(event_hash_hex.removeprefix("sha256:"))
    return digest_str(DOMAINS["bundle_member"] + u64be(scope_ordinal) + eh)


def merkle_node(left: str, right: str) -> str:
    lb = bytes.fromhex(left.removeprefix("sha256:"))
    rb = bytes.fromhex(right.removeprefix("sha256:"))
    return digest_str(DOMAINS["bundle_node"] + lb + rb)


def merkle_root(leaf_hashes: list[str]) -> str | None:
    if not leaf_hashes:
        return None
    level = list(leaf_hashes)
    while len(level) > 1:
        nxt: list[str] = []
        i = 0
        while i < len(level):
            if i + 1 < len(level):
                nxt.append(merkle_node(level[i], level[i + 1]))
                i += 2
            else:
                k = 1
                while k * 2 < len(level):
                    k *= 2
                nxt.append(merkle_node(level[i], merkle_root(level[i:])[0]))  # type: ignore[index]
                i += 1
        level = nxt
    return level[0]


def merkle_root_rfc6962(leaf_hashes: list[str]) -> str | None:
    if not leaf_hashes:
        return None

    def mth(ds: list[str]) -> str:
        if len(ds) == 1:
            return ds[0]
        k = 1
        while k * 2 < len(ds):
            k *= 2
        return merkle_node(mth(ds[:k]), mth(ds[k:]))

    return mth(leaf_hashes)


def case_bundle_merkle_single() -> dict[str, Any]:
    eh = "sha256:" + "aa" * 32
    leaf = merkle_leaf(0, eh)
    root = merkle_root_rfc6962([leaf])
    return {
        "category": "bundle-merkle",
        "description": "Single-leaf tree: MTH({d0}) = leaf_0 (BUNDLE-V3 §3.3).",
        "input": {"event_hashes": [eh]},
        "expected": {
            "leaf_0": leaf,
            "membership_root": root,
        },
    }


def case_bundle_merkle_two() -> dict[str, Any]:
    eh0 = "sha256:" + "aa" * 32
    eh1 = "sha256:" + "bb" * 32
    leaves = [merkle_leaf(i, h) for i, h in enumerate([eh0, eh1])]
    root = merkle_root_rfc6962(leaves)
    return {
        "category": "bundle-merkle",
        "description": "Two-leaf tree: MTH({d0,d1}) = node(leaf_0, leaf_1).",
        "input": {"event_hashes": [eh0, eh1]},
        "expected": {
            "leaf_0": leaves[0],
            "leaf_1": leaves[1],
            "node_0_1": merkle_node(leaves[0], leaves[1]),
            "membership_root": root,
        },
    }


def case_bundle_merkle_three() -> dict[str, Any]:
    ehs = ["sha256:" + chr(ord("a") + i) * 32 for i in range(3)]
    leaves = [merkle_leaf(i, h) for i, h in enumerate(ehs)]
    root = merkle_root_rfc6962(leaves)
    return {
        "category": "bundle-merkle",
        "description": "Three-leaf tree: RFC 6962 split-at-largest-power-of-two (k=2).",
        "input": {"event_hashes": ehs},
        "expected": {
            "leaves": leaves,
            "membership_root": root,
        },
    }


def case_bundle_merkle_five() -> dict[str, Any]:
    ehs = ["sha256:" + chr(ord("a") + i) * 32 for i in range(5)]
    leaves = [merkle_leaf(i, h) for i, h in enumerate(ehs)]
    root = merkle_root_rfc6962(leaves)
    return {
        "category": "bundle-merkle",
        "description": "Five-leaf tree: exercises the odd-split at k=4.",
        "input": {"event_hashes": ehs},
        "expected": {
            "leaves": leaves,
            "membership_root": root,
        },
    }


def case_bundle_merkle_empty() -> dict[str, Any]:
    return {
        "category": "bundle-merkle",
        "description": "Empty tree has no root — an empty bundle has no membership to sign (BUN...",
        "input": {"event_hashes": []},
        "expected": {"membership_root": None},
    }


def case_workflow_definition_digest() -> dict[str, Any]:
    definition = {
        "states": ["open", "in_progress", "reviewed", "done"],
        "transitions": [
            {"name": "start", "from_state": "open", "to_state": "in_progress"},
            {"name": "adversarial_pass", "from_state": "in_progress", "to_state": "reviewed"},
            {"name": "accept", "from_state": "reviewed", "to_state": "done"},
        ],
    }
    b = canonicalize(definition)
    digest = domain_digest_framed(DOMAINS["workflow_definition"], b)
    return {
        "category": "workflow-definition-digest",
        "description": "Domain-separated + length-framed workflow definition digest (V6-ENVELOP...",
        "input": {"definition": definition},
        "expected": {
            "canonical_bytes": b.decode(),
            "canonical_len": len(b),
            "definition_hash": digest,
        },
    }


def case_review_subject_state() -> dict[str, Any]:
    from reducer_v1_vectors import WORKFLOW, _basic

    from regista._reducer import REDUCER_VERSION, content_state_digest, reduce_and_canonicalize

    envelopes = _basic()
    reduced_canonical = reduce_and_canonicalize(envelopes, workflow_definitions=WORKFLOW)
    digest = content_state_digest(envelopes, workflow_definitions=WORKFLOW)
    return {
        "category": "review-subject",
        "description": "content_state_digest over a reduced event prefix (REVIEW-VERDICTS §2.3,...",
        "input": {
            "envelopes_count": len(envelopes),
            "envelope_descriptions": "basic-workflow-walk from reducer_v1_vectors",
        },
        "expected": {
            "reducer_version": REDUCER_VERSION,
            "reduced_canonical_bytes": reduced_canonical.decode(),
            "content_state_digest": digest,
        },
    }


def case_review_subject() -> dict[str, Any]:
    content_state_digest_val = "sha256:" + "7a" * 32
    reviewed_through_event_hash = "sha256:" + "8b" * 32
    subject = {
        "work_item_id": ENTITY_ID,
        "project_instance_id": PROJECT_INSTANCE_ID,
        "reviewed_through_event_hash": reviewed_through_event_hash,
        "content_state_digest": content_state_digest_val,
    }
    b = canonicalize(subject)
    digest = domain_digest(DOMAINS["review_subject"], b)
    return {
        "category": "review-subject",
        "description": "subject_digest over the review subject object (REVIEW-VERDICTS §2.3).",
        "input": {"review_subject": subject},
        "expected": {
            "canonical_bytes": b.decode(),
            "subject_digest": digest,
        },
    }


def case_delegation_credential() -> dict[str, Any]:
    doc_no_sig = {
        "type": "regista.action-delegation",
        "version": 1,
        "credential_id": "d1e2f3a4-b5c6-7890-abcd-ef1234567890",
        "trust_domain_id": TRUST_DOMAIN_ID,
        "issuer_principal_id": "human:itadmin",
        "subject_principal_id": "agent:mvmcc03",
        "issuer_key_id": TEST_KEY_ID,
        "issuer_key_binding_event_hash": "sha256:" + "5a" * 32,
        "parent_credential_hash": None,
        "scope": {
            "project_instance_ids": [PROJECT_INSTANCE_ID],
            "entity_kinds": ["work_item"],
            "workflow_names": ["agent-notes"],
            "transitions": ["note_added"],
        },
        "not_before": "2026-08-09T00:00:00.000000Z",
        "not_after": "2026-08-10T00:00:00.000000Z",
        "max_uses": None,
        "delegation_allowed": False,
    }
    b = canonicalize(doc_no_sig)
    sig_input = DOMAINS["delegation_signing"] + u64be(len(b)) + b
    signature = SK.sign(sig_input).signature
    cred_hash = domain_digest_framed(DOMAINS["delegation_hash"], b)
    {**doc_no_sig, "signature": {"scheme_id": "ed25519", "value": signature.hex()}}
    return {
        "category": "delegation",
        "description": "Action-delegation credential: two domains (signing input + hash) over t...",
        "input": {"document_minus_signature": doc_no_sig},
        "expected": {
            "canonical_bytes": b.decode(),
            "canonical_len": len(b),
            "signature_input_domain": DOMAINS["delegation_signing"].decode("utf-8"),
            "signature_hex": signature.hex(),
            "credential_hash": cred_hash,
        },
    }


def case_trust_genesis() -> dict[str, Any]:
    binding_core = {
        "type": "regista.trust-genesis.core",
        "version": 1,
        "governance": {
            "mode": "solo_effective",
            "threshold": 1,
            "signer_count": 2,
        },
        "signers": [
            {
                "signer_id": "root-a",
                "scheme_id": "ed25519",
                "public_key": PUB.hex(),
                "fingerprint": TEST_FINGERPRINT,
                "custody": {
                    "declared_mode": "offline-host",
                    "declared_holder": "human:itadmin",
                    "attestation": None,
                },
            },
            {
                "signer_id": "root-b",
                "scheme_id": "ed25519",
                "public_key": PUB2.hex(),
                "fingerprint": TEST_FINGERPRINT_2,
                "custody": {
                    "declared_mode": "offline-airgapped",
                    "declared_holder": "human:itadmin",
                    "attestation": None,
                },
            },
        ],
        "created_at": "2026-08-20T00:00:00.000000Z",
        "nonce": "0123456789abcdef" * 8,
    }
    core_bytes = canonicalize(binding_core)
    core_digest = domain_digest_framed(DOMAINS["trust_genesis_core"], core_bytes)
    trust_domain_core_digest = core_digest
    trust_domain_id = str(
        uuid.uuid5(
            uuid.NAMESPACE_OID,
            "regista.trust-domain:" + core_digest.removeprefix("sha256:"),
        )
    )
    genesis_doc_no_extras = {
        "type": "regista.trust-genesis",
        "version": 1,
        "binding_core": binding_core,
        "trust_domain_core_digest": trust_domain_core_digest,
        "trust_domain_id": trust_domain_id,
        "trust_log": {
            "project_instance_id": "11111111-2222-3333-4444-555555555555",
            "project_name_hint": "regista_trust",
            "initial_head_event_hash": None,
        },
        "publication": {
            "kind": "git",
            "url": "https://github.example/regista-attestations",
            "path": "trust-domain.json",
            "bootstrap": "direct-exchange",
        },
    }
    sig_bytes = canonicalize(genesis_doc_no_extras)
    sig_input = DOMAINS["trust_genesis_signing"] + u64be(len(sig_bytes)) + sig_bytes
    signature = SK.sign(sig_input).signature
    return {
        "category": "genesis",
        "description": "Trust-domain genesis: core_digest → trust_domain_id (UUIDv5) + genesis...",
        "input": {
            "binding_core": binding_core,
            "genesis_document_minus_extras": genesis_doc_no_extras,
        },
        "expected": {
            "core_canonical_bytes": core_bytes.decode(),
            "core_canonical_len": len(core_bytes),
            "trust_domain_core_digest": trust_domain_core_digest,
            "trust_domain_id": trust_domain_id,
            "genesis_signature_hex": signature.hex(),
        },
    }


def case_trust_checkpoint() -> dict[str, Any]:
    doc_no_sig = {
        "type": "regista.trust-checkpoint",
        "version": 1,
        "trust_domain_id": TRUST_DOMAIN_ID,
        "trust_domain_core_digest": "sha256:" + "0a" * 32,
        "checkpoint_seq": 12,
        "trust_log": {
            "project_instance_id": "11111111-2222-3333-4444-555555555555",
            "event_count": 418,
            "genesis_event_hash": "sha256:" + "aa" * 32,
            "head_event_hash": "sha256:" + "bb" * 32,
            "max_global_seq": 418,
        },
        "root_governance": {"mode": "solo_effective", "threshold": 1, "signer_count": 2},
        "active_root_fingerprints": [TEST_FINGERPRINT, TEST_FINGERPRINT_2],
        "prev_checkpoint_digest": None,
        "prev_commit": None,
        "created_at": "2026-08-20T12:00:00.000000Z",
        "signer": {
            "scheme_id": "ed25519",
            "key_id": TEST_KEY_ID,
            "principal_id": "service:regista-trust",
            "fingerprint": TEST_FINGERPRINT,
        },
    }
    b = canonicalize(doc_no_sig)
    sig_input = DOMAINS["trust_checkpoint"] + u64be(len(b)) + b
    signature = SK.sign(sig_input).signature
    return {
        "category": "checkpoint",
        "description": "Trust-log checkpoint: domain-separated signing (TRUST-DOMAIN §4.3).",
        "input": {"document_minus_signature": doc_no_sig},
        "expected": {
            "canonical_bytes": b.decode(),
            "canonical_len": len(b),
            "signature_hex": signature.hex(),
        },
    }


def case_cutover_checkpoint() -> dict[str, Any]:
    doc = {
        "type": "regista.checkpoint",
        "version": 1,
        "project_instance_id": PROJECT_INSTANCE_ID,
        "trust_domain_id": TRUST_DOMAIN_ID,
        "cutover_event_hash": "sha256:" + "cc" * 32,
    }
    b = canonicalize(doc)
    digest = domain_digest(DOMAINS["checkpoint"], b)
    return {
        "category": "checkpoint",
        "description": "Externally published cutover checkpoint digest (V6-ENVELOPE §6.1, CUTOV...",
        "input": {"checkpoint_statement": doc},
        "expected": {
            "canonical_bytes": b.decode(),
            "checkpoint_digest": digest,
        },
    }


def case_producer_policy() -> dict[str, Any]:
    doc_no_sig = {
        "type": "regista.producer-policy",
        "version": 1,
        "trust_domain_id": TRUST_DOMAIN_ID,
        "trust_domain_core_digest": "sha256:" + "0a" * 32,
        "entries": [
            {
                "host": "mvmcc03",
                "principal_id": "agent:mvmcc03",
                "key_fingerprints": [TEST_FINGERPRINT],
                "allowed_harnesses": ["claude-code"],
            },
            {
                "host": "mvmcc02",
                "principal_id": "agent:mvmcc02",
                "key_fingerprints": [TEST_FINGERPRINT_2],
                "allowed_harnesses": ["claude-code", "opencode", "codex"],
            },
        ],
        "prev_commit": None,
        "created_at": "2026-08-20T12:00:00.000000Z",
    }
    b = canonicalize(doc_no_sig)
    digest = domain_digest_framed(DOMAINS["producer_policy"], b)
    return {
        "category": "producer-policy",
        "description": "Producer policy digest: domain-separated + length-framed (TRUST-DOMAIN...",
        "input": {"document": doc_no_sig},
        "expected": {
            "canonical_bytes": b.decode(),
            "canonical_len": len(b),
            "producer_policy_digest": digest,
        },
    }


def case_estate_catalog() -> dict[str, Any]:
    doc_no_sig = {
        "type": "regista.estate-catalog",
        "version": 1,
        "trust_domain_id": TRUST_DOMAIN_ID,
        "trust_domain_core_digest": "sha256:" + "0a" * 32,
        "root_governance": {"mode": "solo_effective", "threshold": 1, "signer_count": 2},
        "catalog_kind": "cutover",
        "projects": [
            {
                "project_instance_id": PROJECT_INSTANCE_ID,
                "project_name_hint": "agent_notes",
                "cutover_event_hash": "sha256:" + "cc" * 32,
                "legacy_head_event_hash": "sha256:" + "dd" * 32,
                "legacy_event_count": 1000,
                "scheme_counts": {"hmac-sha256": 800, "ed25519": 200},
                "new_epoch_head_event_hash": "sha256:" + "ee" * 32,
            }
        ],
        "trust_log_checkpoint_digest": "sha256:" + "ff" * 32,
        "prev_commit": None,
        "created_at": "2026-08-20T12:00:00.000000Z",
    }
    b = canonicalize(doc_no_sig)
    digest = domain_digest_framed(DOMAINS["estate_catalog"], b)
    return {
        "category": "catalog",
        "description": "Estate cutover catalog digest (TRUST-DOMAIN §4.3).",
        "input": {"document": doc_no_sig},
        "expected": {
            "canonical_bytes": b.decode(),
            "canonical_len": len(b),
            "estate_catalog_digest": digest,
        },
    }


def case_envelope_canonical_order() -> dict[str, Any]:
    env = make_v6_envelope(payload={"note": "order-test"})
    canonical = canonicalize(env)
    top_keys_in_canonical_order = list(json.loads(canonical).keys())
    return {
        "category": "canonical-order",
        "description": "JCS top-level key ordering (UTF-16BE) — not declaration order (V6-ENVEL...",
        "input": {"envelope_declaration_order": env},
        "expected": {
            "canonical_bytes": canonical.decode(),
            "top_level_key_order": top_keys_in_canonical_order,
        },
    }


CASES: list[tuple[str, Any]] = []


def _register_all() -> None:
    global CASES
    CASES = [
        ("v6-envelope-basic", case_v6_envelope_basic()),
        ("v6-envelope-no-model", case_v6_envelope_no_model()),
        ("v6-envelope-canonical-order", case_envelope_canonical_order()),
        ("bootstrap-trust-genesis", case_bootstrap_trust_genesis()),
        ("bootstrap-cutover-checkpoint", case_bootstrap_cutover_checkpoint()),
        ("bootstrap-project-initialized", case_bootstrap_project_initialized()),
        ("fingerprint-primary", case_fingerprint()),
        ("fingerprint-second-key", case_fingerprint_second_key()),
        ("version-aware-event-hash", case_version_aware_event_hash()),
        ("legacy-seam-checkpoint", case_legacy_seam_checkpoint()),
        ("bundle-merkle-single", case_bundle_merkle_single()),
        ("bundle-merkle-two", case_bundle_merkle_two()),
        ("bundle-merkle-three", case_bundle_merkle_three()),
        ("bundle-merkle-five", case_bundle_merkle_five()),
        ("bundle-merkle-empty", case_bundle_merkle_empty()),
        ("workflow-definition-digest", case_workflow_definition_digest()),
        ("review-subject-state", case_review_subject_state()),
        ("review-subject", case_review_subject()),
        ("delegation-credential", case_delegation_credential()),
        ("trust-genesis", case_trust_genesis()),
        ("trust-checkpoint", case_trust_checkpoint()),
        ("cutover-checkpoint", case_cutover_checkpoint()),
        ("producer-policy", case_producer_policy()),
        ("estate-catalog", case_estate_catalog()),
    ]


def main() -> int:
    _register_all()
    vectors_dir = Path(__file__).resolve().parents[1] / "tests" / "vectors" / "v6"
    vectors_dir.mkdir(parents=True, exist_ok=True)
    manifest: dict[str, Any] = {
        "description": "Byte-level conformance vectors for regista 0.6.0 (Gate 0, P0.3).",
        "test_seed_hex": SEED.hex(),
        "test_public_key_hex": PUB.hex(),
        "test_key_id": TEST_KEY_ID,
        "test_fingerprint": TEST_FINGERPRINT,
        "domain_tags": {k: v.decode("utf-8") for k, v in DOMAINS.items()},
        "cases": [],
    }
    for name, case in CASES:
        out_path = vectors_dir / f"{name}.json"
        out_path.write_text(json.dumps(case, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        expected_keys = sorted(case["expected"].keys())
        manifest["cases"].append(
            {
                "name": name,
                "category": case["category"],
                "description": case["description"],
                "file": out_path.name,
                "expected_keys": expected_keys,
            }
        )
        print(f"  {name}: {out_path.relative_to(Path(__file__).resolve().parents[1])}")
    manifest_path = vectors_dir / "manifest.json"
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(f"\nManifest: {manifest_path.relative_to(Path(__file__).resolve().parents[1])}")
    print(f"Total: {len(CASES)} vector cases")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
