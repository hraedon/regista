#!/usr/bin/env python3
"""Generate the V6-ENVELOPE.md worked test vector.

Read-only with respect to the regista repo: it imports only the vendored RFC 8785
canonicalizer (copied byte-identically from origin/main:src/regista/_vendor/rfc8785.py)
plus PyNaCl. Nothing here is production code.
"""
from __future__ import annotations

import hashlib
import json
import struct
import sys

sys.path.insert(0, "/home/itadmin/audit-scratch/v6-design/_postS1")
from rfc8785 import dumps as jcs  # noqa: E402

import nacl.signing  # noqa: E402

# --- deterministic test key -------------------------------------------------
# Seed is 32 bytes of 0x01. NEVER usable in production; it exists so an
# implementer can reproduce every byte below.
SEED = bytes([0x01]) * 32
sk = nacl.signing.SigningKey(SEED)
vk = sk.verify_key
pub = bytes(vk)

# regista key_id convention today is "pk_" + 16 hex chars (see _principal_keys.py).
# For the vector we derive it deterministically from the public key so the
# document does not have to assert an unexplained constant.
fingerprint = hashlib.sha256(b"regista.key.fingerprint.v1\x00" + pub).hexdigest()
key_id = "pk_" + fingerprint[:16]

envelope = {
    "type": "regista.event",
    "version": 6,
    "project_instance_id": "9f1c6a2e-3d5b-4c8a-9e07-1b2d3f4a5c6d",
    "trust_domain_id": "018f3a5c-7b21-4e6d-8f90-a1b2c3d4e5f6",
    "event_id": "3b9c1d7e-5f42-4a8b-9c1d-0e2f3a4b5c6d",
    "entity": {"kind": "work_item", "id": "7e4d2c1a-9b8f-4e3d-a2c1-5f6e7d8c9b0a"},
    "entity_seq": 17,
    "actor": {
        "principal_id": "agent:01J8ZC4M9QK3V7XN2R6TB5HFAD",
        "kind": "agent",
        "metadata": {"harness": "claude-code", "model_lineage": "anthropic/claude-opus-5"},
    },
    "signing": {
        "scheme_id": "ed25519",
        "key_id": key_id,
        "key_binding_event_hash": "sha256:" + hashlib.sha256(b"key-binding-event-placeholder").hexdigest(),
    },
    "authorization": {"mode": "direct", "credentials": []},
    "workflow": {
        "name": "agent-notes",
        "version": 3,
        "definition_hash": "sha256:" + hashlib.sha256(b"workflow-definition-placeholder").hexdigest(),
        "registration_event_hash": "sha256:" + hashlib.sha256(b"workflow-registration-placeholder").hexdigest(),
    },
    "occurred_at": "2026-08-08T12:34:56.123456Z",
    "transition": "note_added",
    "payload": {"note": "hello", "seq": 17},
    "chain": {
        "hash_algorithm": "sha-256",
        "previous_entity_event_hash": "sha256:" + hashlib.sha256(b"prev-entity-event-placeholder").hexdigest(),
        "previous_project_event_hash": "sha256:" + hashlib.sha256(b"prev-project-event-placeholder").hexdigest(),
    },
}

canonical = jcs(envelope)
sig_input = b"regista.event.v6\x00" + canonical
signature = sk.sign(sig_input).signature

event_hash = hashlib.sha256(
    b"regista.event.hash.v1\x00"
    + struct.pack(">Q", len(canonical))
    + canonical
    + signature
).digest()

entity_link = hashlib.sha256(b"regista.chain.entity.v1\x00" + event_hash).digest()
project_link = hashlib.sha256(b"regista.chain.project.v1\x00" + event_hash).digest()

out = {
    "test_seed_hex": SEED.hex(),
    "public_key_hex": pub.hex(),
    "key_fingerprint": "sha256:" + fingerprint,
    "key_id": key_id,
    "canonical_len": len(canonical),
    "canonical_bytes_utf8": canonical.decode(),
    "canonical_sha256": hashlib.sha256(canonical).hexdigest(),
    "signature_input_sha256": hashlib.sha256(sig_input).hexdigest(),
    "signature_b64": __import__("base64").b64encode(signature).decode(),
    "signature_hex": signature.hex(),
    "event_hash": "sha256:" + event_hash.hex(),
    "entity_chain_link": "sha256:" + entity_link.hex(),
    "project_chain_link": "sha256:" + project_link.hex(),
}

# Cross-domain non-confusability demonstration: the same event_hash under two
# different link domains produces two unrelated values, and neither equals the
# event hash itself.
assert entity_link != project_link != event_hash

print(json.dumps(out, indent=2))
