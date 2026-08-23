"""Test trust-root fixtures for the P2.1 trust-domain genesis contracts.

Mints fully signed ``regista.trust-genesis`` documents with **ephemeral test Ed25519
keys** for the three governance modes and hands back the private seeds so tests can
sign further material (P2.2 governance/log events, P1.7 writer fixtures build on this).

Never usable in production: keys are minted per call (or from caller-supplied
deterministic seeds), and nothing here touches a database or the publication channel.

API surface
-----------

``mint_genesis(threshold=..., signer_count=..., ...) -> TrustRootFixture``
    The general constructor. Signers are generated, sorted by fingerprint ascending
    (as the contract requires of ``binding_core``), the derivation is computed via the
    production module (grounded independently by the Gate 0 vector conformance test),
    and by default **every** signer signs (extra valid signatures are permitted and
    reported by the verifier). ``sign_with`` restricts which signers sign.

    The ``declared_mode`` / ``declared_holder`` parameters are unchanged, but per
    **WI-292** their output is the mandatory top-level ``initial_custody`` array —
    one entry per signer, keyed and sorted by fingerprint — not a ``custody`` block
    inside ``binding_core.signers[]``.

``mint_solo() / mint_solo_effective(signer_count=3) / mint_co_signed(threshold=2,
signer_count=2)``
    The three §3.4 modes: 1-of-1, 1-of-n, k-of-n.

``make_signature_entry(document, seed, signer_id, fingerprint, signed_at=...) -> dict``
    A detached signature entry over the document's §3.5 signature input — what the
    offline ceremony helper produces, usable to re-sign a mutated document in tests.

``TrustRootFixture`` fields:
    ``document`` (the signed genesis document, JSON-shaped dict), ``seeds``
    (signer_id -> 32-byte Ed25519 seed), ``public_keys`` (signer_id -> 32 raw bytes),
    ``fingerprints`` (signer_id -> fingerprint), ``signer_ids`` (sorted by fingerprint,
    i.e. binding_core order), ``trust_domain_id``, ``trust_domain_core_digest``,
    ``threshold``, ``signer_count``, ``mode``.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
from typing import Any

import nacl.signing

from regista._principal_keys import _compute_fingerprint
from regista._trust_domain import (
    derive_core_digest,
    derive_governance_mode,
    derive_trust_domain_id,
    genesis_signature_input,
)

DEFAULT_CREATED_AT = "2026-08-20T00:00:00.000000Z"
DEFAULT_SIGNED_AT = "2026-08-20T00:01:00.000000Z"
DEFAULT_NONCE = "0123456789abcdef" * 4  # 64 lowercase hex chars (§3.2)
DEFAULT_PROJECT_INSTANCE_ID = "11111111-2222-3333-4444-555555555555"


@dataclass(frozen=True)
class TrustRootFixture:
    document: dict[str, Any]
    seeds: dict[str, bytes]
    public_keys: dict[str, bytes]
    fingerprints: dict[str, str]
    signer_ids: tuple[str, ...]  # binding_core order (fingerprint ascending)
    trust_domain_id: str
    trust_domain_core_digest: str
    threshold: int
    signer_count: int
    mode: str


def make_signature_entry(
    document: dict[str, Any],
    seed: bytes,
    signer_id: str,
    fingerprint: str,
    *,
    signed_at: str = DEFAULT_SIGNED_AT,
    scheme_id: str = "ed25519",
) -> dict[str, Any]:
    """Sign the document's §3.5 signature input and return one signatures[] entry."""
    sig_input = genesis_signature_input(document)
    signature = nacl.signing.SigningKey(seed).sign(sig_input).signature
    return {
        "signer_id": signer_id,
        "fingerprint": fingerprint,
        "scheme_id": scheme_id,
        "signed_at": signed_at,
        "signature": base64.b64encode(signature).decode("ascii"),
    }


def mint_genesis(
    *,
    threshold: int,
    signer_count: int,
    sign_with: list[str] | None = None,
    seeds: list[bytes] | None = None,
    created_at: str = DEFAULT_CREATED_AT,
    nonce: str = DEFAULT_NONCE,
    project_instance_id: str = DEFAULT_PROJECT_INSTANCE_ID,
    project_name_hint: str = "regista_trust",
    declared_mode: str = "offline-host",
    declared_holder: str = "human:test-owner",
    declared_holders: list[str] | None = None,
) -> TrustRootFixture:
    """Mint a signed genesis document with ephemeral keys.

    ``sign_with`` names the signer_ids that sign (default: all of them — extra
    valid signatures beyond the threshold are permitted). ``seeds`` supplies
    deterministic 32-byte Ed25519 seeds instead of random generation.

    ``declared_holder`` gives every ``initial_custody`` entry the same holder;
    ``declared_holders`` instead gives a DISTINCT holder per signer, positionally
    aligned with ``signer_ids`` (root-a, root-b, ... in fingerprint-ascending order).
    Needed to exercise per-signer custody correspondence (WI-320 (a-prime)), which a
    single shared holder cannot distinguish.
    """
    if seeds is not None and len(seeds) != signer_count:
        raise ValueError(f"expected {signer_count} seeds, got {len(seeds)}")
    if declared_holders is not None and len(declared_holders) != signer_count:
        raise ValueError(
            f"expected {signer_count} declared_holders, got {len(declared_holders)}"
        )
    keypairs: list[tuple[bytes, bytes]] = []
    for i in range(signer_count):
        signing_key = (
            nacl.signing.SigningKey(seeds[i]) if seeds is not None
            else nacl.signing.SigningKey.generate()
        )
        keypairs.append((bytes(signing_key), bytes(signing_key.verify_key)))

    # Assign signer ids AFTER sorting by fingerprint, so root-a is always the
    # lexically-first signer and the binding_core ordering rule is satisfied.
    keypairs.sort(key=lambda kp: _compute_fingerprint(kp[1], "ed25519"))
    signer_ids = tuple(f"root-{chr(ord('a') + i)}" for i in range(signer_count))
    seed_map: dict[str, bytes] = {}
    public_map: dict[str, bytes] = {}
    fingerprint_map: dict[str, str] = {}
    signers: list[dict[str, Any]] = []
    # WI-292: custody declarations are a separate top-level block, keyed by fingerprint
    # and sorted by it. The keypairs are already fingerprint-sorted, so appending in
    # step with the signers satisfies the ordering rule.
    initial_custody: list[dict[str, Any]] = []
    for index, (signer_id, (seed, public)) in enumerate(
        zip(signer_ids, keypairs, strict=True)
    ):
        fingerprint = _compute_fingerprint(public, "ed25519")
        seed_map[signer_id] = seed
        public_map[signer_id] = public
        fingerprint_map[signer_id] = fingerprint
        signers.append(
            {
                "signer_id": signer_id,
                "scheme_id": "ed25519",
                "public_key": base64.b64encode(public).decode("ascii"),
                "fingerprint": fingerprint,
            }
        )
        initial_custody.append(
            {
                "fingerprint": fingerprint,
                "declared_mode": declared_mode,
                "declared_holder": (
                    declared_holder if declared_holders is None
                    else declared_holders[index]
                ),
                "attestation": None,
            }
        )

    binding_core = {
        "type": "regista.trust-genesis.core",
        "version": 1,
        "signers": signers,
        "created_at": created_at,
        "nonce": nonce,
    }
    core_digest = derive_core_digest(binding_core)
    trust_domain_id = derive_trust_domain_id(core_digest)
    mode = derive_governance_mode(threshold, signer_count)
    document: dict[str, Any] = {
        "type": "regista.trust-genesis",
        "version": 1,
        "binding_core": binding_core,
        "initial_custody": initial_custody,
        "initial_governance": {
            "mode": mode,
            "threshold": threshold,
            "signer_count": signer_count,
        },
        "trust_domain_core_digest": core_digest,
        "trust_domain_id": trust_domain_id,
        "trust_log": {
            "project_instance_id": project_instance_id,
            "project_name_hint": project_name_hint,
            "initial_head_event_hash": None,
        },
        "publication": {
            "kind": "git",
            "url": "https://github.example/regista-attestations",
            "path": "trust-domain.json",
            "bootstrap": "direct-exchange",
        },
        "signatures": [],
        "countersignatures": [],
        "anchors": [],
    }
    signing_ids = list(signer_ids) if sign_with is None else list(sign_with)
    for signer_id in signing_ids:
        document["signatures"].append(
            make_signature_entry(
                document, seed_map[signer_id], signer_id, fingerprint_map[signer_id]
            )
        )
    return TrustRootFixture(
        document=document,
        seeds=seed_map,
        public_keys=public_map,
        fingerprints=fingerprint_map,
        signer_ids=signer_ids,
        trust_domain_id=trust_domain_id,
        trust_domain_core_digest=core_digest,
        threshold=threshold,
        signer_count=signer_count,
        mode=mode,
    )


def mint_solo(**kwargs: Any) -> TrustRootFixture:
    """1-of-1: lab/dev posture; mode ``solo``."""
    return mint_genesis(threshold=1, signer_count=1, **kwargs)


def mint_solo_effective(signer_count: int = 3, **kwargs: Any) -> TrustRootFixture:
    """1-of-n (n >= 2): several fingerprints, any one suffices; mode ``solo_effective``."""
    return mint_genesis(threshold=1, signer_count=signer_count, **kwargs)


def mint_co_signed(threshold: int = 2, signer_count: int = 2, **kwargs: Any) -> TrustRootFixture:
    """k-of-n (k >= 2): no single signer could have produced it; mode ``co_signed``."""
    return mint_genesis(threshold=threshold, signer_count=signer_count, **kwargs)
