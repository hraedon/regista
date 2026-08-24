"""WI-337 fixtures: an in-memory trust log, its published export, and a bound project.

Database-free **on purpose**, for the same reason ``test_wi330_estate_catalog.py`` is:
the artifact's byte contract and its fail-closed refusals are the whole of what a
published document promises, and a conformance test that only runs where PostgreSQL is
reachable is a conformance test that silently stops running. The live ceremony (``trust
publish-log`` against a real store) lives in ``test_wi337_trust_log_export_live.py``.

Nothing here reimplements verification. The trust-log events are built with the same
``_trust_log_fixtures`` payload builders the WI-301/WI-303 suites use and signed with
``sign_v6_envelope``; the export document is produced by the PRODUCTION builder
(``_trust_log_export.build_trust_log_export``) fed an ``OfflineTrustLogMaterial``, so the
fixture cannot drift from what ``regista trust publish-log`` writes.

Clock discipline (WI-318): every timestamp is anchored to ``_ts()``, which is evaluated at
CALL time, never at module import. A 14-minute suite runs these fixtures long after the
module was imported, and a possession challenge whose ``expires_at`` was fixed at import
would be a time bomb exactly like the one WI-318 removed.
"""

from __future__ import annotations

import base64
import uuid
from dataclasses import dataclass, field
from typing import Any

import nacl.signing
from _trust_fixtures import TrustRootFixture, mint_solo
from _trust_log_fixtures import (
    TrustLogKey,
    _ts,
    build_v6_envelope,
    make_enrollment_payload,
    make_possession_challenge,
    make_registrar_delegation_payload,
    make_root_rotation_payload,
    make_trust_domain_established_payload,
    principal_entity_uuid,
)

from regista._principal_keys import _compute_fingerprint
from regista._signing import compute_v6_event_hash, sign_v6_envelope
from regista._trust_log import expected_entity_kind
from regista._trust_log_export import (
    ExportedEvent,
    OfflineTrustLogMaterial,
    build_trust_log_export,
    sign_trust_log_export,
)

ROOT_PRINCIPAL = "service:root-a"
REGISTRAR_PRINCIPAL = "service:registrar-1"

#: Every lifecycle transition the fixture's registrar performs. The default scope set in
#: ``_trust_log_fixtures`` omits ``principal_registered``, and a registrar acting outside
#: its scopes is refused by the replay — which is correct, and would look like a fixture
#: bug rather than the contract working, so the scope is named here explicitly.
REGISTRAR_SCOPES = [
    "principal_registered",
    "principal_key_enrolled",
    "principal_key_rotated",
    "principal_key_revoked",
]


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


@dataclass
class MemoryTrustLog:
    """A signed trust-log chain held in memory, plus its possession evidence."""

    genesis: TrustRootFixture
    trust_domain_id: str
    project_instance_id: str
    root_key: TrustLogKey
    registrar_key: TrustLogKey
    events: list[ExportedEvent] = field(default_factory=list)
    challenges: dict[str, dict[str, Any]] = field(default_factory=dict)
    #: ``key_id -> TrustLogKey`` for every principal key the log enrolled.
    enrolled: dict[str, TrustLogKey] = field(default_factory=dict)
    #: ``event_hash`` of each appended event, in chain order.
    hashes: list[str] = field(default_factory=list)
    _entity_seq: dict[tuple[str, str], int] = field(default_factory=dict)
    _entity_head: dict[tuple[str, str], str] = field(default_factory=dict)
    genesis_event_hash: str = ""
    delegation_event_hash: str = ""

    # -- construction ---------------------------------------------------------

    def append(
        self,
        *,
        transition: str,
        payload: dict[str, Any],
        signing_key: TrustLogKey,
        actor_principal_id: str,
        entity_id: str,
        key_binding_event_hash: str | None,
        entity_kind: str | None = None,
    ) -> str:
        kind = entity_kind or expected_entity_kind(transition)
        seq = self._entity_seq.get((kind, entity_id), 0) + 1
        self._entity_seq[(kind, entity_id)] = seq
        envelope = build_v6_envelope(
            transition=transition,
            payload=payload,
            trust_domain_id=self.trust_domain_id,
            project_instance_id=self.project_instance_id,
            entity_id=entity_id,
            entity_seq=seq,
            signing_key=signing_key,
            actor_principal_id=actor_principal_id,
            key_binding_event_hash=key_binding_event_hash,
            previous_entity_event_hash=self._entity_head.get((kind, entity_id)),
            previous_project_event_hash=self.hashes[-1] if self.hashes else None,
            occurred_at=_ts(),
            entity_kind=kind,
        )
        signed = sign_v6_envelope(envelope, signing_key.seed)
        event_hash = "sha256:" + compute_v6_event_hash(
            signed.canonical_envelope, signed.signature
        ).hex()
        self.events.append(
            ExportedEvent(
                canonical_envelope=signed.canonical_envelope, signature=signed.signature
            )
        )
        self.hashes.append(event_hash)
        self._entity_head[(kind, entity_id)] = event_hash
        return event_hash

    def register(self, principal_id: str, *, kind: str = "agent") -> str:
        return self.append(
            transition="principal_registered",
            payload={
                "type": "regista.principal-registration",
                "version": 1,
                "trust_domain_id": self.trust_domain_id,
                "principal_id": principal_id,
                "principal_kind": kind,
                "authorized_by": {
                    "authority": "registrar",
                    "principal_id": REGISTRAR_PRINCIPAL,
                    "key_id": self.registrar_key.key_id,
                    "delegation_event_hash": self.delegation_event_hash,
                },
            },
            signing_key=self.registrar_key,
            actor_principal_id=REGISTRAR_PRINCIPAL,
            entity_id=principal_entity_uuid(principal_id),
            key_binding_event_hash=self.delegation_event_hash,
        )

    def enrol(self, principal_id: str, key: TrustLogKey, *, kind: str = "agent") -> str:
        challenge = make_possession_challenge(
            trust_domain_id=self.trust_domain_id,
            principal_id=principal_id,
            fingerprint=key.fingerprint,
        )
        payload = make_enrollment_payload(
            trust_domain_id=self.trust_domain_id,
            principal_id=principal_id,
            key=key,
            principal_kind=kind,
            challenge=challenge,
            authorized_by={
                "authority": "registrar",
                "principal_id": REGISTRAR_PRINCIPAL,
                "key_id": self.registrar_key.key_id,
                "delegation_event_hash": self.delegation_event_hash,
            },
        )
        self.challenges[challenge.challenge_id] = {
            "challenge_id": challenge.challenge_id,
            "operation_id": challenge.operation_id,
            "operation_digest": challenge.operation_digest,
            "project": challenge.project,
            "principal_id": challenge.principal_id,
            "fingerprint": challenge.fingerprint,
            "scheme": challenge.scheme,
            "verifier_nonce": challenge.verifier_nonce,
            "enrollment_request_digest": challenge.enrollment_request_digest,
            "issued_at": challenge.issued_at,
            "expires_at": challenge.expires_at,
            "used": True,
            "kind": "possession",
            "trust_domain_id": challenge.trust_domain_id,
            "proof_signature": payload["possession_proof"]["signature"],
        }
        self.enrolled[key.key_id] = key
        return self.append(
            transition="principal_key_enrolled",
            payload=payload,
            signing_key=self.registrar_key,
            actor_principal_id=REGISTRAR_PRINCIPAL,
            entity_id=principal_entity_uuid(principal_id),
            key_binding_event_hash=self.delegation_event_hash,
        )

    def revoke(self, principal_id: str, key_id: str, *, reason: str = "compromised") -> str:
        return self.append(
            transition="principal_key_revoked",
            payload={
                "type": "regista.key-revocation",
                "version": 1,
                "trust_domain_id": self.trust_domain_id,
                "principal_id": principal_id,
                "key_id": key_id,
                "reason": reason,
                "revoked_at": _ts(),
                "effective_from": {
                    "kind": "on_chain_position",
                    "trust_log_event_hash": "self",
                },
                "retroactive_suspicion": {
                    "declared": False,
                    "suspect_from_event_hash": None,
                    "note": None,
                },
                "authorized_by": {
                    "authority": "registrar",
                    "principal_id": REGISTRAR_PRINCIPAL,
                    "key_id": self.registrar_key.key_id,
                    "delegation_event_hash": self.delegation_event_hash,
                },
            },
            signing_key=self.registrar_key,
            actor_principal_id=REGISTRAR_PRINCIPAL,
            entity_id=principal_entity_uuid(principal_id),
            key_binding_event_hash=self.delegation_event_hash,
        )

    def rotate_root(
        self,
        *,
        added: list[TrustLogKey],
        removed_fingerprints: list[str],
        new_threshold: int,
        signing_root_keys: list[TrustLogKey],
    ) -> str:
        """Append a §5.4 ``trust_root_rotated`` event, root-authorised.

        The envelope is signed by a CURRENT root and binds to the genesis event; the
        payload carries >= threshold detached root signatures from the current set. This
        is what lets a test prove the WI-337 defence: after A/B -> A/C, the removed root B
        is no longer in the replay-derived active set, so a B signature over the published
        export is refused (``root_signer_not_active``) rather than re-authorising the very
        log that records B's removal.
        """
        payload = make_root_rotation_payload(
            trust_domain_id=self.trust_domain_id,
            added=added,
            removed=removed_fingerprints,
            new_threshold=new_threshold,
            signing_root_keys=signing_root_keys,
        )
        return self.append(
            transition="trust_root_rotated",
            payload=payload,
            signing_key=signing_root_keys[0],
            actor_principal_id=ROOT_PRINCIPAL,
            entity_id=self.trust_domain_id,
            key_binding_event_hash=self.genesis_event_hash,
            entity_kind="trust_domain",
        )

    # -- publication ----------------------------------------------------------

    def material(self) -> OfflineTrustLogMaterial:
        return OfflineTrustLogMaterial(
            events=tuple(self.events), challenges=dict(self.challenges)
        )

    def export(
        self, *, created_at: str | None = None, sign: bool = True, prev_commit: str | None = None
    ) -> dict[str, Any]:
        """Build (and by default root-sign) the publication document.

        Uses the PRODUCTION builder, so the fixture and ``regista trust publish-log``
        cannot disagree about what a published export contains.
        """
        document = build_trust_log_export(
            self.material(),
            genesis_document=self.genesis.document,
            created_at=created_at or _ts(),
            prev_commit=prev_commit,
        )
        if not sign:
            return document
        return self.sign(document)

    def sign(
        self, document: dict[str, Any], *, signer_ids: list[str] | None = None
    ) -> dict[str, Any]:
        signed = document
        for signer_id in signer_ids or list(self.genesis.signer_ids):
            signed = sign_trust_log_export(
                signed,
                seed=self.genesis.seeds[signer_id],
                signer_id=signer_id,
                fingerprint=self.genesis.fingerprints[signer_id],
            )
        return signed


def mint_trust_log(
    *,
    genesis: TrustRootFixture | None = None,
    principals: dict[str, str] | None = None,
) -> MemoryTrustLog:
    """A complete, replayable trust log: genesis, a registrar, and enrolled principals.

    ``principals`` maps ``principal_id -> key_id``. Every one is registered and enrolled
    under the registrar's root-signed delegation, so its key genuinely chains to the
    genesis roots — which is the property WI-337 exists to make checkable offline.
    """

    fixture = genesis or mint_solo()
    root_signer = fixture.signer_ids[0]
    root_key = TrustLogKey(
        key_id="k_root",
        seed=fixture.seeds[root_signer],
        public_key=fixture.public_keys[root_signer],
        fingerprint=fixture.fingerprints[root_signer],
    )
    registrar_key = TrustLogKey.mint("pk_registrar_1")
    log = MemoryTrustLog(
        genesis=fixture,
        trust_domain_id=fixture.trust_domain_id,
        project_instance_id=str(fixture.document["trust_log"]["project_instance_id"]),
        root_key=root_key,
        registrar_key=registrar_key,
    )

    # 1. trust_domain_established — the one event with a null predecessor AND a null
    #    key binding (§5.2 AMENDED). Signed by a genesis root; the payload restates the
    #    genesis and carries detached root signatures over it.
    root_keys = [
        TrustLogKey(
            key_id=f"k_{signer_id}",
            seed=fixture.seeds[signer_id],
            public_key=fixture.public_keys[signer_id],
            fingerprint=fixture.fingerprints[signer_id],
        )
        for signer_id in fixture.signer_ids
    ]
    log.genesis_event_hash = log.append(
        transition="trust_domain_established",
        payload=make_trust_domain_established_payload(fixture.document, root_keys=root_keys),
        signing_key=root_key,
        actor_principal_id=ROOT_PRINCIPAL,
        entity_id=fixture.trust_domain_id,
        key_binding_event_hash=None,
        entity_kind="trust_domain",
    )

    # 2. registrar_delegated — root authority. Principal registration and key enrolment
    #    carry no `root_signatures` member (their payload key sets are closed), so root
    #    cannot perform them directly: a registrar is the only path, and it is exactly
    #    what makes the enrolments' authority a CHAIN rather than a single signature.
    log.delegation_event_hash = log.append(
        transition="registrar_delegated",
        payload=make_registrar_delegation_payload(
            trust_domain_id=fixture.trust_domain_id,
            registrar_principal_id=REGISTRAR_PRINCIPAL,
            key=registrar_key,
            scopes=REGISTRAR_SCOPES,
            not_before=_ts(-24 * 60 * 60),
            not_after=_ts(365 * 24 * 60 * 60),
            root_keys=root_keys,
        ),
        signing_key=root_key,
        actor_principal_id=ROOT_PRINCIPAL,
        entity_id=fixture.trust_domain_id,
        key_binding_event_hash=log.genesis_event_hash,
        entity_kind="trust_domain",
    )

    for principal_id, key_id in (principals or {}).items():
        log.register(principal_id)
        log.enrol(principal_id, TrustLogKey.mint(key_id))
    return log


def mint_key(key_id: str) -> TrustLogKey:
    return TrustLogKey.mint(key_id)


def fingerprint_of(public_key: bytes) -> str:
    return _compute_fingerprint(public_key, "ed25519")


def ed25519_pair() -> tuple[bytes, bytes]:
    signing_key = nacl.signing.SigningKey.generate()
    return bytes(signing_key), bytes(signing_key.verify_key)


def fresh_uuid() -> str:
    return str(uuid.uuid4())
