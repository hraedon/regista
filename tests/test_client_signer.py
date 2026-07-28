"""Tests for the client-side key custody and signing helper (Plan 031 §5).

The client signer generates Ed25519 keypairs, custodies private keys, and
signs possession and effective-use challenges without exposing private
material to the caller.
"""

from __future__ import annotations

import base64
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from regista.client_signer import (
    CLIENT_TYPE,
    CLIENT_VERSION,
    ClientSigner,
    SignerIdentity,
    _custody_from_ref,
    _derive_public_key,
    _fingerprint,
    _sign_ed25519,
)
from regista.principal_lifecycle import (
    EffectiveChallenge,
    EffectiveReceiptStatus,
    PossessionChallenge,
    ProofFormat,
)


class TestSignerIdentity:
    def test_to_dict(self):
        identity = SignerIdentity(
            principal_id="alice",
            public_key=b"\x00" * 32,
            fingerprint="ed25519:sha256:abc123",
            scheme="ed25519",
            custody_mode="file",
            secret_ref="file:/tmp/alice.key",
        )
        d = identity.to_dict()
        assert d["principal_id"] == "alice"
        assert d["fingerprint"] == "ed25519:sha256:abc123"
        assert d["scheme"] == "ed25519"
        assert d["custody_mode"] == "file"
        assert d["secret_ref"] == "file:/tmp/alice.key"
        assert base64.b64decode(d["public_key"]) == b"\x00" * 32


class TestClientSignerGenerate:
    def test_generate_file_backend(self, tmp_path):
        signer = ClientSigner.generate(
            "test-principal",
            backend="file",
            private_key_dir=str(tmp_path),
        )
        assert signer.identity.principal_id == "test-principal"
        assert signer.identity.scheme == "ed25519"
        assert signer.identity.custody_mode == "file"
        assert len(signer.public_key) == 32
        assert signer.identity.fingerprint.startswith("ed25519:sha256:")
        assert signer.identity.secret_ref.startswith("file:")
        key_path = Path(signer.identity.secret_ref.removeprefix("file:"))
        assert key_path.exists()
        assert key_path.stat().st_mode & 0o777 == 0o600

    def test_generate_rejects_unsupported_scheme(self, tmp_path):
        with pytest.raises(ValueError, match="Unsupported scheme"):
            ClientSigner.generate(
                "test-principal",
                backend="file",
                private_key_dir=str(tmp_path),
                scheme="rsa-2048",
            )

    def test_generate_unique_keys(self, tmp_path):
        signer1 = ClientSigner.generate(
            "principal-1",
            backend="file",
            private_key_dir=str(tmp_path),
        )
        signer2 = ClientSigner.generate(
            "principal-2",
            backend="file",
            private_key_dir=str(tmp_path),
        )
        assert signer1.public_key != signer2.public_key
        assert signer1.identity.fingerprint != signer2.identity.fingerprint


class TestClientSignerLoad:
    def test_load_existing_key(self, tmp_path):
        signer1 = ClientSigner.generate(
            "test-principal",
            backend="file",
            private_key_dir=str(tmp_path),
        )
        signer2 = ClientSigner.load(
            "test-principal",
            signer1.identity.secret_ref,
        )
        assert signer2.public_key == signer1.public_key
        assert signer2.identity.fingerprint == signer1.identity.fingerprint

    def test_load_infers_custody_mode(self, tmp_path):
        signer = ClientSigner.generate(
            "test-principal",
            backend="file",
            private_key_dir=str(tmp_path),
        )
        loaded = ClientSigner.load("test-principal", signer.identity.secret_ref)
        assert loaded.identity.custody_mode == "file"

    def test_load_explicit_custody_mode(self, tmp_path):
        signer = ClientSigner.generate(
            "test-principal",
            backend="file",
            private_key_dir=str(tmp_path),
        )
        loaded = ClientSigner.load(
            "test-principal",
            signer.identity.secret_ref,
            custody_mode="windows_local",
        )
        assert loaded.identity.custody_mode == "windows_local"


class TestSignPossession:
    def _make_challenge(self, principal_id: str, fingerprint: str) -> PossessionChallenge:
        now = datetime.now(UTC)
        return PossessionChallenge(
            challenge_id=str(uuid.uuid4()),
            operation_id=str(uuid.uuid4()),
            operation_digest="abc123digest",
            project="test-project",
            principal_id=principal_id,
            fingerprint=fingerprint,
            scheme="ed25519",
            verifier_nonce="test-nonce",
            issued_at=now,
            expires_at=now + timedelta(minutes=5),
        )

    def test_sign_possession_produces_valid_proof(self, tmp_path):
        signer = ClientSigner.generate(
            "test-principal",
            backend="file",
            private_key_dir=str(tmp_path),
        )
        challenge = self._make_challenge("test-principal", signer.identity.fingerprint)
        proof = signer.sign_possession(challenge)

        assert proof.format is ProofFormat.SIGNATURE_V1
        assert proof.challenge_id == challenge.challenge_id
        assert proof.operation_id == challenge.operation_id
        assert proof.operation_digest == challenge.operation_digest
        assert len(proof.signature) == 64

        import nacl.signing

        verify_key = nacl.signing.VerifyKey(signer.public_key)
        envelope = challenge.signing_bytes()
        verify_key.verify(envelope, proof.signature)

    def test_sign_possession_binds_to_challenge(self, tmp_path):
        signer = ClientSigner.generate(
            "test-principal",
            backend="file",
            private_key_dir=str(tmp_path),
        )
        challenge1 = self._make_challenge("test-principal", signer.identity.fingerprint)
        challenge2 = self._make_challenge("test-principal", signer.identity.fingerprint)
        proof1 = signer.sign_possession(challenge1)
        proof2 = signer.sign_possession(challenge2)

        assert proof1.signature != proof2.signature
        assert proof1.challenge_id != proof2.challenge_id

    def test_sign_possession_rejects_wrong_principal(self, tmp_path):
        signer = ClientSigner.generate(
            "test-principal",
            backend="file",
            private_key_dir=str(tmp_path),
        )
        challenge = self._make_challenge("other-principal", signer.identity.fingerprint)
        with pytest.raises(ValueError, match="principal_id"):
            signer.sign_possession(challenge)

    def test_sign_possession_rejects_wrong_fingerprint(self, tmp_path):
        signer = ClientSigner.generate(
            "test-principal",
            backend="file",
            private_key_dir=str(tmp_path),
        )
        challenge = self._make_challenge("test-principal", "ed25519:sha256:wrong")
        with pytest.raises(ValueError, match="fingerprint"):
            signer.sign_possession(challenge)

    def test_sign_possession_rejects_wrong_scheme(self, tmp_path):
        signer = ClientSigner.generate(
            "test-principal",
            backend="file",
            private_key_dir=str(tmp_path),
        )
        now = datetime.now(UTC)
        challenge = PossessionChallenge(
            challenge_id=str(uuid.uuid4()),
            operation_id=str(uuid.uuid4()),
            operation_digest="abc123digest",
            project="test-project",
            principal_id="test-principal",
            fingerprint=signer.identity.fingerprint,
            scheme="rsa-2048",
            verifier_nonce="test-nonce",
            issued_at=now,
            expires_at=now + timedelta(minutes=5),
        )
        with pytest.raises(ValueError, match="scheme"):
            signer.sign_possession(challenge)


class TestSignEffective:
    def _make_effective_challenge(
        self,
        principal_id: str,
        fingerprint: str,
    ) -> EffectiveChallenge:
        from regista.principal_lifecycle import EffectiveChallenge

        now = datetime.now(UTC)
        return EffectiveChallenge(
            challenge_id=str(uuid.uuid4()),
            operation_id=str(uuid.uuid4()),
            operation_digest="digest-456",
            project="test-project",
            principal_id=principal_id,
            fingerprint=fingerprint,
            scheme="ed25519",
            verifier_nonce="test-nonce",
            issued_at=now,
            expires_at=now + timedelta(minutes=5),
        )

    def test_sign_effective_produces_receipt(self, tmp_path):
        signer = ClientSigner.generate(
            "test-principal",
            backend="file",
            private_key_dir=str(tmp_path),
        )
        challenge = self._make_effective_challenge(
            "test-principal",
            signer.identity.fingerprint,
        )
        receipt = signer.sign_effective(challenge)
        assert receipt.operation_id == challenge.operation_id
        assert receipt.operation_digest == challenge.operation_digest
        assert receipt.project == "test-project"
        assert receipt.principal_id == "test-principal"
        assert receipt.fingerprint == signer.identity.fingerprint
        assert receipt.client_type == CLIENT_TYPE
        assert receipt.client_version == CLIENT_VERSION
        assert receipt.status is EffectiveReceiptStatus.EFFECTIVE
        assert receipt.challenge_id == challenge.challenge_id
        assert receipt.signature is not None
        assert len(receipt.signature) == 64

        import nacl.signing

        verify_key = nacl.signing.VerifyKey(signer.public_key)
        envelope = challenge.signing_bytes()
        verify_key.verify(envelope, receipt.signature)

    def test_sign_effective_custom_status(self, tmp_path):
        signer = ClientSigner.generate(
            "test-principal",
            backend="file",
            private_key_dir=str(tmp_path),
        )
        challenge = self._make_effective_challenge(
            "test-principal",
            signer.identity.fingerprint,
        )
        receipt = signer.sign_effective(
            challenge,
            status=EffectiveReceiptStatus.COMMITTED_NOT_EFFECTIVE,
        )
        assert receipt.status is EffectiveReceiptStatus.COMMITTED_NOT_EFFECTIVE

    def test_sign_effective_rejects_wrong_principal(self, tmp_path):
        signer = ClientSigner.generate(
            "test-principal",
            backend="file",
            private_key_dir=str(tmp_path),
        )
        challenge = self._make_effective_challenge(
            "other-principal",
            signer.identity.fingerprint,
        )
        with pytest.raises(ValueError, match="principal_id"):
            signer.sign_effective(challenge)

    def test_sign_effective_rejects_wrong_fingerprint(self, tmp_path):
        signer = ClientSigner.generate(
            "test-principal",
            backend="file",
            private_key_dir=str(tmp_path),
        )
        challenge = self._make_effective_challenge(
            "test-principal",
            "ed25519:sha256:wrong",
        )
        with pytest.raises(ValueError, match="fingerprint"):
            signer.sign_effective(challenge)


class TestDestroy:
    def test_destroy_drops_key_reference(self, tmp_path):
        signer = ClientSigner.generate(
            "test-principal",
            backend="file",
            private_key_dir=str(tmp_path),
        )
        assert signer._private_key != b""
        signer.destroy()
        assert signer._private_key == b""


class TestHelpers:
    def test_fingerprint(self):
        fp = _fingerprint(b"\x00" * 32, "ed25519")
        assert fp.startswith("ed25519:sha256:")
        assert len(fp) == len("ed25519:sha256:") + 64

    def test_derive_public_key(self):
        import nacl.signing

        sk = nacl.signing.SigningKey.generate()
        private_key = bytes(sk)
        expected_public = bytes(sk.verify_key)
        derived = _derive_public_key(private_key)
        assert derived == expected_public

    def test_custody_from_ref(self):
        assert _custody_from_ref("file:/tmp/key") == "file"
        assert _custody_from_ref("vault:secret/key") == "remote_organizational"
        assert _custody_from_ref("azure:key-name") == "remote_organizational"
        assert _custody_from_ref("windows:blob") == "windows_local"
        with pytest.raises(ValueError, match="Cannot infer custody mode"):
            _custody_from_ref("unknown:ref")


class TestEndToEndWithLifecycle:
    """Integration test: signer + PrincipalLifecycle round-trip."""

    def test_enrollment_flow(self, tmp_path):
        from regista.principal_lifecycle import (
            CustodyMode,
            EnrollmentRequest,
            PrincipalKind,
            PrincipalLifecycle,
        )

        signer = ClientSigner.generate(
            "alice",
            backend="file",
            private_key_dir=str(tmp_path),
        )

        lifecycle = PrincipalLifecycle("test-project")
        request = EnrollmentRequest(
            principal_id="alice",
            principal_kind=PrincipalKind.HUMAN,
            actor_id="admin",
            public_key=signer.public_key,
            scheme="ed25519",
            custody_mode=CustodyMode.FILE,
            reason="initial enrollment",
            requested_authority="admin",
            policy_version="v1",
        )
        operation = lifecycle.prepare_enrollment(request, idempotency_key="enroll-alice-1")
        assert operation.state.value == "awaiting_proof"

        challenge = lifecycle.issue_possession_challenge(operation.operation_id)
        proof = signer.sign_possession(challenge)
        verified = lifecycle.submit_possession(operation.operation_id, proof)
        assert verified.state.value == "awaiting_approval"

    def test_wrong_key_rejected_by_lifecycle(self, tmp_path):
        """A proof signed by the wrong key is rejected at submit_possession.

        This simulates an attacker who bypasses the signer's validation and
        directly constructs a proof with a different key. The lifecycle's
        signature verification must catch this.
        """
        from regista.principal_lifecycle import (
            CustodyMode,
            EnrollmentRequest,
            LifecycleContractError,
            LifecycleErrorCode,
            PossessionProof,
            PrincipalKind,
            PrincipalLifecycle,
            ProofFormat,
        )

        signer_a = ClientSigner.generate(
            "alice",
            backend="file",
            private_key_dir=str(tmp_path),
        )
        signer_b = ClientSigner.generate(
            "bob",
            backend="file",
            private_key_dir=str(tmp_path),
        )

        lifecycle = PrincipalLifecycle("test-project")
        request = EnrollmentRequest(
            principal_id="alice",
            principal_kind=PrincipalKind.HUMAN,
            actor_id="admin",
            public_key=signer_a.public_key,
            scheme="ed25519",
            custody_mode=CustodyMode.FILE,
            reason="initial enrollment",
            requested_authority="admin",
            policy_version="v1",
        )
        operation = lifecycle.prepare_enrollment(request, idempotency_key="enroll-alice-wrongkey")

        challenge = lifecycle.issue_possession_challenge(operation.operation_id)
        envelope = challenge.signing_bytes()
        forged_signature = _sign_ed25519(signer_b._private_key, envelope)
        forged_proof = PossessionProof(
            format=ProofFormat.SIGNATURE_V1,
            challenge_id=challenge.challenge_id,
            operation_id=challenge.operation_id,
            operation_digest=challenge.operation_digest,
            signature=forged_signature,
        )

        with pytest.raises(LifecycleContractError) as exc_info:
            lifecycle.submit_possession(operation.operation_id, forged_proof)
        assert exc_info.value.code == LifecycleErrorCode.PROOF_VERIFICATION_FAILED
