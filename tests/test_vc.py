"""Tests for VC generation, verification, and StatusList2021."""

from __future__ import annotations

import base64
import json
import time
from datetime import UTC, datetime, timedelta

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sm_locp.mrr_evaluator import ComplianceStatus, ConditionResult, EvaluationResult
from sm_locp.mrr_loader import MRRCertification, MRRCondition, MRRPolicy
from sm_locp.status_list import StatusList2021, StatusListEntry, verify_status_list_credential
from sm_locp.vc_generator import (
    ComplianceCredential,
    ComplianceCredentialSubject,
    CredentialStatus,
    VCGenerator,
    VCProof,
    reset_vc_generator_state,
)
from sm_locp.vc_verifier import VCVerifier, VerificationResult


# ── helpers ──────────────────────────────────────────────────────────────────

def _make_evaluation(
    rule_id: str = "test-rule",
    status: ComplianceStatus = ComplianceStatus.COMPLIANT,
    confidence: float = 1.0,
) -> EvaluationResult:
    """Build a minimal EvaluationResult for test use."""
    cond = MRRCondition(field="val", operator="==", value=True, required=True)
    return EvaluationResult(
        rule_id=rule_id,
        policy=MRRPolicy(
            rule_id=rule_id,
            agency="TEST",
            cfr_reference="TEST 1.1",
            version="1.0.0",
            title="Test",
            description="test policy",
            conditions=[cond],
            certification=MRRCertification(ttl_seconds=3600),
        ),
        status=status,
        confidence=confidence,
        condition_results=[
            ConditionResult(condition=cond, passed=True, actual_value=True)
        ],
    )


# ── TestVCGenerator ──────────────────────────────────────────────────────────

class TestVCGenerator:
    """Tests for VCGenerator."""

    def test_generate_credential(self, vc_generator: VCGenerator) -> None:
        # Step 1: create a subject
        subject = ComplianceCredentialSubject(
            id="did:web:subject.example",
            rule_id="r1",
            status="COMPLIANT",
            confidence=0.95,
        )
        # Step 2: generate
        cred = vc_generator.generate(subject)
        # Step 3: verify structure
        assert cred.id.startswith("urn:uuid:")
        assert cred.issuer == "did:web:test.stellarminds.ai"
        assert "VerifiableCredential" in cred.type
        assert cred.proof is not None

    def test_sign_and_verify_round_trip(
        self, vc_generator: VCGenerator, vc_verifier: VCVerifier
    ) -> None:
        # Step 1: generate a credential
        subject = ComplianceCredentialSubject(
            id="did:web:test.stellarminds.ai",
            rule_id="round-trip",
            status="COMPLIANT",
            confidence=1.0,
        )
        cred = vc_generator.generate(subject)
        # Step 2: verify it
        result = vc_verifier.verify(cred.to_dict(), check_expiration=False)
        # Step 3: should be valid
        assert result.valid is True
        assert result.signature_valid is True

    def test_generate_from_evaluation(self, vc_generator: VCGenerator) -> None:
        # Step 1: create an evaluation result
        ev = _make_evaluation()
        # Step 2: generate credential from it
        cred = vc_generator.generate_from_evaluation(ev)
        # Step 3: verify fields
        assert cred.credential_subject.rule_id == "test-rule"
        assert cred.credential_subject.status == "COMPLIANT"

    def test_generate_batch(self, vc_generator: VCGenerator) -> None:
        # Step 1: create mixed evaluations
        compliant = _make_evaluation("r1", ComplianceStatus.COMPLIANT)
        non_compliant = _make_evaluation("r2", ComplianceStatus.NON_COMPLIANT)
        # Step 2: batch generate (only compliant should produce VCs)
        creds = vc_generator.generate_batch([compliant, non_compliant])
        # Step 3: verify
        assert len(creds) == 1
        assert creds[0].credential_subject.rule_id == "r1"

    def test_expired_credential(
        self, vc_generator: VCGenerator, vc_verifier: VCVerifier
    ) -> None:
        # Step 1: generate with 1-second TTL
        subject = ComplianceCredentialSubject(
            id="did:web:test.stellarminds.ai",
            rule_id="exp-test",
            status="COMPLIANT",
            confidence=1.0,
        )
        cred = vc_generator.generate(subject, ttl_seconds=1)
        # Step 2: wait for expiration
        time.sleep(2)
        # Step 3: verify -- should be expired
        result = vc_verifier.verify(cred.to_dict(), check_expiration=True)
        assert result.expired is True
        assert result.valid is False

    def test_credential_structure(self, vc_generator: VCGenerator) -> None:
        # Step 1: generate a credential
        subject = ComplianceCredentialSubject(
            id="did:web:test.stellarminds.ai",
            rule_id="struct-test",
            status="COMPLIANT",
            confidence=0.9,
        )
        cred = vc_generator.generate(subject)
        d = cred.to_dict()
        # Step 2: verify W3C structure
        assert "@context" in d
        assert "https://www.w3.org/2018/credentials/v1" in d["@context"]
        assert "type" in d
        assert "credentialSubject" in d
        assert "issuanceDate" in d
        assert "expirationDate" in d
        assert "proof" in d


# ── TestVCVerifier ───────────────────────────────────────────────────────────

class TestVCVerifier:
    """Tests for VCVerifier."""

    def test_verify_valid(
        self, vc_generator: VCGenerator, vc_verifier: VCVerifier
    ) -> None:
        # Step 1: generate and verify
        subject = ComplianceCredentialSubject(
            id="did:web:test.stellarminds.ai",
            rule_id="valid-test",
            status="COMPLIANT",
            confidence=1.0,
        )
        cred = vc_generator.generate(subject)
        result = vc_verifier.verify(cred.to_dict(), check_expiration=False)
        # Step 2: should pass
        assert result.valid is True

    def test_verify_tampered_fails(
        self, vc_generator: VCGenerator, vc_verifier: VCVerifier
    ) -> None:
        # Step 1: generate credential
        subject = ComplianceCredentialSubject(
            id="did:web:test.stellarminds.ai",
            rule_id="tamper-test",
            status="COMPLIANT",
            confidence=1.0,
        )
        cred = vc_generator.generate(subject)
        data = cred.to_dict()
        # Step 2: tamper with it
        data["credentialSubject"]["status"] = "NON_COMPLIANT"
        # Step 3: verify -- should fail
        result = vc_verifier.verify(data, check_expiration=False)
        assert result.signature_valid is False
        assert result.valid is False

    def test_verify_wrong_key_fails(self, vc_generator: VCGenerator) -> None:
        # Step 1: generate credential
        subject = ComplianceCredentialSubject(
            id="did:web:test.stellarminds.ai",
            rule_id="wrong-key-test",
            status="COMPLIANT",
            confidence=1.0,
        )
        cred = vc_generator.generate(subject)
        # Step 2: create verifier with a different key
        other_key = Ed25519PrivateKey.generate()
        wrong_pub = base64.b64encode(other_key.public_key().public_bytes_raw()).decode("ascii")
        verifier = VCVerifier()
        verifier.register_public_key("did:web:test.stellarminds.ai", wrong_pub)
        # Step 3: verify -- should fail
        result = verifier.verify(cred.to_dict(), check_expiration=False)
        assert result.valid is False

    def test_verify_expired(
        self, vc_generator: VCGenerator, vc_verifier: VCVerifier
    ) -> None:
        # Step 1: generate with 1-second TTL
        subject = ComplianceCredentialSubject(
            id="did:web:test.stellarminds.ai",
            rule_id="expired-test",
            status="COMPLIANT",
            confidence=1.0,
        )
        cred = vc_generator.generate(subject, ttl_seconds=1)
        # Step 2: wait and verify
        time.sleep(2)
        result = vc_verifier.verify(cred.to_dict(), check_expiration=True)
        # Step 3: should be expired
        assert result.expired is True
        assert result.valid is False


# ── TestStatusList2021 ───────────────────────────────────────────────────────

class TestStatusList2021:
    """Tests for StatusList2021."""

    def test_allocate_index(self) -> None:
        # Step 1: allocate an index
        sl = StatusList2021(list_id="test-list", issuer_did="did:web:test")
        idx = sl.allocate_index("urn:uuid:abc")
        # Step 2: verify
        assert idx == 0
        # Step 3: same credential returns same index
        assert sl.allocate_index("urn:uuid:abc") == 0
        # Step 4: different credential gets next index
        assert sl.allocate_index("urn:uuid:def") == 1

    def test_revoke(self) -> None:
        # Step 1: allocate and revoke
        sl = StatusList2021(list_id="test-list", issuer_did="did:web:test")
        sl.allocate_index("urn:uuid:abc")
        result = sl.revoke("urn:uuid:abc", reason="test revocation")
        # Step 2: verify
        assert result is True
        assert sl.is_revoked("urn:uuid:abc") is True
        # Step 3: double-revoke returns False
        assert sl.revoke("urn:uuid:abc") is False

    def test_unrevoke_suspension_only(self) -> None:
        # Step 1: revocation-purpose list does not allow unrevoke
        sl = StatusList2021(list_id="rev-list", issuer_did="did:web:test", purpose="revocation")
        sl.allocate_index("urn:uuid:abc")
        sl.revoke("urn:uuid:abc")
        assert sl.unrevoke("urn:uuid:abc") is False
        # Step 2: suspension-purpose list allows unrevoke
        sl2 = StatusList2021(list_id="sus-list", issuer_did="did:web:test", purpose="suspension")
        sl2.allocate_index("urn:uuid:xyz")
        sl2.revoke("urn:uuid:xyz")
        assert sl2.is_revoked("urn:uuid:xyz") is True
        result = sl2.unrevoke("urn:uuid:xyz")
        assert result is True
        assert sl2.is_revoked("urn:uuid:xyz") is False

    def test_is_revoked(self) -> None:
        # Step 1: unallocated credential
        sl = StatusList2021(list_id="test-list", issuer_did="did:web:test")
        assert sl.is_revoked("urn:uuid:unknown") is False
        # Step 2: allocated but not revoked
        sl.allocate_index("urn:uuid:abc")
        assert sl.is_revoked("urn:uuid:abc") is False
        # Step 3: revoked
        sl.revoke("urn:uuid:abc")
        assert sl.is_revoked("urn:uuid:abc") is True

    def test_get_encoded_list(self) -> None:
        # Step 1: create and encode
        sl = StatusList2021(list_id="test-list", issuer_did="did:web:test")
        encoded = sl.get_encoded_list()
        # Step 2: should be a non-empty base64 string
        assert isinstance(encoded, str)
        assert len(encoded) > 0
        # Step 3: should be decodable
        raw = base64.b64decode(encoded)
        assert len(raw) > 0

    def test_to_credential_dict(self) -> None:
        # Step 1: generate credential dict
        sl = StatusList2021(list_id="test-list", issuer_did="did:web:test")
        sl.allocate_index("urn:uuid:abc")
        d = sl.to_credential_dict()
        # Step 2: verify W3C structure
        assert "StatusList2021Credential" in d["type"]
        assert d["issuer"] == "did:web:test"
        assert "encodedList" in d["credentialSubject"]

    def test_to_credential_dict_signed(self, ed25519_keypair: tuple[str, str]) -> None:
        # Step 1: generate signed credential dict
        private_b64, public_b64 = ed25519_keypair
        sl = StatusList2021(list_id="signed-list", issuer_did="did:web:test")
        sl.allocate_index("urn:uuid:abc")
        d = sl.to_credential_dict(private_key_b64=private_b64)
        # Step 2: should have proof
        assert "proof" in d
        # Step 3: verify signature
        assert verify_status_list_credential(d, public_b64) is True

    def test_verify_status_list_credential(self, ed25519_keypair: tuple[str, str]) -> None:
        # Step 1: create signed status list credential
        private_b64, public_b64 = ed25519_keypair
        sl = StatusList2021(list_id="verify-list", issuer_did="did:web:test")
        sl.allocate_index("urn:uuid:cred1")
        sl.revoke("urn:uuid:cred1")
        d = sl.to_credential_dict(private_key_b64=private_b64)
        # Step 2: verify with correct key
        assert verify_status_list_credential(d, public_b64) is True
        # Step 3: verify with wrong key fails
        other = Ed25519PrivateKey.generate()
        wrong_pub = base64.b64encode(other.public_key().public_bytes_raw()).decode("ascii")
        assert verify_status_list_credential(d, wrong_pub) is False
