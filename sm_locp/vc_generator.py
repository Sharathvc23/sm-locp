"""W3C Verifiable Credential generator for LOCP compliance proofs.

Generates cryptographically-signed compliance credentials that can be
verified by anyone using the issuer's public key.
"""

from __future__ import annotations

import base64
import json
import logging
import threading
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)

from .mrr_evaluator import EvaluationResult

logger = logging.getLogger(__name__)

# W3C VC contexts
W3C_VC_CONTEXT = "https://www.w3.org/2018/credentials/v1"
W3C_STATUS_LIST_CONTEXT = "https://w3id.org/vc/status-list/2021/v1"
SM_LOCP_CONTEXT = "https://stellarminds.ai/ns/locp/v1"
STATUS_LIST_ENDPOINT = "https://example.com/api/v1/vc/status"


def _encode_b64(data: bytes) -> str:
    """Base64 encode bytes to string."""
    return base64.b64encode(data).decode("ascii")


def _decode_b64(data: str) -> bytes:
    """Base64 decode string to bytes."""
    return base64.b64decode(data.encode("ascii"))


def _canonical_json(data: dict[str, Any]) -> bytes:
    """Create canonical JSON representation for signing."""
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")


@dataclass
class ComplianceCredentialSubject:
    """The subject of a compliance credential."""

    id: str  # DID of the subject
    rule_id: str
    status: str
    confidence: float
    evaluation_state: dict[str, Any] = field(default_factory=dict)
    agency: str = ""
    cfr_reference: str = ""
    # Ruleset binding for verifiability
    ruleset_hash: str | None = None
    ruleset_version: str | None = None
    policy_hash: str | None = None
    evaluated_at: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        result = {
            "id": self.id,
            "rule_id": self.rule_id,
            "status": self.status,
            "confidence": self.confidence,
            "evaluation_state": self.evaluation_state,
            "agency": self.agency,
            "cfr_reference": self.cfr_reference,
        }
        # Include ruleset binding if present
        if self.ruleset_hash:
            result["ruleset_hash"] = self.ruleset_hash
        if self.ruleset_version:
            result["ruleset_version"] = self.ruleset_version
        if self.policy_hash:
            result["policy_hash"] = self.policy_hash
        if self.evaluated_at:
            result["evaluated_at"] = self.evaluated_at
        return result


@dataclass
class VCProof:
    """Ed25519 proof for a Verifiable Credential."""

    type: str = "Ed25519Signature2020"
    verification_method: str = ""
    created: str = ""
    proof_purpose: str = "assertionMethod"
    proof_value: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "type": self.type,
            "verificationMethod": self.verification_method,
            "created": self.created,
            "proofPurpose": self.proof_purpose,
            "proofValue": self.proof_value,
        }


@dataclass
class CredentialStatus:
    """W3C StatusList2021 credential status for revocation checking.

    Implements: https://w3c-ccg.github.io/vc-status-list-2021/

    The status list is a compressed bitstring where each credential
    has a position (statusListIndex). If the bit is 1, the credential
    is revoked.
    """

    id: str  # URL to query status
    type: str = "StatusList2021Entry"
    status_purpose: str = "revocation"  # or "suspension"
    status_list_index: str = ""  # Position in the status list bitstring
    status_list_credential: str = ""  # URL to the StatusList2021Credential

    def to_dict(self) -> dict[str, Any]:
        """Convert to W3C-compliant dictionary."""
        return {
            "id": self.id,
            "type": self.type,
            "statusPurpose": self.status_purpose,
            "statusListIndex": self.status_list_index,
            "statusListCredential": self.status_list_credential,
        }


# Simple in-memory counter for status indices (suitable for dev/test).
_fallback_counter: int = 0
_fallback_lock = threading.Lock()


def _next_status_index() -> int:
    """Get the next status list index using a thread-safe in-memory counter."""
    global _fallback_counter
    with _fallback_lock:
        _fallback_counter += 1
        return _fallback_counter


@dataclass
class ComplianceCredential:
    """A W3C Verifiable Credential for compliance assertion."""

    context: list[str]
    type: list[str]
    id: str
    issuer: str
    issuance_date: str
    expiration_date: str
    credential_subject: ComplianceCredentialSubject
    credential_status: CredentialStatus | None = None
    credential_schema: dict[str, str] | None = None
    proof: VCProof | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary (unsigned)."""
        result: dict[str, Any] = {
            "@context": self.context,
            "type": self.type,
            "id": self.id,
            "issuer": self.issuer,
            "issuanceDate": self.issuance_date,
            "expirationDate": self.expiration_date,
            "credentialSubject": self.credential_subject.to_dict(),
        }
        # Add credentialStatus for revocation checking (W3C StatusList2021)
        if self.credential_status:
            result["credentialStatus"] = self.credential_status.to_dict()
        # Add credentialSchema for validation
        if self.credential_schema:
            result["credentialSchema"] = self.credential_schema
        if self.proof:
            result["proof"] = self.proof.to_dict()
        return result

    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), indent=2)


class VCGenerator:
    """Generates W3C Verifiable Credentials for compliance proofs."""

    def __init__(
        self,
        issuer_did: str,
        private_key_b64: str,
        *,
        default_ttl_seconds: int = 300,
    ) -> None:
        """Initialize the VC generator.

        Args:
            issuer_did: The DID of the issuer.
            private_key_b64: Base64-encoded Ed25519 private key bytes.
            default_ttl_seconds: Default time-to-live for credentials.
        """
        self._issuer_did = issuer_did
        self._private_key = Ed25519PrivateKey.from_private_bytes(_decode_b64(private_key_b64))
        self._public_key = self._private_key.public_key()
        self._default_ttl = default_ttl_seconds

    @property
    def issuer_did(self) -> str:
        """Get the issuer DID."""
        return self._issuer_did

    @property
    def public_key_b64(self) -> str:
        """Get the base64-encoded public key."""
        return _encode_b64(self._public_key.public_bytes_raw())

    def generate_from_evaluation(
        self,
        evaluation: EvaluationResult,
        subject_did: str | None = None,
        ttl_seconds: int | None = None,
    ) -> ComplianceCredential:
        """Generate a credential from an evaluation result.

        Args:
            evaluation: The EvaluationResult to create a credential for.
            subject_did: DID of the subject. Defaults to issuer DID.
            ttl_seconds: Time-to-live in seconds. Defaults to policy's ttl or default.

        Returns:
            Signed ComplianceCredential.
        """
        subject_did = subject_did or self._issuer_did
        ttl = ttl_seconds or evaluation.policy.certification.ttl_seconds or self._default_ttl

        # Extract evaluation state from evaluation
        evaluation_state = {}
        for result in evaluation.condition_results:
            if result.actual_value is not None:
                # Use the field name as key
                key = result.condition.field.replace(".", "_")
                evaluation_state[key] = result.actual_value

        subject = ComplianceCredentialSubject(
            id=subject_did,
            rule_id=evaluation.rule_id,
            status=evaluation.status.value,
            confidence=evaluation.confidence,
            evaluation_state=evaluation_state,
            agency=evaluation.policy.agency,
            cfr_reference=evaluation.policy.cfr_reference,
            # Ruleset binding for verifiability
            ruleset_hash=evaluation.ruleset_hash,
            ruleset_version=evaluation.ruleset_version,
            policy_hash=evaluation.policy_hash,
            evaluated_at=evaluation.evaluated_at.isoformat(),
        )

        return self.generate(subject, ttl_seconds=ttl)

    def generate(
        self,
        subject: ComplianceCredentialSubject,
        ttl_seconds: int | None = None,
        *,
        include_status: bool = True,
    ) -> ComplianceCredential:
        """Generate a signed compliance credential.

        Args:
            subject: The credential subject.
            ttl_seconds: Time-to-live in seconds.
            include_status: Whether to include credentialStatus for revocation.

        Returns:
            Signed ComplianceCredential.
        """
        now = datetime.now(UTC)
        ttl = ttl_seconds or self._default_ttl
        expiration = now + timedelta(seconds=ttl)

        # Generate credential ID using uuid4
        cred_id = f"urn:uuid:{uuid4()}"

        # Build credential status for W3C StatusList2021
        credential_status = None
        if include_status:
            status_index = _next_status_index()
            credential_status = CredentialStatus(
                id=f"{STATUS_LIST_ENDPOINT}/{cred_id}",
                type="StatusList2021Entry",
                status_purpose="revocation",
                status_list_index=str(status_index),
                status_list_credential=f"https://example.com/api/v1/vc/status/list/locp-2026",
            )

        # Build credential schema reference
        credential_schema = {
            "id": "https://stellarminds.ai/schemas/locp/compliance-credential.json",
            "type": "JsonSchema",
        }

        credential = ComplianceCredential(
            context=[W3C_VC_CONTEXT, W3C_STATUS_LIST_CONTEXT, SM_LOCP_CONTEXT],
            type=["VerifiableCredential", "ComplianceCredential"],
            id=cred_id,
            issuer=self._issuer_did,
            issuance_date=now.isoformat(),
            expiration_date=expiration.isoformat(),
            credential_subject=subject,
            credential_status=credential_status,
            credential_schema=credential_schema,
        )

        # Sign the credential
        self._sign_credential(credential)

        return credential

    def _sign_credential(self, credential: ComplianceCredential) -> None:
        """Sign the credential with Ed25519.

        Args:
            credential: The credential to sign (modified in place).
        """
        now = datetime.now(UTC)

        # Create proof structure
        proof = VCProof(
            verification_method=f"{self._issuer_did}#key-1",
            created=now.isoformat(),
        )

        # Get canonical form of credential without proof
        credential_dict = credential.to_dict()
        canonical = _canonical_json(credential_dict)

        # Sign
        signature = self._private_key.sign(canonical)
        proof.proof_value = _encode_b64(signature)

        credential.proof = proof

    def generate_batch(
        self,
        evaluations: list[EvaluationResult],
        subject_did: str | None = None,
    ) -> list[ComplianceCredential]:
        """Generate credentials for multiple evaluation results.

        Args:
            evaluations: List of EvaluationResult.
            subject_did: DID of the subject.

        Returns:
            List of signed ComplianceCredential.
        """
        return [
            self.generate_from_evaluation(e, subject_did=subject_did)
            for e in evaluations
            if e.compliant  # Only generate VCs for compliant results
        ]


def reset_vc_generator_state() -> None:
    """Reset VC generator state for test isolation."""
    global _fallback_counter
    _fallback_counter = 0


__all__ = [
    "VCGenerator",
    "ComplianceCredential",
    "ComplianceCredentialSubject",
    "CredentialStatus",
    "VCProof",
    "W3C_VC_CONTEXT",
    "W3C_STATUS_LIST_CONTEXT",
    "SM_LOCP_CONTEXT",
    "reset_vc_generator_state",
]
