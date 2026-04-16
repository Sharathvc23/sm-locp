"""W3C Verifiable Credential verifier for LOCP compliance proofs.

Verifies cryptographic signatures on compliance credentials.
"""

from __future__ import annotations

import base64
import json
import logging
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .vc_generator import ComplianceCredential, ComplianceCredentialSubject, VCProof

logger = logging.getLogger(__name__)


def _decode_b64(data: str) -> bytes:
    """Base64 decode string to bytes."""
    return base64.b64decode(data.encode("ascii"))


def _canonical_json(data: dict[str, Any]) -> bytes:
    """Create canonical JSON representation for verification."""
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")


@dataclass
class VerificationResult:
    """Result of credential verification."""

    valid: bool
    credential: ComplianceCredential | None = None
    issuer: str = ""
    subject_did: str = ""
    rule_id: str = ""
    status: str = ""
    confidence: float = 0.0
    expired: bool = False
    signature_valid: bool = False
    errors: list[Any] | None = None

    def __post_init__(self) -> None:
        if self.errors is None:
            self.errors = []

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "valid": self.valid,
            "issuer": self.issuer,
            "subject_did": self.subject_did,
            "rule_id": self.rule_id,
            "status": self.status,
            "confidence": self.confidence,
            "expired": self.expired,
            "signature_valid": self.signature_valid,
            "errors": self.errors,
        }


class VCVerifier:
    """Verifies W3C Verifiable Credentials for compliance proofs."""

    def __init__(self, public_keys: dict[str, str] | None = None) -> None:
        """Initialize the verifier.

        Args:
            public_keys: Dictionary mapping DID to base64-encoded public key.
                        If not provided, keys must be provided during verification.
        """
        self._public_keys: dict[str, str] = public_keys or {}

    def register_public_key(self, did: str, public_key_b64: str) -> None:
        """Register a public key for a DID.

        Args:
            did: The DID to register.
            public_key_b64: Base64-encoded Ed25519 public key bytes.
        """
        self._public_keys[did] = public_key_b64

    def get_public_key(self, did: str) -> str | None:
        """Look up a registered public key by DID.

        Args:
            did: The DID to look up.

        Returns:
            Base64-encoded public key or None if not registered.
        """
        return self._public_keys.get(did)

    def verify(
        self,
        credential_data: dict[str, Any],
        *,
        public_key_b64: str | None = None,
        check_expiration: bool = True,
    ) -> VerificationResult:
        """Verify a credential from dictionary data.

        Args:
            credential_data: The credential as a dictionary.
            public_key_b64: Optional public key override.
            check_expiration: Whether to check expiration date.

        Returns:
            VerificationResult with verification status and details.
        """
        errors: list = []

        # Parse credential
        try:
            credential = self._parse_credential(credential_data)
        except (KeyError, ValueError, TypeError) as e:
            logger.debug("Returning default due to error", exc_info=True)
            return VerificationResult(
                valid=False,
                errors=[f"Failed to parse credential: {e}"],
            )

        issuer = credential.issuer
        subject = credential.credential_subject

        # Get public key
        key_b64 = public_key_b64 or self._public_keys.get(issuer)
        if not key_b64:
            # Try to extract key from verification method
            if credential.proof and credential.proof.verification_method:
                base_did = credential.proof.verification_method.split("#")[0]
                key_b64 = self._public_keys.get(base_did)

        if not key_b64:
            return VerificationResult(
                valid=False,
                credential=credential,
                issuer=issuer,
                subject_did=subject.id,
                rule_id=subject.rule_id,
                status=subject.status,
                confidence=subject.confidence,
                errors=[f"No public key found for issuer: {issuer}"],
            )

        # Verify signature
        signature_valid = False
        try:
            signature_valid = self._verify_signature(credential_data, key_b64)
        except InvalidSignature:
            errors.append("Invalid signature")
        except (ValueError, TypeError) as e:
            logger.debug("Operation failed", exc_info=True)
            errors.append(f"Signature verification error: {e}")

        # Check expiration
        expired = False
        if check_expiration:
            try:
                exp_str = credential.expiration_date
                if exp_str:
                    exp_dt = datetime.fromisoformat(exp_str.replace("Z", "+00:00"))
                    now = datetime.now(UTC)
                    expired = now > exp_dt
                    if expired:
                        errors.append("Credential has expired")
            except (ValueError, TypeError) as e:
                logger.debug("Operation failed", exc_info=True)
                errors.append(f"Failed to check expiration: {e}")

        # Determine overall validity
        valid = signature_valid and not expired and len(errors) == 0

        return VerificationResult(
            valid=valid,
            credential=credential,
            issuer=issuer,
            subject_did=subject.id,
            rule_id=subject.rule_id,
            status=subject.status,
            confidence=subject.confidence,
            expired=expired,
            signature_valid=signature_valid,
            errors=errors,
        )

    def verify_json(
        self,
        credential_json: str,
        *,
        public_key_b64: str | None = None,
        check_expiration: bool = True,
    ) -> VerificationResult:
        """Verify a credential from JSON string.

        Args:
            credential_json: The credential as a JSON string.
            public_key_b64: Optional public key override.
            check_expiration: Whether to check expiration date.

        Returns:
            VerificationResult with verification status and details.
        """
        try:
            credential_data = json.loads(credential_json)
        except json.JSONDecodeError as e:
            return VerificationResult(
                valid=False,
                errors=[f"Invalid JSON: {e}"],
            )
        return self.verify(
            credential_data,
            public_key_b64=public_key_b64,
            check_expiration=check_expiration,
        )

    def _parse_credential(self, data: dict[str, Any]) -> ComplianceCredential:
        """Parse credential data into ComplianceCredential.

        Args:
            data: The credential dictionary.

        Returns:
            Parsed ComplianceCredential.
        """
        subject_data = data.get("credentialSubject", {})
        subject = ComplianceCredentialSubject(
            id=subject_data.get("id", ""),
            rule_id=subject_data.get("rule_id", ""),
            status=subject_data.get("status", ""),
            confidence=subject_data.get("confidence", 0.0),
            evaluation_state=subject_data.get("evaluation_state", {}),
            agency=subject_data.get("agency", ""),
            cfr_reference=subject_data.get("cfr_reference", ""),
        )

        proof_data = data.get("proof")
        proof = None
        if proof_data:
            proof = VCProof(
                type=proof_data.get("type", ""),
                verification_method=proof_data.get("verificationMethod", ""),
                created=proof_data.get("created", ""),
                proof_purpose=proof_data.get("proofPurpose", ""),
                proof_value=proof_data.get("proofValue", ""),
            )

        return ComplianceCredential(
            context=data.get("@context", []),
            type=data.get("type", []),
            id=data.get("id", ""),
            issuer=data.get("issuer", ""),
            issuance_date=data.get("issuanceDate", ""),
            expiration_date=data.get("expirationDate", ""),
            credential_subject=subject,
            proof=proof,
        )

    def _verify_signature(
        self,
        credential_data: dict[str, Any],
        public_key_b64: str,
    ) -> bool:
        """Verify the Ed25519 signature on a credential.

        Args:
            credential_data: The full credential dictionary.
            public_key_b64: Base64-encoded public key.

        Returns:
            True if signature is valid.

        Raises:
            InvalidSignature: If signature verification fails.
        """
        # Extract proof
        proof_data = credential_data.get("proof")
        if not proof_data:
            raise ValueError("No proof in credential")

        signature_b64 = proof_data.get("proofValue")
        if not signature_b64:
            raise ValueError("No proofValue in proof")

        # Create credential without proof for verification
        credential_without_proof = {k: v for k, v in credential_data.items() if k != "proof"}
        canonical = _canonical_json(credential_without_proof)

        # Verify
        public_key = Ed25519PublicKey.from_public_bytes(_decode_b64(public_key_b64))
        signature = _decode_b64(signature_b64)

        public_key.verify(signature, canonical)
        return True


__all__ = ["VCVerifier", "VerificationResult"]
