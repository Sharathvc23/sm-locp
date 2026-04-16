"""W3C StatusList2021 implementation for credential revocation.

Implements: https://w3c-ccg.github.io/vc-status-list-2021/

A StatusList2021Credential is a special Verifiable Credential that contains
a compressed bitstring. Each credential issued is assigned an index in this
bitstring. If the bit at that index is 1, the credential is revoked.
"""

from __future__ import annotations

import base64
import gzip
import json
import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

logger = logging.getLogger(__name__)

# W3C StatusList2021 constants
STATUS_LIST_2021_CONTEXT = "https://w3id.org/vc/status-list/2021/v1"
W3C_VC_CONTEXT = "https://www.w3.org/2018/credentials/v1"
SM_CONTEXT = "https://stellarminds.ai/ns/did/v1"

# Default list size (supports 131072 credentials per list)
DEFAULT_LIST_SIZE = 131072  # 16 KB when compressed


def _encode_b64(data: bytes) -> str:
    """Base64 encode bytes to string."""
    return base64.b64encode(data).decode("ascii")


def _decode_b64(data: str) -> bytes:
    """Base64 decode string to bytes."""
    return base64.b64decode(data.encode("ascii"))


def _canonical_json(data: dict[str, Any]) -> bytes:
    """Create canonical JSON representation for signing."""
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")


def verify_status_list_credential(credential_data: dict[str, Any], public_key_b64: str) -> bool:
    """Verify the Ed25519 signature on a StatusList2021Credential.

    Extracts the proof, reconstructs the credential without it, computes
    canonical JSON, and verifies the Ed25519 signature.

    Args:
        credential_data: The full credential dictionary (including proof).
        public_key_b64: Base64-encoded Ed25519 public key.

    Returns:
        True if signature is valid, False if signature verification fails.

    Raises:
        ValueError: If credential has no proof or proof has no proofValue
            (structural issues, not signature failures).
    """
    proof = credential_data.get("proof")
    if not proof:
        raise ValueError("No proof in credential")

    signature_b64 = proof.get("proofValue")
    if not signature_b64:
        raise ValueError("No proofValue in proof")

    # Reconstruct credential without proof for verification
    credential_without_proof = {k: v for k, v in credential_data.items() if k != "proof"}
    canonical = _canonical_json(credential_without_proof)

    try:
        public_key = Ed25519PublicKey.from_public_bytes(_decode_b64(public_key_b64))
        signature = _decode_b64(signature_b64)
        public_key.verify(signature, canonical)
        return True
    except InvalidSignature:
        return False


@dataclass
class StatusListEntry:
    """Represents a credential's position in the status list."""

    credential_id: str
    index: int
    purpose: str = "revocation"  # or "suspension"
    revoked: bool = False
    revoked_at: datetime | None = None
    reason: str | None = None


@dataclass
class StatusList2021:
    """A W3C StatusList2021 credential for revocation checking.

    The status list is a gzip-compressed, base64-encoded bitstring.
    Each bit corresponds to a credential index. If bit is 1, credential is revoked.
    """

    list_id: str
    issuer_did: str
    purpose: str = "revocation"
    size: int = DEFAULT_LIST_SIZE
    _bitstring: bytearray = field(default_factory=lambda: bytearray(DEFAULT_LIST_SIZE // 8))
    _entries: dict[str, StatusListEntry] = field(default_factory=dict)
    _next_index: int = 0
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def allocate_index(self, credential_id: str) -> int:
        """Allocate a new index for a credential.

        Args:
            credential_id: The credential ID (e.g., "urn:uuid:...").

        Returns:
            The allocated index.

        Raises:
            ValueError: If list is full or credential already has an index.
        """
        if credential_id in self._entries:
            return self._entries[credential_id].index

        if self._next_index >= self.size:
            raise ValueError(f"Status list {self.list_id} is full")

        index = self._next_index
        self._next_index += 1

        entry = StatusListEntry(
            credential_id=credential_id,
            index=index,
            purpose=self.purpose,
        )
        self._entries[credential_id] = entry

        return index

    def revoke(self, credential_id: str, reason: str | None = None) -> bool:
        """Revoke a credential by setting its bit to 1.

        Args:
            credential_id: The credential ID to revoke.
            reason: Optional reason for revocation.

        Returns:
            True if revoked, False if already revoked or not found.
        """
        entry = self._entries.get(credential_id)
        if not entry:
            return False

        if entry.revoked:
            return False

        # Set the bit
        byte_index = entry.index // 8
        bit_index = entry.index % 8
        self._bitstring[byte_index] |= 1 << (7 - bit_index)

        entry.revoked = True
        entry.revoked_at = datetime.now(UTC)
        entry.reason = reason

        return True

    def unrevoke(self, credential_id: str) -> bool:
        """Unrevoke a credential (only valid for suspension purpose).

        Args:
            credential_id: The credential ID to unrevoke.

        Returns:
            True if unrevoked, False if not found or not revoked.
        """
        if self.purpose != "suspension":
            return False

        entry = self._entries.get(credential_id)
        if not entry or not entry.revoked:
            return False

        # Clear the bit
        byte_index = entry.index // 8
        bit_index = entry.index % 8
        self._bitstring[byte_index] &= ~(1 << (7 - bit_index))

        entry.revoked = False
        entry.revoked_at = None
        entry.reason = None

        return True

    def is_revoked(self, credential_id: str) -> bool:
        """Check if a credential is revoked.

        Args:
            credential_id: The credential ID to check.

        Returns:
            True if revoked, False otherwise.
        """
        entry = self._entries.get(credential_id)
        if not entry:
            return False
        return entry.revoked

    def is_revoked_by_index(self, index: int) -> bool:
        """Check if a credential at given index is revoked.

        Args:
            index: The status list index.

        Returns:
            True if revoked, False otherwise.
        """
        if index < 0 or index >= self.size:
            return False

        byte_index = index // 8
        bit_index = index % 8
        return bool(self._bitstring[byte_index] & (1 << (7 - bit_index)))

    def get_encoded_list(self) -> str:
        """Get the gzip-compressed, base64-encoded bitstring.

        Returns:
            The encoded status list as a string.
        """
        compressed = gzip.compress(bytes(self._bitstring))
        return _encode_b64(compressed)

    def to_credential_dict(
        self,
        private_key_b64: str | None = None,
    ) -> dict[str, Any]:
        """Generate a StatusList2021Credential.

        Args:
            private_key_b64: Optional base64-encoded Ed25519 private key for signing.

        Returns:
            W3C StatusList2021Credential dictionary.
        """
        now = datetime.now(UTC)

        credential: dict[str, Any] = {
            "@context": [
                W3C_VC_CONTEXT,
                STATUS_LIST_2021_CONTEXT,
                SM_CONTEXT,
            ],
            "id": f"https://example.com/api/v1/vc/status/list/{self.list_id}",
            "type": ["VerifiableCredential", "StatusList2021Credential"],
            "issuer": self.issuer_did,
            "issuanceDate": now.isoformat(),
            "credentialSubject": {
                "id": f"https://example.com/api/v1/vc/status/list/{self.list_id}#list",
                "type": "StatusList2021",
                "statusPurpose": self.purpose,
                "encodedList": self.get_encoded_list(),
            },
        }

        # Sign if private key provided
        if private_key_b64:
            credential = self._sign_credential(credential, private_key_b64)

        return credential

    def _sign_credential(
        self,
        credential: dict[str, Any],
        private_key_b64: str,
    ) -> dict[str, Any]:
        """Sign the credential with Ed25519.

        Args:
            credential: The credential dictionary.
            private_key_b64: Base64-encoded Ed25519 private key.

        Returns:
            Signed credential dictionary.
        """
        private_key = Ed25519PrivateKey.from_private_bytes(_decode_b64(private_key_b64))
        now = datetime.now(UTC)

        canonical = _canonical_json(credential)
        signature = private_key.sign(canonical)

        credential["proof"] = {
            "type": "Ed25519Signature2020",
            "verificationMethod": f"{self.issuer_did}#key-1",
            "created": now.isoformat(),
            "proofPurpose": "assertionMethod",
            "proofValue": _encode_b64(signature),
        }

        return credential

    def list_revoked(self) -> list[StatusListEntry]:
        """List all revoked credentials.

        Returns:
            List of revoked StatusListEntry objects.
        """
        return [e for e in self._entries.values() if e.revoked]

    @property
    def revocation_count(self) -> int:
        """Get the number of revoked credentials."""
        return sum(1 for e in self._entries.values() if e.revoked)

    @property
    def allocated_count(self) -> int:
        """Get the number of allocated indices."""
        return len(self._entries)


__all__ = [
    "StatusList2021",
    "StatusListEntry",
    "verify_status_list_credential",
    "STATUS_LIST_2021_CONTEXT",
    "DEFAULT_LIST_SIZE",
]
