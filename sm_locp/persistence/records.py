"""Immutable record types exchanged across the persistence Protocol boundary.

These dataclasses are the stable wire format between the engine and any
``Store`` implementation. They are intentionally frozen: stores hand out
snapshots, callers never mutate them in place.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class ContentHash:
    """Algorithm-tagged digest. ``algo`` is always ``"sha256"`` in v1."""

    algo: str
    value: str


@dataclass(frozen=True)
class PolicyRecord:
    """A single versioned MRR policy document."""

    regime_id: str
    rule_id: str
    version: str
    content_hash: ContentHash
    body: dict[str, Any]
    created_at: str
    tenant_id: str | None = None


@dataclass(frozen=True)
class CredentialRecord:
    """A stored W3C Verifiable Credential plus queryable metadata."""

    credential_id: str
    subject_did: str
    issuer_did: str
    regime_id: str
    rule_id: str
    status: str
    issued_at: str
    body: dict[str, Any]
    expires_at: str | None = None
    revocation_list_id: str | None = None
    revocation_index: int | None = None
    revoked: bool = False
    tenant_id: str | None = None


@dataclass(frozen=True)
class StatusListRecord:
    """A W3C StatusList2021 bitstring plus its signed wrapper."""

    list_id: str
    purpose: str
    size: int
    bitstring_b64: str
    updated_at: str
    signature: dict[str, Any] | None = None
    tenant_id: str | None = None


@dataclass(frozen=True)
class EvaluationRecord:
    """A point-in-time compliance evaluation, written append-only."""

    evaluation_id: str
    subject_did: str
    regime_id: str
    rule_id: str
    input_hash: ContentHash
    result: str
    confidence: float
    evaluated_at: str
    theory_hash: ContentHash | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    tenant_id: str | None = None
