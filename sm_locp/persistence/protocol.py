"""The persistence Protocol surface — v1.

Any backend that satisfies these Protocols is pluggable into the OCP engine.
The interface is intentionally small: four stores, a bundling facade, and
explicit atomicity requirements on the status-list operations.

Implementations MUST honour the contract documented on each method:

* ``PolicyStore.put`` is idempotent on ``(regime_id, rule_id, version,
  content_hash)`` — replaying the same record is a no-op.
* ``StatusListStore.set_bit`` and ``reserve_index`` are atomic.
* ``list(...)`` / ``find_for_subject(...)`` return iterators — implementers
  stream results and callers must not assume bounded memory.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Protocol, runtime_checkable

from .records import (
    CredentialRecord,
    EvaluationRecord,
    PolicyRecord,
    StatusListRecord,
)


class PolicyStoreConflictError(Exception):
    """Raised when ``PolicyStore.put`` receives a mutated body at an existing version."""


class StatusListExhaustedError(Exception):
    """Raised when ``StatusListStore.reserve_index`` has no free indices left."""


@runtime_checkable
class PolicyStore(Protocol):
    """Versioned, content-addressed store of MRR policies."""

    def put(self, record: PolicyRecord) -> None:
        """Persist ``record``. Idempotent when the content hash matches."""

    def get(
        self,
        regime_id: str,
        rule_id: str,
        version: str | None = None,
    ) -> PolicyRecord | None:
        """Return a specific version, or the latest if ``version`` is ``None``."""

    def list(
        self,
        regime_id: str | None = None,
        tenant_id: str | None = None,
    ) -> Iterator[PolicyRecord]:
        """Stream records, optionally scoped by regime and/or tenant."""

    def delete(self, regime_id: str, rule_id: str, version: str) -> bool:
        """Remove a specific version. Returns ``True`` if a record was deleted."""


@runtime_checkable
class CredentialStore(Protocol):
    """Store of issued W3C Verifiable Credentials."""

    def put(self, record: CredentialRecord) -> None:
        """Persist a newly-issued credential."""

    def get(self, credential_id: str) -> CredentialRecord | None:
        """Return the credential by its VC ``id`` URI, or ``None`` if unknown."""

    def find_for_subject(
        self,
        subject_did: str,
        rule_id: str | None = None,
    ) -> Iterator[CredentialRecord]:
        """Stream credentials for a subject DID, optionally filtered by rule."""

    def mark_revoked(self, credential_id: str) -> bool:
        """Flag a credential as revoked locally. Returns ``True`` on success.

        Note: bit-level revocation also requires a ``StatusListStore.set_bit``
        call on the referenced list. ``mark_revoked`` is the query-side flag.
        """


@runtime_checkable
class StatusListStore(Protocol):
    """Store for W3C StatusList2021 bitstrings and index reservations."""

    def load(self, list_id: str) -> StatusListRecord | None:
        """Return the current signed status list, or ``None`` if unknown."""

    def save(self, record: StatusListRecord) -> None:
        """Replace the stored status list. Caller holds the signing key."""

    def set_bit(self, list_id: str, index: int, value: bool) -> None:
        """Atomically set a single bit to ``value``. Must be thread-safe."""

    def reserve_index(self, list_id: str) -> int:
        """Atomically allocate the next free index. Raises ``StatusListExhausted``
        when the list is full."""


@runtime_checkable
class EvaluationStore(Protocol):
    """Append-only audit log of compliance evaluations."""

    def append(self, record: EvaluationRecord) -> None:
        """Append a single evaluation. Implementations MUST NOT mutate history."""

    def find_for_subject(
        self,
        subject_did: str,
        since: str | None = None,
        rule_id: str | None = None,
    ) -> Iterator[EvaluationRecord]:
        """Stream evaluations for a subject, optionally filtered by time and rule.

        ``since`` is an ISO-8601 timestamp; implementations filter inclusively.
        """


@runtime_checkable
class Persistence(Protocol):
    """Facade exposing all four stores. Engine components take this, not the individual stores."""

    @property
    def policies(self) -> PolicyStore: ...

    @property
    def credentials(self) -> CredentialStore: ...

    @property
    def status_lists(self) -> StatusListStore: ...

    @property
    def evaluations(self) -> EvaluationStore: ...
