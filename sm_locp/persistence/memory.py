"""In-memory implementation of the persistence Protocol.

Zero dependencies, thread-safe via ``threading.Lock``. Suitable for tests,
quickstarts, and small single-process deployments. Not durable: all state is
lost when the process exits.
"""

from __future__ import annotations

import base64
import threading
from collections.abc import Iterator
from copy import deepcopy

from .canonical import content_hash
from .protocol import (
    CredentialStore,
    EvaluationStore,
    Persistence,
    PolicyStore,
    PolicyStoreConflictError,
    StatusListExhaustedError,
    StatusListStore,
)
from .records import (
    CredentialRecord,
    EvaluationRecord,
    PolicyRecord,
    StatusListRecord,
)


def _policy_key(tenant_id: str | None, regime_id: str, rule_id: str, version: str) -> tuple[str | None, str, str, str]:
    return (tenant_id, regime_id, rule_id, version)


class InMemoryPolicyStore:
    """Dict-backed ``PolicyStore``. Versions are kept in insertion order."""

    def __init__(self) -> None:
        self._records: dict[tuple[str | None, str, str, str], PolicyRecord] = {}
        self._lock = threading.Lock()

    def put(self, record: PolicyRecord) -> None:
        computed = content_hash(record.body)
        if computed != record.content_hash:
            raise PolicyStoreConflictError(
                f"content_hash mismatch for {record.regime_id}/{record.rule_id}@{record.version}: "
                f"record claims {record.content_hash.value} but body hashes to {computed.value}"
            )
        key = _policy_key(record.tenant_id, record.regime_id, record.rule_id, record.version)
        with self._lock:
            existing = self._records.get(key)
            if existing is not None and existing.content_hash != record.content_hash:
                raise PolicyStoreConflictError(
                    f"version {record.version} already exists for {record.regime_id}/{record.rule_id} "
                    f"with a different content hash"
                )
            self._records[key] = record

    def get(
        self,
        regime_id: str,
        rule_id: str,
        version: str | None = None,
    ) -> PolicyRecord | None:
        with self._lock:
            if version is not None:
                for key, rec in self._records.items():
                    if key[1] == regime_id and key[2] == rule_id and key[3] == version:
                        return rec
                return None
            latest: PolicyRecord | None = None
            for key, rec in self._records.items():
                if key[1] == regime_id and key[2] == rule_id:
                    latest = rec
            return latest

    def list(
        self,
        regime_id: str | None = None,
        tenant_id: str | None = None,
    ) -> Iterator[PolicyRecord]:
        with self._lock:
            snapshot = list(self._records.values())
        for rec in snapshot:
            if regime_id is not None and rec.regime_id != regime_id:
                continue
            if tenant_id is not None and rec.tenant_id != tenant_id:
                continue
            yield rec

    def delete(self, regime_id: str, rule_id: str, version: str) -> bool:
        with self._lock:
            for key in list(self._records.keys()):
                if key[1] == regime_id and key[2] == rule_id and key[3] == version:
                    del self._records[key]
                    return True
            return False


class InMemoryCredentialStore:
    """Dict-backed ``CredentialStore`` keyed by credential id."""

    def __init__(self) -> None:
        self._records: dict[str, CredentialRecord] = {}
        self._lock = threading.Lock()

    def put(self, record: CredentialRecord) -> None:
        with self._lock:
            self._records[record.credential_id] = record

    def get(self, credential_id: str) -> CredentialRecord | None:
        with self._lock:
            return self._records.get(credential_id)

    def find_for_subject(
        self,
        subject_did: str,
        rule_id: str | None = None,
    ) -> Iterator[CredentialRecord]:
        with self._lock:
            snapshot = list(self._records.values())
        for rec in snapshot:
            if rec.subject_did != subject_did:
                continue
            if rule_id is not None and rec.rule_id != rule_id:
                continue
            yield rec

    def mark_revoked(self, credential_id: str) -> bool:
        with self._lock:
            existing = self._records.get(credential_id)
            if existing is None:
                return False
            if existing.revoked:
                return True
            # frozen dataclass → rebuild with revoked=True
            self._records[credential_id] = CredentialRecord(
                credential_id=existing.credential_id,
                subject_did=existing.subject_did,
                issuer_did=existing.issuer_did,
                regime_id=existing.regime_id,
                rule_id=existing.rule_id,
                status=existing.status,
                issued_at=existing.issued_at,
                body=deepcopy(existing.body),
                expires_at=existing.expires_at,
                revocation_list_id=existing.revocation_list_id,
                revocation_index=existing.revocation_index,
                revoked=True,
                tenant_id=existing.tenant_id,
            )
            return True


class InMemoryStatusListStore:
    """``StatusListStore`` with atomic bit operations guarded by a lock."""

    def __init__(self) -> None:
        self._records: dict[str, StatusListRecord] = {}
        self._next_index: dict[str, int] = {}
        self._lock = threading.Lock()

    def load(self, list_id: str) -> StatusListRecord | None:
        with self._lock:
            return self._records.get(list_id)

    def save(self, record: StatusListRecord) -> None:
        with self._lock:
            self._records[record.list_id] = record
            self._next_index.setdefault(record.list_id, 0)

    def set_bit(self, list_id: str, index: int, value: bool) -> None:
        with self._lock:
            record = self._records.get(list_id)
            if record is None:
                raise KeyError(f"unknown status list: {list_id}")
            if not 0 <= index < record.size:
                raise IndexError(f"index {index} out of range for list of size {record.size}")
            raw = bytearray(base64.b64decode(record.bitstring_b64.encode("ascii")))
            byte_idx, bit_idx = divmod(index, 8)
            if value:
                raw[byte_idx] |= 1 << bit_idx
            else:
                raw[byte_idx] &= ~(1 << bit_idx) & 0xFF
            updated = StatusListRecord(
                list_id=record.list_id,
                purpose=record.purpose,
                size=record.size,
                bitstring_b64=base64.b64encode(bytes(raw)).decode("ascii"),
                updated_at=record.updated_at,
                signature=record.signature,
                tenant_id=record.tenant_id,
            )
            self._records[list_id] = updated

    def reserve_index(self, list_id: str) -> int:
        with self._lock:
            record = self._records.get(list_id)
            if record is None:
                raise KeyError(f"unknown status list: {list_id}")
            nxt = self._next_index.get(list_id, 0)
            if nxt >= record.size:
                raise StatusListExhaustedError(f"status list {list_id} has no free indices")
            self._next_index[list_id] = nxt + 1
            return nxt


class InMemoryEvaluationStore:
    """Append-only list of ``EvaluationRecord``."""

    def __init__(self) -> None:
        self._records: list[EvaluationRecord] = []
        self._lock = threading.Lock()

    def append(self, record: EvaluationRecord) -> None:
        with self._lock:
            self._records.append(record)

    def find_for_subject(
        self,
        subject_did: str,
        since: str | None = None,
        rule_id: str | None = None,
    ) -> Iterator[EvaluationRecord]:
        with self._lock:
            snapshot = list(self._records)
        for rec in snapshot:
            if rec.subject_did != subject_did:
                continue
            if rule_id is not None and rec.rule_id != rule_id:
                continue
            if since is not None and rec.evaluated_at < since:
                continue
            yield rec


class InMemoryPersistence:
    """Facade bundling the four in-memory stores."""

    def __init__(self) -> None:
        self._policies = InMemoryPolicyStore()
        self._credentials = InMemoryCredentialStore()
        self._status_lists = InMemoryStatusListStore()
        self._evaluations = InMemoryEvaluationStore()

    @property
    def policies(self) -> PolicyStore:
        return self._policies

    @property
    def credentials(self) -> CredentialStore:
        return self._credentials

    @property
    def status_lists(self) -> StatusListStore:
        return self._status_lists

    @property
    def evaluations(self) -> EvaluationStore:
        return self._evaluations


__all__ = [
    "InMemoryCredentialStore",
    "InMemoryEvaluationStore",
    "InMemoryPersistence",
    "InMemoryPolicyStore",
    "InMemoryStatusListStore",
]

# Static checks that the in-memory impls satisfy the Protocols. These would
# fail at import time if the Protocol surface drifted.
_: Persistence = InMemoryPersistence()
_pol: PolicyStore = InMemoryPolicyStore()
_cred: CredentialStore = InMemoryCredentialStore()
_sl: StatusListStore = InMemoryStatusListStore()
_eval: EvaluationStore = InMemoryEvaluationStore()
del _, _pol, _cred, _sl, _eval
