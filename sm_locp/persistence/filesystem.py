"""Filesystem implementation of the persistence Protocol.

Zero dependencies beyond the stdlib. Intended for single-process deployments,
development, and small standalone agents. Layout under ``root``:

.. code-block:: text

    {root}/
        policies/{regime_id}/{rule_id}@{version}.json       # MRRLoader-compatible
        credentials/{sha256(credential_id)}.json
        status_lists/{list_id}.json
        status_lists/{list_id}.next_index                   # sidecar counter
        evaluations/{sha256(subject_did)}.jsonl             # append-only per subject

Atomicity model
---------------

In-process: a single ``threading.Lock`` per store guards all mutations. File
writes go through a tmp-file + ``os.replace`` to ensure readers never observe
partial documents.

Multi-process: **not supported.** If multiple processes write to the same root,
use a SQL or Redis-backed backend instead. This is documented in
``GOVERNANCE.md``.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
from collections.abc import Iterator
from copy import deepcopy
from pathlib import Path
from typing import Any

from .canonical import canonical_json_bytes, content_hash
from .protocol import (
    CredentialStore,
    EvaluationStore,
    PolicyStore,
    PolicyStoreConflictError,
    StatusListExhaustedError,
    StatusListStore,
)
from .records import (
    ContentHash,
    CredentialRecord,
    EvaluationRecord,
    PolicyRecord,
    StatusListRecord,
)


def _sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def _atomic_write_bytes(path: Path, data: bytes) -> None:
    """Write ``data`` to ``path`` atomically via tmp + ``os.replace``."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_bytes(data)
    os.replace(tmp, path)


def _read_json(path: Path) -> dict[str, Any]:
    data: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    return data


def _write_json(path: Path, body: dict[str, Any]) -> None:
    _atomic_write_bytes(path, canonical_json_bytes(body))


TENANT_BUCKET_DEFAULT = "_default"


def _tenant_bucket(tenant_id: str | None) -> str:
    return f"_t_{_sha256_hex(tenant_id)[:16]}" if tenant_id else TENANT_BUCKET_DEFAULT


class FileSystemPolicyStore:
    """Filesystem-backed ``PolicyStore``.

    Single-tenant (``tenant_id=None``) policies live at
    ``policies/_default/{regime}/{rule}@{version}.json`` — this matches the
    existing ``MRRLoader`` directory layout so an authored policy tree is
    directly readable. Multi-tenant policies are sharded under
    ``policies/_t_{hash}/{regime}/...`` to keep tenant data strictly separated.
    """

    def __init__(self, root: Path) -> None:
        self._root = root / "policies"
        self._lock = threading.Lock()

    def _path(self, tenant_id: str | None, regime_id: str, rule_id: str, version: str) -> Path:
        return self._root / _tenant_bucket(tenant_id) / regime_id / f"{rule_id}@{version}.json"

    def _envelope(self, record: PolicyRecord) -> dict[str, Any]:
        return {
            "regime_id": record.regime_id,
            "rule_id": record.rule_id,
            "version": record.version,
            "content_hash": {"algo": record.content_hash.algo, "value": record.content_hash.value},
            "body": record.body,
            "created_at": record.created_at,
            "tenant_id": record.tenant_id,
        }

    def _from_envelope(self, env: dict[str, Any]) -> PolicyRecord:
        ch = env["content_hash"]
        return PolicyRecord(
            regime_id=env["regime_id"],
            rule_id=env["rule_id"],
            version=env["version"],
            content_hash=ContentHash(algo=ch["algo"], value=ch["value"]),
            body=env["body"],
            created_at=env["created_at"],
            tenant_id=env.get("tenant_id"),
        )

    def put(self, record: PolicyRecord) -> None:
        computed = content_hash(record.body)
        if computed != record.content_hash:
            raise PolicyStoreConflictError(
                f"content_hash mismatch for {record.regime_id}/{record.rule_id}@{record.version}"
            )
        path = self._path(record.tenant_id, record.regime_id, record.rule_id, record.version)
        with self._lock:
            if path.exists():
                existing = self._from_envelope(_read_json(path))
                if existing.content_hash != record.content_hash:
                    raise PolicyStoreConflictError(
                        f"version {record.version} already exists for "
                        f"{record.regime_id}/{record.rule_id} with a different content hash"
                    )
                return
            _write_json(path, self._envelope(record))

    def _candidate_files(self, regime_id: str, rule_id: str) -> list[Path]:
        files: list[Path] = []
        if not self._root.exists():
            return files
        for tenant_dir in self._root.iterdir():
            if not tenant_dir.is_dir():
                continue
            regime_dir = tenant_dir / regime_id
            if regime_dir.is_dir():
                files.extend(sorted(regime_dir.glob(f"{rule_id}@*.json")))
        return files

    def get(
        self,
        regime_id: str,
        rule_id: str,
        version: str | None = None,
    ) -> PolicyRecord | None:
        with self._lock:
            if version is not None:
                for tenant_dir in self._root.iterdir() if self._root.exists() else []:
                    if not tenant_dir.is_dir():
                        continue
                    path = tenant_dir / regime_id / f"{rule_id}@{version}.json"
                    if path.exists():
                        return self._from_envelope(_read_json(path))
                return None
            candidates = self._candidate_files(regime_id, rule_id)
            if not candidates:
                return None
            records = [self._from_envelope(_read_json(p)) for p in candidates]
            # Tie-break ``created_at`` by version so callers get a stable
            # "latest" even when records share a timestamp.
            return max(records, key=lambda r: (r.created_at, r.version))

    def list(
        self,
        regime_id: str | None = None,
        tenant_id: str | None = None,
    ) -> Iterator[PolicyRecord]:
        if not self._root.exists():
            return
        with self._lock:
            if tenant_id is not None:
                tenant_dirs = [self._root / _tenant_bucket(tenant_id)]
            else:
                tenant_dirs = [d for d in self._root.iterdir() if d.is_dir()]
            files: list[Path] = []
            for td in tenant_dirs:
                if not td.is_dir():
                    continue
                regimes = [td / regime_id] if regime_id else [r for r in td.iterdir() if r.is_dir()]
                for rd in regimes:
                    if rd.is_dir():
                        files.extend(sorted(rd.glob("*.json")))
        for f in files:
            try:
                env = _read_json(f)
            except (OSError, json.JSONDecodeError):
                continue
            yield self._from_envelope(env)

    def delete(self, regime_id: str, rule_id: str, version: str) -> bool:
        with self._lock:
            if not self._root.exists():
                return False
            for tenant_dir in self._root.iterdir():
                if not tenant_dir.is_dir():
                    continue
                path = tenant_dir / regime_id / f"{rule_id}@{version}.json"
                if path.exists():
                    path.unlink()
                    return True
            return False


class FileSystemCredentialStore:
    """Filesystem-backed ``CredentialStore`` keyed by sha256(credential_id)."""

    def __init__(self, root: Path) -> None:
        self._root = root / "credentials"
        self._lock = threading.Lock()

    def _path(self, credential_id: str) -> Path:
        return self._root / f"{_sha256_hex(credential_id)}.json"

    def _envelope(self, record: CredentialRecord) -> dict[str, Any]:
        return {
            "credential_id": record.credential_id,
            "subject_did": record.subject_did,
            "issuer_did": record.issuer_did,
            "regime_id": record.regime_id,
            "rule_id": record.rule_id,
            "status": record.status,
            "issued_at": record.issued_at,
            "expires_at": record.expires_at,
            "body": record.body,
            "revocation_list_id": record.revocation_list_id,
            "revocation_index": record.revocation_index,
            "revoked": record.revoked,
            "tenant_id": record.tenant_id,
        }

    def _from_envelope(self, env: dict[str, Any]) -> CredentialRecord:
        return CredentialRecord(
            credential_id=env["credential_id"],
            subject_did=env["subject_did"],
            issuer_did=env["issuer_did"],
            regime_id=env["regime_id"],
            rule_id=env["rule_id"],
            status=env["status"],
            issued_at=env["issued_at"],
            body=env["body"],
            expires_at=env.get("expires_at"),
            revocation_list_id=env.get("revocation_list_id"),
            revocation_index=env.get("revocation_index"),
            revoked=env.get("revoked", False),
            tenant_id=env.get("tenant_id"),
        )

    def put(self, record: CredentialRecord) -> None:
        with self._lock:
            _write_json(self._path(record.credential_id), self._envelope(record))

    def get(self, credential_id: str) -> CredentialRecord | None:
        path = self._path(credential_id)
        with self._lock:
            return self._from_envelope(_read_json(path)) if path.exists() else None

    def find_for_subject(
        self,
        subject_did: str,
        rule_id: str | None = None,
    ) -> Iterator[CredentialRecord]:
        if not self._root.exists():
            return
        with self._lock:
            files = sorted(self._root.glob("*.json"))
        for f in files:
            try:
                env = _read_json(f)
            except (OSError, json.JSONDecodeError):
                continue
            if env.get("subject_did") != subject_did:
                continue
            if rule_id is not None and env.get("rule_id") != rule_id:
                continue
            yield self._from_envelope(env)

    def mark_revoked(self, credential_id: str) -> bool:
        path = self._path(credential_id)
        with self._lock:
            if not path.exists():
                return False
            env = _read_json(path)
            if env.get("revoked"):
                return True
            env["revoked"] = True
            _write_json(path, env)
            return True


class FileSystemStatusListStore:
    """Filesystem-backed ``StatusListStore`` with sidecar counter file."""

    def __init__(self, root: Path) -> None:
        self._root = root / "status_lists"
        self._lock = threading.Lock()

    def _path(self, list_id: str) -> Path:
        return self._root / f"{list_id}.json"

    def _counter_path(self, list_id: str) -> Path:
        return self._root / f"{list_id}.next_index"

    def _envelope(self, record: StatusListRecord) -> dict[str, Any]:
        return {
            "list_id": record.list_id,
            "purpose": record.purpose,
            "size": record.size,
            "bitstring_b64": record.bitstring_b64,
            "updated_at": record.updated_at,
            "signature": record.signature,
            "tenant_id": record.tenant_id,
        }

    def _from_envelope(self, env: dict[str, Any]) -> StatusListRecord:
        return StatusListRecord(
            list_id=env["list_id"],
            purpose=env["purpose"],
            size=env["size"],
            bitstring_b64=env["bitstring_b64"],
            updated_at=env["updated_at"],
            signature=env.get("signature"),
            tenant_id=env.get("tenant_id"),
        )

    def load(self, list_id: str) -> StatusListRecord | None:
        path = self._path(list_id)
        with self._lock:
            return self._from_envelope(_read_json(path)) if path.exists() else None

    def save(self, record: StatusListRecord) -> None:
        with self._lock:
            _write_json(self._path(record.list_id), self._envelope(record))
            counter = self._counter_path(record.list_id)
            if not counter.exists():
                _atomic_write_bytes(counter, b"0")

    def set_bit(self, list_id: str, index: int, value: bool) -> None:
        import base64

        path = self._path(list_id)
        with self._lock:
            if not path.exists():
                raise KeyError(f"unknown status list: {list_id}")
            env = _read_json(path)
            if not 0 <= index < env["size"]:
                raise IndexError(f"index {index} out of range for list of size {env['size']}")
            raw = bytearray(base64.b64decode(env["bitstring_b64"].encode("ascii")))
            byte_idx, bit_idx = divmod(index, 8)
            if value:
                raw[byte_idx] |= 1 << bit_idx
            else:
                raw[byte_idx] &= ~(1 << bit_idx) & 0xFF
            env["bitstring_b64"] = base64.b64encode(bytes(raw)).decode("ascii")
            _write_json(path, env)

    def reserve_index(self, list_id: str) -> int:
        path = self._path(list_id)
        counter = self._counter_path(list_id)
        with self._lock:
            if not path.exists():
                raise KeyError(f"unknown status list: {list_id}")
            env = _read_json(path)
            size = env["size"]
            current = int(counter.read_text(encoding="utf-8")) if counter.exists() else 0
            if current >= size:
                raise StatusListExhaustedError(f"status list {list_id} has no free indices")
            _atomic_write_bytes(counter, str(current + 1).encode("utf-8"))
            return current


class FileSystemEvaluationStore:
    """Filesystem-backed ``EvaluationStore`` sharded by subject DID hash."""

    def __init__(self, root: Path) -> None:
        self._root = root / "evaluations"
        self._lock = threading.Lock()

    def _path(self, subject_did: str) -> Path:
        return self._root / f"{_sha256_hex(subject_did)}.jsonl"

    def _envelope(self, record: EvaluationRecord) -> dict[str, Any]:
        env: dict[str, Any] = {
            "evaluation_id": record.evaluation_id,
            "subject_did": record.subject_did,
            "regime_id": record.regime_id,
            "rule_id": record.rule_id,
            "input_hash": {"algo": record.input_hash.algo, "value": record.input_hash.value},
            "result": record.result,
            "confidence": record.confidence,
            "evaluated_at": record.evaluated_at,
            "metadata": deepcopy(record.metadata),
            "tenant_id": record.tenant_id,
        }
        if record.theory_hash is not None:
            env["theory_hash"] = {"algo": record.theory_hash.algo, "value": record.theory_hash.value}
        return env

    def _from_envelope(self, env: dict[str, Any]) -> EvaluationRecord:
        ih = env["input_hash"]
        th = env.get("theory_hash")
        return EvaluationRecord(
            evaluation_id=env["evaluation_id"],
            subject_did=env["subject_did"],
            regime_id=env["regime_id"],
            rule_id=env["rule_id"],
            input_hash=ContentHash(algo=ih["algo"], value=ih["value"]),
            result=env["result"],
            confidence=env["confidence"],
            evaluated_at=env["evaluated_at"],
            theory_hash=ContentHash(algo=th["algo"], value=th["value"]) if th else None,
            metadata=env.get("metadata") or {},
            tenant_id=env.get("tenant_id"),
        )

    def append(self, record: EvaluationRecord) -> None:
        path = self._path(record.subject_did)
        line = json.dumps(self._envelope(record), sort_keys=True, separators=(",", ":")) + "\n"
        with self._lock:
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("a", encoding="utf-8") as f:
                f.write(line)

    def find_for_subject(
        self,
        subject_did: str,
        since: str | None = None,
        rule_id: str | None = None,
    ) -> Iterator[EvaluationRecord]:
        path = self._path(subject_did)
        if not path.exists():
            return
        with self._lock:
            lines = path.read_text(encoding="utf-8").splitlines()
        for line in lines:
            if not line.strip():
                continue
            env = json.loads(line)
            if rule_id is not None and env.get("rule_id") != rule_id:
                continue
            if since is not None and env.get("evaluated_at", "") < since:
                continue
            yield self._from_envelope(env)


class FileSystemPersistence:
    """Facade bundling filesystem-backed stores rooted at ``root``."""

    def __init__(self, root: Path | str) -> None:
        self._root = Path(root)
        self._root.mkdir(parents=True, exist_ok=True)
        self._policies = FileSystemPolicyStore(self._root)
        self._credentials = FileSystemCredentialStore(self._root)
        self._status_lists = FileSystemStatusListStore(self._root)
        self._evaluations = FileSystemEvaluationStore(self._root)

    @property
    def root(self) -> Path:
        return self._root

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
    "FileSystemCredentialStore",
    "FileSystemEvaluationStore",
    "FileSystemPersistence",
    "FileSystemPolicyStore",
    "FileSystemStatusListStore",
]

