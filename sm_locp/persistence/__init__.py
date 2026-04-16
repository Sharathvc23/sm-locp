"""Persistence layer for sm-locp.

Provides a small, stable Protocol surface (``PolicyStore``, ``CredentialStore``,
``StatusListStore``, ``EvaluationStore``) plus an in-memory default. External
backends (filesystem, SQLite, Postgres, curated corpora) implement the same
Protocols — the engine is indifferent.
"""

from __future__ import annotations

from .canonical import canonical_json_bytes, content_hash
from .filesystem import (
    FileSystemCredentialStore,
    FileSystemEvaluationStore,
    FileSystemPersistence,
    FileSystemPolicyStore,
    FileSystemStatusListStore,
)
from .memory import (
    InMemoryCredentialStore,
    InMemoryEvaluationStore,
    InMemoryPersistence,
    InMemoryPolicyStore,
    InMemoryStatusListStore,
)
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
    ContentHash,
    CredentialRecord,
    EvaluationRecord,
    PolicyRecord,
    StatusListRecord,
)

#: Semantic version of the persistence Protocol surface. Major versions are
#: governed by the RFC process described in ``GOVERNANCE.md``. Backends should
#: assert ``PROTOCOL_VERSION.startswith("1.")`` to declare v1 compatibility.
PROTOCOL_VERSION = "1.0.0"

__all__ = [
    "PROTOCOL_VERSION",
    "ContentHash",
    "CredentialRecord",
    "CredentialStore",
    "EvaluationRecord",
    "EvaluationStore",
    "FileSystemCredentialStore",
    "FileSystemEvaluationStore",
    "FileSystemPersistence",
    "FileSystemPolicyStore",
    "FileSystemStatusListStore",
    "InMemoryCredentialStore",
    "InMemoryEvaluationStore",
    "InMemoryPersistence",
    "InMemoryPolicyStore",
    "InMemoryStatusListStore",
    "Persistence",
    "PolicyRecord",
    "PolicyStore",
    "PolicyStoreConflictError",
    "StatusListExhaustedError",
    "StatusListRecord",
    "StatusListStore",
    "canonical_json_bytes",
    "content_hash",
]
