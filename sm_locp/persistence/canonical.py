"""Canonical JSON serialization and content hashing.

All persisted documents (policies, credentials, status lists) are canonicalized
before hashing so that two semantically identical bodies always produce the same
``ContentHash``. Canonical form is sorted keys, no whitespace, UTF-8.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from .records import ContentHash

HASH_ALGO = "sha256"


def canonical_json_bytes(body: dict[str, Any]) -> bytes:
    """Return canonical JSON encoding of ``body`` as UTF-8 bytes.

    Sorted keys and no whitespace so the output is deterministic across runs
    and platforms. This is the same canonicalization used for VC signing.
    """
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")


def content_hash(body: dict[str, Any]) -> ContentHash:
    """Compute ``ContentHash`` over the canonical JSON of ``body``."""
    digest = hashlib.sha256(canonical_json_bytes(body)).hexdigest()
    return ContentHash(algo=HASH_ALGO, value=digest)
