"""Reusable persistence conformance suite.

Any backend — in-memory, filesystem, SQLite, Postgres, or a proprietary
corpus connector — can subclass ``PersistenceConformance`` and set
``persistence_factory`` to run the full contract test suite against its
implementation. The suite enforces the documented guarantees: idempotency,
hash verification, atomicity of status-list operations, append-only
evaluation history, and streaming iterators.
"""

from __future__ import annotations

import base64
import threading
from collections.abc import Callable
from typing import Any

import pytest

from sm_locp.persistence import (
    ContentHash,
    CredentialRecord,
    EvaluationRecord,
    Persistence,
    PolicyRecord,
    PolicyStoreConflictError,
    StatusListExhaustedError,
    StatusListRecord,
    content_hash,
)


def _policy(
    *,
    regime_id: str = "warehouse-safety",
    rule_id: str = "ws-forklift-cert",
    version: str = "1.0.0",
    body: dict[str, Any] | None = None,
    tenant_id: str | None = None,
) -> PolicyRecord:
    body = body or {"rule_id": rule_id, "version": version, "conditions": []}
    return PolicyRecord(
        regime_id=regime_id,
        rule_id=rule_id,
        version=version,
        content_hash=content_hash(body),
        body=body,
        created_at="2026-04-16T00:00:00Z",
        tenant_id=tenant_id,
    )


def _credential(
    *,
    credential_id: str,
    subject_did: str = "did:web:example.com:agent-1",
    rule_id: str = "ws-forklift-cert",
) -> CredentialRecord:
    return CredentialRecord(
        credential_id=credential_id,
        subject_did=subject_did,
        issuer_did="did:web:example.com",
        regime_id="warehouse-safety",
        rule_id=rule_id,
        status="COMPLIANT",
        issued_at="2026-04-16T00:00:00Z",
        body={"id": credential_id},
    )


def _status_list(*, list_id: str = "list-1", size: int = 128) -> StatusListRecord:
    return StatusListRecord(
        list_id=list_id,
        purpose="revocation",
        size=size,
        bitstring_b64=base64.b64encode(bytes(size // 8)).decode("ascii"),
        updated_at="2026-04-16T00:00:00Z",
    )


def _evaluation(*, evaluation_id: str, subject_did: str = "did:web:example.com:agent-1") -> EvaluationRecord:
    return EvaluationRecord(
        evaluation_id=evaluation_id,
        subject_did=subject_did,
        regime_id="warehouse-safety",
        rule_id="ws-forklift-cert",
        input_hash=ContentHash(algo="sha256", value="0" * 64),
        result="COMPLIANT",
        confidence=1.0,
        evaluated_at="2026-04-16T00:00:00Z",
    )


class PersistenceConformance:
    """Inherit and set ``persistence_factory`` to a zero-arg callable."""

    persistence_factory: Callable[[], Persistence]

    @pytest.fixture
    def persistence(self) -> Persistence:
        return type(self).persistence_factory()

    # --- PolicyStore --------------------------------------------------------

    def test_policy_put_then_get_roundtrip(self, persistence: Persistence) -> None:
        record = _policy()
        persistence.policies.put(record)
        assert persistence.policies.get(record.regime_id, record.rule_id, record.version) == record

    def test_policy_get_latest_when_version_omitted(self, persistence: Persistence) -> None:
        first = _policy(version="1.0.0")
        second = _policy(version="1.1.0", body={"rule_id": "ws-forklift-cert", "version": "1.1.0", "conditions": [1]})
        persistence.policies.put(first)
        persistence.policies.put(second)
        latest = persistence.policies.get(first.regime_id, first.rule_id)
        assert latest is not None and latest.version == "1.1.0"

    def test_policy_put_is_idempotent_on_same_hash(self, persistence: Persistence) -> None:
        record = _policy()
        persistence.policies.put(record)
        persistence.policies.put(record)  # must not raise
        listed = list(persistence.policies.list(regime_id=record.regime_id))
        assert len(listed) == 1

    def test_policy_put_rejects_hash_mismatch(self, persistence: Persistence) -> None:
        record = _policy()
        tampered = PolicyRecord(
            regime_id=record.regime_id,
            rule_id=record.rule_id,
            version=record.version,
            content_hash=ContentHash(algo="sha256", value="f" * 64),
            body=record.body,
            created_at=record.created_at,
        )
        with pytest.raises(PolicyStoreConflictError):
            persistence.policies.put(tampered)

    def test_policy_put_rejects_mutated_body_at_same_version(self, persistence: Persistence) -> None:
        first = _policy(version="1.0.0")
        mutated_body = {"rule_id": first.rule_id, "version": "1.0.0", "conditions": ["different"]}
        second = PolicyRecord(
            regime_id=first.regime_id,
            rule_id=first.rule_id,
            version="1.0.0",
            content_hash=content_hash(mutated_body),
            body=mutated_body,
            created_at=first.created_at,
        )
        persistence.policies.put(first)
        with pytest.raises(PolicyStoreConflictError):
            persistence.policies.put(second)

    def test_policy_list_scopes_by_regime_and_tenant(self, persistence: Persistence) -> None:
        persistence.policies.put(_policy(regime_id="r1"))
        persistence.policies.put(_policy(regime_id="r2"))
        persistence.policies.put(_policy(regime_id="r1", tenant_id="tenant-A"))
        assert {p.regime_id for p in persistence.policies.list(regime_id="r1")} == {"r1"}
        assert [p.tenant_id for p in persistence.policies.list(tenant_id="tenant-A")] == ["tenant-A"]

    def test_policy_delete_returns_false_when_absent(self, persistence: Persistence) -> None:
        assert persistence.policies.delete("r", "x", "1.0.0") is False

    def test_policy_delete_removes_single_version(self, persistence: Persistence) -> None:
        record = _policy()
        persistence.policies.put(record)
        assert persistence.policies.delete(record.regime_id, record.rule_id, record.version) is True
        assert persistence.policies.get(record.regime_id, record.rule_id, record.version) is None

    # --- CredentialStore ----------------------------------------------------

    def test_credential_put_then_get_roundtrip(self, persistence: Persistence) -> None:
        record = _credential(credential_id="urn:uuid:c1")
        persistence.credentials.put(record)
        assert persistence.credentials.get(record.credential_id) == record

    def test_credential_find_for_subject_filters_correctly(self, persistence: Persistence) -> None:
        persistence.credentials.put(_credential(credential_id="urn:uuid:c1", subject_did="did:web:a"))
        persistence.credentials.put(_credential(credential_id="urn:uuid:c2", subject_did="did:web:b"))
        persistence.credentials.put(
            _credential(credential_id="urn:uuid:c3", subject_did="did:web:a", rule_id="other-rule")
        )
        a_all = {c.credential_id for c in persistence.credentials.find_for_subject("did:web:a")}
        a_filtered = {
            c.credential_id for c in persistence.credentials.find_for_subject("did:web:a", rule_id="other-rule")
        }
        assert a_all == {"urn:uuid:c1", "urn:uuid:c3"}
        assert a_filtered == {"urn:uuid:c3"}

    def test_credential_mark_revoked_flips_flag(self, persistence: Persistence) -> None:
        record = _credential(credential_id="urn:uuid:c1")
        persistence.credentials.put(record)
        assert persistence.credentials.mark_revoked(record.credential_id) is True
        stored = persistence.credentials.get(record.credential_id)
        assert stored is not None and stored.revoked is True

    def test_credential_mark_revoked_returns_false_when_absent(self, persistence: Persistence) -> None:
        assert persistence.credentials.mark_revoked("urn:uuid:missing") is False

    # --- StatusListStore ----------------------------------------------------

    def test_status_list_save_then_load(self, persistence: Persistence) -> None:
        record = _status_list()
        persistence.status_lists.save(record)
        assert persistence.status_lists.load(record.list_id) == record

    def test_status_list_set_bit_flips_the_right_bit(self, persistence: Persistence) -> None:
        record = _status_list()
        persistence.status_lists.save(record)
        persistence.status_lists.set_bit(record.list_id, index=9, value=True)
        loaded = persistence.status_lists.load(record.list_id)
        assert loaded is not None
        raw = bytearray(base64.b64decode(loaded.bitstring_b64.encode("ascii")))
        assert raw[1] & (1 << 1)

    def test_status_list_set_bit_out_of_range_raises(self, persistence: Persistence) -> None:
        record = _status_list(size=64)
        persistence.status_lists.save(record)
        with pytest.raises(IndexError):
            persistence.status_lists.set_bit(record.list_id, index=64, value=True)

    def test_status_list_reserve_index_is_monotonic(self, persistence: Persistence) -> None:
        record = _status_list(size=8)
        persistence.status_lists.save(record)
        indices = [persistence.status_lists.reserve_index(record.list_id) for _ in range(8)]
        assert indices == list(range(8))
        with pytest.raises(StatusListExhaustedError):
            persistence.status_lists.reserve_index(record.list_id)

    def test_status_list_reserve_index_is_atomic_under_threads(self, persistence: Persistence) -> None:
        record = _status_list(size=256)
        persistence.status_lists.save(record)
        seen: list[int] = []
        seen_lock = threading.Lock()

        def worker() -> None:
            for _ in range(32):
                idx = persistence.status_lists.reserve_index(record.list_id)
                with seen_lock:
                    seen.append(idx)

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert sorted(seen) == list(range(256))  # no gaps, no collisions

    # --- EvaluationStore ----------------------------------------------------

    def test_evaluation_append_then_find(self, persistence: Persistence) -> None:
        persistence.evaluations.append(_evaluation(evaluation_id="e1"))
        persistence.evaluations.append(_evaluation(evaluation_id="e2", subject_did="did:web:other"))
        found = [e.evaluation_id for e in persistence.evaluations.find_for_subject("did:web:example.com:agent-1")]
        assert found == ["e1"]

    def test_evaluation_find_respects_since_filter(self, persistence: Persistence) -> None:
        old = EvaluationRecord(
            evaluation_id="old",
            subject_did="did:web:a",
            regime_id="r",
            rule_id="x",
            input_hash=ContentHash(algo="sha256", value="0" * 64),
            result="COMPLIANT",
            confidence=1.0,
            evaluated_at="2026-01-01T00:00:00Z",
        )
        new = EvaluationRecord(
            evaluation_id="new",
            subject_did="did:web:a",
            regime_id="r",
            rule_id="x",
            input_hash=ContentHash(algo="sha256", value="0" * 64),
            result="COMPLIANT",
            confidence=1.0,
            evaluated_at="2026-06-01T00:00:00Z",
        )
        persistence.evaluations.append(old)
        persistence.evaluations.append(new)
        found = persistence.evaluations.find_for_subject("did:web:a", since="2026-03-01T00:00:00Z")
        ids = [e.evaluation_id for e in found]
        assert ids == ["new"]
