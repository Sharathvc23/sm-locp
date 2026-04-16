"""Tests for MRR loader and evaluator."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from sm_locp.mrr_evaluator import (
    ComplianceStatus,
    ConditionResult,
    EvaluationResult,
    MRREvaluator,
)
from sm_locp.mrr_loader import (
    MRRCertification,
    MRRCondition,
    MRRDataSource,
    MRRLoader,
    MRRPolicy,
)


# ── helpers ──────────────────────────────────────────────────────────────────

def _write_policy(directory: Path, policy: dict) -> Path:
    """Write a policy dict as JSON into *directory* and return the path."""
    path = directory / f"{policy['rule_id']}.json"
    path.write_text(json.dumps(policy), encoding="utf-8")
    return path


def _sample_policy(rule_id: str = "test-rule-1", agency: str = "TEST_AGENCY") -> dict:
    """Return a minimal valid MRR policy dict."""
    return {
        "rule_id": rule_id,
        "agency": agency,
        "cfr_reference": "TEST 100.1",
        "version": "1.0.0",
        "title": "Test Policy",
        "description": "A test policy for unit tests",
        "conditions": [
            {
                "field": "status.level",
                "operator": ">=",
                "value": 5,
                "required": True,
                "weight": 1.0,
                "description": "Level must be >= 5",
            },
            {
                "field": "status.active",
                "operator": "==",
                "value": True,
                "required": True,
                "weight": 0.8,
                "description": "Must be active",
            },
            {
                "field": "status.score",
                "operator": ">=",
                "value": 80,
                "required": False,
                "weight": 0.3,
                "description": "Recommended score",
            },
        ],
        "applicability": {"domain": ["testing"]},
        "certification": {
            "self_certifiable": True,
            "proof_format": "verifiable_credential",
            "ttl_seconds": 600,
        },
    }


# ── TestMRRLoader ────────────────────────────────────────────────────────────

class TestMRRLoader:
    """Tests for MRRLoader."""

    def test_load_file(self, tmp_path: Path) -> None:
        # Step 1: write a policy file
        policy_data = _sample_policy()
        path = _write_policy(tmp_path, policy_data)
        # Step 2: load it
        loader = MRRLoader(policies_path=tmp_path, validate_schema=False)
        policy = loader.load_file(path)
        # Step 3: verify
        assert policy.rule_id == "test-rule-1"
        assert policy.agency == "TEST_AGENCY"
        assert len(policy.conditions) == 3

    def test_load_all(self, tmp_path: Path) -> None:
        # Step 1: write multiple policies
        _write_policy(tmp_path, _sample_policy("rule-a", "AGENCY_A"))
        _write_policy(tmp_path, _sample_policy("rule-b", "AGENCY_B"))
        # Step 2: load all
        loader = MRRLoader(policies_path=tmp_path, validate_schema=False)
        policies = loader.load_all()
        # Step 3: verify
        assert len(policies) == 2
        assert "rule-a" in policies
        assert "rule-b" in policies

    def test_get_by_agency(self, tmp_path: Path) -> None:
        # Step 1: write policies for different agencies
        _write_policy(tmp_path, _sample_policy("r1", "ALPHA"))
        _write_policy(tmp_path, _sample_policy("r2", "ALPHA"))
        _write_policy(tmp_path, _sample_policy("r3", "BETA"))
        # Step 2: filter by agency
        loader = MRRLoader(policies_path=tmp_path, validate_schema=False)
        loader.load_all()
        alpha = loader.get_by_agency("ALPHA")
        # Step 3: verify
        assert len(alpha) == 2
        assert all(p.agency == "ALPHA" for p in alpha)

    def test_compute_ruleset_hash(self, tmp_path: Path) -> None:
        # Step 1: write a policy
        _write_policy(tmp_path, _sample_policy())
        loader = MRRLoader(policies_path=tmp_path, validate_schema=False)
        loader.load_all()
        # Step 2: compute hash
        h = loader.compute_ruleset_hash()
        # Step 3: verify format
        assert h.startswith("sha256:")
        assert len(h) > 10

    def test_get_policy_hash(self, tmp_path: Path) -> None:
        # Step 1: write and load a policy
        _write_policy(tmp_path, _sample_policy("ph-1"))
        loader = MRRLoader(policies_path=tmp_path, validate_schema=False)
        loader.load_all()
        # Step 2: get hash
        h = loader.get_policy_hash("ph-1")
        # Step 3: verify
        assert h is not None
        assert h.startswith("sha256:")

    def test_get_policy_hash_missing(self, tmp_path: Path) -> None:
        # Step 1: empty loader
        loader = MRRLoader(policies_path=tmp_path, validate_schema=False)
        loader.load_all()
        # Step 2: non-existent policy returns None
        assert loader.get_policy_hash("does-not-exist") is None


# ── TestMRREvaluator ─────────────────────────────────────────────────────────

class TestMRREvaluator:
    """Tests for MRREvaluator."""

    @pytest.fixture()
    def evaluator(self, tmp_path: Path) -> MRREvaluator:
        _write_policy(tmp_path, _sample_policy())
        loader = MRRLoader(policies_path=tmp_path, validate_schema=False)
        loader.load_all()
        return MRREvaluator(loader)

    def test_evaluate_compliant(self, evaluator: MRREvaluator) -> None:
        # Step 1: state that satisfies all conditions
        state = {"status": {"level": 10, "active": True, "score": 90}}
        # Step 2: evaluate
        result = evaluator.evaluate("test-rule-1", state)
        # Step 3: should be compliant
        assert result.status == ComplianceStatus.COMPLIANT
        assert result.compliant is True

    def test_evaluate_non_compliant(self, evaluator: MRREvaluator) -> None:
        # Step 1: state that fails all required conditions
        state = {"status": {"level": 1, "active": False, "score": 10}}
        # Step 2: evaluate
        result = evaluator.evaluate("test-rule-1", state)
        # Step 3: should be non-compliant
        assert result.status == ComplianceStatus.NON_COMPLIANT
        assert result.compliant is False

    def test_partial_compliance(self, evaluator: MRREvaluator) -> None:
        # Step 1: state where only some required conditions pass
        state = {"status": {"level": 10, "active": False, "score": 90}}
        # Step 2: evaluate
        result = evaluator.evaluate("test-rule-1", state)
        # Step 3: should be partial
        assert result.status == ComplianceStatus.PARTIAL

    def test_operators(self, tmp_path: Path) -> None:
        """Test all supported comparison operators."""
        operators_and_states: list[tuple[str, object, object, bool]] = [
            ("==", True, True, True),
            ("!=", "a", "b", True),
            ("<", 5, 10, True),
            ("<=", 10, 10, True),
            (">", 15, 10, True),
            (">=", 10, 10, True),
            ("in", "x", ["x", "y"], True),
            ("not_in", "z", ["x", "y"], True),
            ("contains", "abc", "b", True),
            ("matches", "hello123", r"hello\d+", True),
        ]
        for op, actual_val, expected_val, should_pass in operators_and_states:
            policy_data = {
                "rule_id": f"op-{op}",
                "agency": "OP_TEST",
                "cfr_reference": "TEST",
                "version": "1.0.0",
                "conditions": [
                    {"field": "val", "operator": op, "value": expected_val, "required": True, "weight": 1.0}
                ],
            }
            subdir = tmp_path / f"op_{op.replace('<', 'lt').replace('>', 'gt').replace('=', 'eq')}"
            subdir.mkdir(exist_ok=True)
            _write_policy(subdir, policy_data)
            loader = MRRLoader(policies_path=subdir, validate_schema=False)
            loader.load_all()
            ev = MRREvaluator(loader)
            result = ev.evaluate(f"op-{op}", {"val": actual_val})
            assert result.compliant is should_pass, f"Operator {op} failed"

    def test_missing_field(self, evaluator: MRREvaluator) -> None:
        # Step 1: state with missing required field
        state = {"status": {"active": True}}
        # Step 2: evaluate
        result = evaluator.evaluate("test-rule-1", state)
        # Step 3: missing required field -> non-compliant or partial
        assert result.status in (ComplianceStatus.NON_COMPLIANT, ComplianceStatus.PARTIAL)

    def test_confidence_calculation(self, evaluator: MRREvaluator) -> None:
        # Step 1: fully compliant state
        state = {"status": {"level": 10, "active": True, "score": 95}}
        result = evaluator.evaluate("test-rule-1", state)
        # Step 2: confidence should be > 0
        assert result.confidence > 0.0
        # Step 3: confidence should be <= 1.0
        assert result.confidence <= 1.0
