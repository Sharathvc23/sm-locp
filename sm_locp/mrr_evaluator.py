"""MRR (Machine-Readable Regulations) evaluator for LOCP.

Evaluates entity state against MRR policies to determine compliance.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any

from .mrr_loader import MRRCondition, MRRLoader, MRRPolicy

logger = logging.getLogger(__name__)


class ComplianceStatus(Enum):
    """Compliance status for a rule evaluation."""

    COMPLIANT = "COMPLIANT"
    NON_COMPLIANT = "NON_COMPLIANT"
    PARTIAL = "PARTIAL"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    UNKNOWN = "UNKNOWN"


@dataclass
class ConditionResult:
    """Result of evaluating a single condition."""

    condition: MRRCondition
    passed: bool
    actual_value: Any
    message: str = ""


@dataclass
class EvaluationResult:
    """Result of evaluating a policy against state."""

    rule_id: str
    policy: MRRPolicy
    status: ComplianceStatus
    confidence: float
    condition_results: list[ConditionResult]
    evaluated_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    state_snapshot: dict[str, Any] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    # Ruleset binding for verifiability
    policy_hash: str | None = None
    ruleset_hash: str | None = None
    ruleset_version: str | None = None

    @property
    def compliant(self) -> bool:
        """Check if the result indicates compliance."""
        return self.status == ComplianceStatus.COMPLIANT

    @property
    def passed_count(self) -> int:
        """Count of passed conditions."""
        return sum(1 for r in self.condition_results if r.passed)

    @property
    def failed_count(self) -> int:
        """Count of failed required conditions."""
        return sum(1 for r in self.condition_results if not r.passed and r.condition.required)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        result = {
            "rule_id": self.rule_id,
            "agency": self.policy.agency,
            "cfr_reference": self.policy.cfr_reference,
            "title": self.policy.title,
            "status": self.status.value,
            "confidence": self.confidence,
            "evaluated_at": self.evaluated_at.isoformat(),
            "passed_conditions": self.passed_count,
            "total_conditions": len(self.condition_results),
            "condition_results": [
                {
                    "field": r.condition.field,
                    "operator": r.condition.operator,
                    "expected": r.condition.value,
                    "actual": r.actual_value,
                    "passed": r.passed,
                    "required": r.condition.required,
                    "message": r.message,
                }
                for r in self.condition_results
            ],
            "errors": self.errors,
        }
        # Include ruleset binding if present
        if self.policy_hash:
            result["policy_hash"] = self.policy_hash
        if self.ruleset_hash:
            result["ruleset_hash"] = self.ruleset_hash
        if self.ruleset_version:
            result["ruleset_version"] = self.ruleset_version
        return result


class MRREvaluator:
    """Evaluates state against MRR policies."""

    def __init__(self, loader: MRRLoader | None = None) -> None:
        """Initialize the evaluator.

        Args:
            loader: MRRLoader instance. Creates default if not provided.
        """
        self._loader = loader or MRRLoader()

    def evaluate(
        self,
        rule_id: str,
        state: dict[str, Any],
    ) -> EvaluationResult:
        """Evaluate state against a specific policy.

        Args:
            rule_id: The policy rule_id to evaluate.
            state: Dictionary containing the current state data.

        Returns:
            EvaluationResult with compliance status and details.
        """
        policy = self._loader.get(rule_id)
        if not policy:
            return EvaluationResult(
                rule_id=rule_id,
                policy=MRRPolicy(
                    rule_id=rule_id,
                    agency="UNKNOWN",
                    cfr_reference="",
                    version="0.0",
                    title="Unknown Policy",
                    description="",
                    conditions=[],
                ),
                status=ComplianceStatus.UNKNOWN,
                confidence=0.0,
                condition_results=[],
                errors=[f"Policy not found: {rule_id}"],
            )

        return self._evaluate_policy(policy, state)

    def evaluate_all(
        self,
        state: dict[str, Any],
        *,
        agency: str | None = None,
        domain: str | None = None,
        operator_type: str | None = None,
        entity_type: str | None = None,
    ) -> list[EvaluationResult]:
        """Evaluate state against all applicable policies.

        Args:
            state: Dictionary containing the current state data.
            agency: Filter to specific agency.
            domain: Filter to specific domain.
            operator_type: Filter to specific operator type.
            entity_type: Filter to specific entity type.

        Returns:
            List of EvaluationResult for each applicable policy.
        """
        if agency:
            policies = self._loader.get_by_agency(agency)
        else:
            policies = self._loader.get_applicable(
                domain=domain,
                operator_type=operator_type,
                entity_type=entity_type,
            )

        return [self._evaluate_policy(p, state) for p in policies]

    def _evaluate_policy(
        self,
        policy: MRRPolicy,
        state: dict[str, Any],
    ) -> EvaluationResult:
        """Evaluate state against a policy.

        Args:
            policy: The MRRPolicy to evaluate against.
            state: Dictionary containing the current state data.

        Returns:
            EvaluationResult with compliance status and details.
        """
        condition_results: list[ConditionResult] = []
        errors: list[str] = []

        for condition in policy.conditions:
            try:
                result = self._evaluate_condition(condition, state)
                condition_results.append(result)
            except (KeyError, ValueError, TypeError, AttributeError) as e:
                logger.debug("Operation failed", exc_info=True)
                errors.append(f"Error evaluating {condition.field}: {e}")
                condition_results.append(
                    ConditionResult(
                        condition=condition,
                        passed=False,
                        actual_value=None,
                        message=f"Evaluation error: {e}",
                    )
                )

        # Determine overall status
        status = self._determine_status(condition_results)

        # Calculate confidence
        confidence = self._calculate_confidence(condition_results, policy)

        # Compute ruleset binding hashes
        policy_hash = self._loader.get_policy_hash(policy.rule_id)
        ruleset_hash = self._loader.compute_ruleset_hash()
        ruleset_version = self._loader.ruleset_version

        return EvaluationResult(
            rule_id=policy.rule_id,
            policy=policy,
            status=status,
            confidence=confidence,
            condition_results=condition_results,
            state_snapshot=state.copy(),
            errors=errors,
            policy_hash=policy_hash,
            ruleset_hash=ruleset_hash,
            ruleset_version=ruleset_version,
        )

    def _evaluate_condition(
        self,
        condition: MRRCondition,
        state: dict[str, Any],
    ) -> ConditionResult:
        """Evaluate a single condition against state.

        Args:
            condition: The MRRCondition to evaluate.
            state: Dictionary containing the current state data.

        Returns:
            ConditionResult indicating pass/fail and actual value.
        """
        # Get the actual value from state using dot notation
        actual_value = self._get_nested_value(state, condition.field)

        if actual_value is None:
            return ConditionResult(
                condition=condition,
                passed=not condition.required,  # Missing non-required = pass
                actual_value=None,
                message=f"Field not found: {condition.field}",
            )

        # Evaluate the operator
        passed = self._apply_operator(condition.operator, actual_value, condition.value)

        message = ""
        if not passed:
            message = condition.error_message or f"{condition.field} {condition.operator} {condition.value} failed"

        return ConditionResult(
            condition=condition,
            passed=passed,
            actual_value=actual_value,
            message=message,
        )

    def _get_nested_value(self, data: dict[str, Any], path: str) -> Any:
        """Get a value from nested dict using dot notation.

        Args:
            data: The data dictionary.
            path: Dot-notation path (e.g., "status.level").

        Returns:
            The value at the path, or None if not found.
        """
        parts = path.split(".")
        current = data
        for part in parts:
            if isinstance(current, dict) and part in current:
                current = current[part]
            else:
                return None
        return current

    def _apply_operator(self, operator: str, actual: Any, expected: Any) -> bool:
        """Apply a comparison operator.

        Args:
            operator: The comparison operator.
            actual: The actual value from state.
            expected: The expected value from condition.

        Returns:
            True if the comparison passes.
        """
        try:
            if operator == "==":
                return bool(actual == expected)
            elif operator == "!=":
                return bool(actual != expected)
            elif operator == "<":
                return float(actual) < float(expected)
            elif operator == "<=":
                return float(actual) <= float(expected)
            elif operator == ">":
                return float(actual) > float(expected)
            elif operator == ">=":
                return float(actual) >= float(expected)
            elif operator == "in":
                return actual in expected
            elif operator == "not_in":
                return actual not in expected
            elif operator == "contains":
                return expected in actual
            elif operator == "matches":
                return bool(re.match(expected, str(actual)))
            else:
                logger.warning("Unknown operator: %s", operator)
                return False
        except (TypeError, ValueError) as e:
            logger.warning("Operator %s failed: %s", operator, e)
            return False

    def _determine_status(self, results: list[ConditionResult]) -> ComplianceStatus:
        """Determine overall compliance status from condition results.

        Args:
            results: List of ConditionResult.

        Returns:
            Overall ComplianceStatus.
        """
        if not results:
            return ComplianceStatus.NOT_APPLICABLE

        # Check required conditions
        required_results = [r for r in results if r.condition.required]

        if not required_results:
            return ComplianceStatus.NOT_APPLICABLE

        # All required must pass for COMPLIANT
        required_passed = all(r.passed for r in required_results)
        some_required_passed = any(r.passed for r in required_results)

        if required_passed:
            return ComplianceStatus.COMPLIANT
        elif some_required_passed:
            return ComplianceStatus.PARTIAL
        else:
            return ComplianceStatus.NON_COMPLIANT

    def _calculate_confidence(
        self,
        results: list[ConditionResult],
        policy: MRRPolicy,
    ) -> float:
        """Calculate confidence score for the evaluation.

        Args:
            results: List of ConditionResult.
            policy: The policy being evaluated.

        Returns:
            Confidence score from 0.0 to 1.0.
        """
        if not results:
            return 0.0

        # Weighted average of conditions that passed
        total_weight = sum(r.condition.weight for r in results)
        if total_weight == 0:
            return 0.0

        passed_weight = sum(r.condition.weight for r in results if r.passed)
        base_confidence = passed_weight / total_weight

        # Adjust based on risk model requirements
        risk_model = policy.risk_model
        required_confidence = risk_model.get("confidence_required")
        if required_confidence and base_confidence < required_confidence:
            # Scale confidence relative to requirement
            return float(base_confidence / required_confidence)

        return base_confidence


__all__ = [
    "MRREvaluator",
    "EvaluationResult",
    "ConditionResult",
    "ComplianceStatus",
]
