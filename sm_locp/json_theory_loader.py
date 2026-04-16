"""JSON Theory Loader for regulatory compliance.

Loads MRR JSON policies from a directory and converts them to
DefeasibleTheory objects that can be used by the defeasible reasoning engine.

Provides an alternative to building theories programmatically via
RegulatoryTheoryBuilder — useful when rules are authored as JSON files
by policy teams rather than encoded in Python.

Example:
    >>> loader = JsonTheoryLoader()
    >>> manifest = loader.get_manifest()
    >>> print(manifest["DEPT_A"]["strict_rules"])  # Number of strict rules
    >>> theory = loader.load_regime("dept_a")
    >>> result = theory.query(Literal.parse("safety_compliant"))
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .engine import (
    DefeasibleTheory,
    Literal,
    Rule,
    RuleType,
)

logger = logging.getLogger(__name__)


@dataclass
class RulesManifest:
    """Manifest of rules loaded for a regulatory regime."""

    regime: str
    strict_rules: int = 0
    defeasible_rules: int = 0
    defeaters: int = 0
    total_rules: int = 0
    citations: list[str] = field(default_factory=list)
    policy_files: list[str] = field(default_factory=list)
    categories: set[str] = field(default_factory=set)

    def as_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "regime": self.regime,
            "strict_rules": self.strict_rules,
            "defeasible_rules": self.defeasible_rules,
            "defeaters": self.defeaters,
            "total_rules": self.total_rules,
            "citations": self.citations[:20],  # Limit for readability
            "policy_files_count": len(self.policy_files),
            "categories": list(self.categories),
        }


class JsonTheoryLoader:
    """Loads MRR JSON policies and converts to defeasible logic theories.

    The loader scans policies/{regime}/**/*.json and converts
    each MRR policy's conditions into defeasible rules:

    - conditions with required=True -> STRICT rules
    - conditions with required=False -> DEFEASIBLE rules
    - conditions with negation patterns -> DEFEATER rules

    Citations are extracted from the cfr_reference field.
    """

    # Common operators and their logical representations
    OPERATOR_MAP = {
        "==": "equals",
        "!=": "not_equals",
        "<": "less_than",
        "<=": "less_than_or_equal",
        ">": "greater_than",
        ">=": "greater_than_or_equal",
        "in": "in_set",
        "not_in": "not_in_set",
        "contains": "contains",
        "matches": "matches_pattern",
    }

    def __init__(self, policies_dir: str | None = None) -> None:
        """Initialize the JSON theory loader.

        Args:
            policies_dir: Path to policies directory.
                         Defaults to sm_locp/policies relative to this file.
        """
        if policies_dir:
            self.policies_dir = Path(policies_dir)
        else:
            self.policies_dir = Path(__file__).parent / "policies"

        self._cache: dict[str, DefeasibleTheory] = {}
        self._manifests: dict[str, RulesManifest] = {}
        self._discovered_regimes: list[str] | None = None
        logger.info("JsonTheoryLoader initialized with policies_dir=%s", self.policies_dir)

    def _discover_regimes(self) -> list[str]:
        """Discover available regimes by scanning subdirectories of policies_dir.

        Returns:
            List of regime directory names found.
        """
        if self._discovered_regimes is not None:
            return self._discovered_regimes

        if not self.policies_dir.exists():
            self._discovered_regimes = []
            return self._discovered_regimes

        self._discovered_regimes = [
            d.name for d in sorted(self.policies_dir.iterdir()) if d.is_dir() and not d.name.startswith(".")
        ]
        return self._discovered_regimes

    def load_regime(self, regime: str) -> DefeasibleTheory:
        """Load all policies for a regulatory regime.

        Args:
            regime: The regime to load (any subdirectory name under policies_dir)

        Returns:
            DefeasibleTheory containing all rules for the regime

        Raises:
            ValueError: If regime is not recognized
        """
        regime_lower = regime.lower()

        # Check cache first
        if regime_lower in self._cache:
            return self._cache[regime_lower]

        available = self._discover_regimes()
        if regime_lower not in available:
            raise ValueError(f"Unknown regime: {regime}. Valid regimes: {available}")

        regime_dir = self.policies_dir / regime_lower
        if not regime_dir.exists():
            logger.warning("Regime directory not found: %s", regime_dir)
            # Return empty theory rather than failing
            empty_theory = DefeasibleTheory()
            self._cache[regime_lower] = empty_theory
            self._manifests[regime_lower] = RulesManifest(regime=regime.upper())
            return empty_theory

        theory = DefeasibleTheory()
        manifest = RulesManifest(regime=regime.upper())

        # Scan all JSON files recursively
        policy_files = list(regime_dir.rglob("*.json"))
        logger.info("Found %d policy files for %s", len(policy_files), regime)

        for policy_file in policy_files:
            try:
                rules = self._load_policy_file(policy_file, regime_lower, manifest)
                for rule in rules:
                    theory.add_rule(rule)
            except (OSError, json.JSONDecodeError, KeyError, ValueError) as e:
                logger.warning("Failed to load policy file %s: %s", policy_file, e)
                continue

        manifest.total_rules = manifest.strict_rules + manifest.defeasible_rules + manifest.defeaters

        self._cache[regime_lower] = theory
        self._manifests[regime_lower] = manifest

        logger.info(
            "Loaded %d rules for %s: %d strict, %d defeasible, %d defeaters",
            manifest.total_rules,
            regime,
            manifest.strict_rules,
            manifest.defeasible_rules,
            manifest.defeaters,
        )

        return theory

    def _load_policy_file(self, policy_file: Path, regime: str, manifest: RulesManifest) -> list[Rule]:
        """Load rules from a single policy JSON file.

        Args:
            policy_file: Path to the policy JSON file
            regime: The regulatory regime
            manifest: Manifest to update with rule counts

        Returns:
            List of Rule objects extracted from the policy
        """
        with open(policy_file, encoding="utf-8") as f:
            policy = json.load(f)

        rules: list[Rule] = []
        manifest.policy_files.append(str(policy_file.relative_to(self.policies_dir)))

        # Extract citation
        cfr_ref = policy.get("cfr_reference", "")
        if cfr_ref and cfr_ref not in manifest.citations:
            manifest.citations.append(cfr_ref)

        # Extract categories
        categories = policy.get("categories", [])
        manifest.categories.update(categories)

        rule_id_base = policy.get("rule_id", policy_file.stem)
        conditions = policy.get("conditions", [])

        for idx, condition in enumerate(conditions):
            rule = self._condition_to_rule(
                condition=condition,
                rule_id_base=rule_id_base,
                condition_idx=idx,
                cfr_ref=cfr_ref,
                regime=regime,
                policy=policy,
            )
            if rule:
                rules.append(rule)

                # Update manifest counters
                if rule.rule_type == RuleType.STRICT:
                    manifest.strict_rules += 1
                elif rule.rule_type == RuleType.DEFEASIBLE:
                    manifest.defeasible_rules += 1
                elif rule.rule_type == RuleType.DEFEATER:
                    manifest.defeaters += 1

        return rules

    def _condition_to_rule(
        self,
        condition: dict[str, Any],
        rule_id_base: str,
        condition_idx: int,
        cfr_ref: str,
        regime: str,
        policy: dict[str, Any],
    ) -> Rule | None:
        """Convert a single MRR condition to a defeasible rule.

        Args:
            condition: The MRR condition dict
            rule_id_base: Base rule ID from policy
            condition_idx: Index of this condition
            cfr_ref: Reference citation
            regime: Regulatory regime name
            policy: Full policy dict for context

        Returns:
            Rule object, or None if condition cannot be converted
        """
        field_name = condition.get("field", "")
        operator = condition.get("operator", "==")
        value = condition.get("value")
        required = condition.get("required", True)
        description = condition.get("description", "")

        if not field_name:
            return None

        # Create rule ID
        rule_id = f"{rule_id_base}-cond-{condition_idx}"

        # Create antecedent literal from field and operator
        antecedent_predicate = self._field_to_predicate(field_name, operator, value)
        antecedent = Literal.parse(antecedent_predicate)

        # Create consequent based on regime and category
        primary_category = policy.get("primary_category", "general")
        consequent_predicate = f"{regime}_{primary_category}_compliant"
        consequent = Literal.parse(consequent_predicate)

        # Determine rule type based on required flag and operator patterns
        if self._is_defeater_pattern(condition, policy):
            rule_type = RuleType.DEFEATER
            # Defeaters assert negated consequent
            consequent = consequent.negate()
        elif required:
            rule_type = RuleType.STRICT
        else:
            rule_type = RuleType.DEFEASIBLE

        # Priority based on weight
        weight = condition.get("weight", 1.0)
        priority = int(weight * 10)

        return Rule(
            rule_id=rule_id,
            rule_type=rule_type,
            antecedents=[antecedent],
            consequent=consequent,
            priority=priority,
            citation=cfr_ref,
            description=description or policy.get("description", ""),
        )

    def _field_to_predicate(self, field_name: str, operator: str, value: Any) -> str:
        """Convert a field/operator/value condition to a predicate string.

        Args:
            field_name: The field being checked (e.g., "safety.level")
            operator: The operator (e.g., "<", "==")
            value: The comparison value

        Returns:
            Predicate string suitable for Literal.parse()
        """
        # Normalize field name: replace dots with underscores
        normalized_field = field_name.replace(".", "_")

        # Map operator to readable form
        op_name = self.OPERATOR_MAP.get(operator, "matches")

        # Handle boolean values specially
        if isinstance(value, bool):
            if value:
                return normalized_field
            else:
                return f"\u00ac{normalized_field}"

        # Handle numeric comparisons
        if isinstance(value, int | float):
            return f"{normalized_field}_{op_name}_{str(value).replace('.', '_').replace('-', 'neg')}"

        # Handle string values
        if isinstance(value, str):
            safe_value = value.replace(" ", "_").replace("-", "_")[:20]
            return f"{normalized_field}_{op_name}_{safe_value}"

        # Default: just use field name
        return normalized_field

    def _is_defeater_pattern(self, condition: dict[str, Any], policy: dict[str, Any]) -> bool:
        """Determine if a condition represents a defeater (exception/block).

        Defeaters are identified by:
        - Operator being "!=" or "not_in"
        - Field containing "denied", "blocked", "prohibited"
        - Policy keywords containing "exception", "waiver", "exemption"

        Args:
            condition: The condition dict
            policy: The full policy dict

        Returns:
            True if this should be a defeater rule
        """
        field_name = condition.get("field", "").lower()
        operator = condition.get("operator", "")

        # Check for negation operators
        if operator in ("!=", "not_in", "not_contains"):
            return True

        # Check for blocking field names
        blocking_terms = ["denied", "blocked", "prohibited", "excluded", "banned"]
        if any(term in field_name for term in blocking_terms):
            return True

        # Check policy keywords for exception patterns
        keywords = policy.get("keywords", [])
        exception_keywords = ["exception", "waiver", "exemption", "override", "bypass"]
        if any(kw.lower() in str(keywords).lower() for kw in exception_keywords):
            return True

        return False

    def get_manifest(self) -> dict[str, dict[str, Any]]:
        """Return rule counts and citations per regime.

        This method loads all regimes if not already cached and returns
        a comprehensive manifest of the loaded rules.

        Returns:
            Dictionary mapping regime names to their RulesManifest dicts
        """
        # Ensure all regimes are loaded
        for regime in self._discover_regimes():
            if regime not in self._cache:
                try:
                    self.load_regime(regime)
                except (OSError, json.JSONDecodeError, KeyError, ValueError) as e:
                    logger.warning("Could not load regime %s: %s", regime, e)
                    self._manifests[regime] = RulesManifest(regime=regime.upper())

        return {regime.upper(): manifest.as_dict() for regime, manifest in self._manifests.items()}

    def load_all_regimes(self) -> dict[str, DefeasibleTheory]:
        """Load all available regulatory regimes.

        Returns:
            Dictionary mapping regime names to their DefeasibleTheory objects
        """
        theories = {}
        for regime in self._discover_regimes():
            try:
                theories[regime.upper()] = self.load_regime(regime)
            except (OSError, json.JSONDecodeError, KeyError, ValueError) as e:
                logger.warning("Could not load regime %s: %s", regime, e)
                theories[regime.upper()] = DefeasibleTheory()
        return theories

    def get_combined_theory(self, regimes: list[str] | None = None) -> DefeasibleTheory:
        """Create a combined theory from multiple regimes.

        Args:
            regimes: List of regime names to combine. If None, combines all.

        Returns:
            DefeasibleTheory containing rules from all specified regimes
        """
        if regimes is None:
            regimes = self._discover_regimes()

        combined = DefeasibleTheory()

        for regime in regimes:
            try:
                theory = self.load_regime(regime)
                for rule in theory.get_rules():
                    combined.add_rule(rule)
            except (OSError, json.JSONDecodeError, KeyError, ValueError) as e:
                logger.warning("Could not add regime %s to combined theory: %s", regime, e)

        return combined

    def search_policies(
        self,
        query_terms: list[str],
        regime: str | None = None,
        category: str | None = None,
    ) -> list[dict[str, Any]]:
        """Search policies by keywords.

        Args:
            query_terms: Terms to search for
            regime: Optional regime to limit search
            category: Optional category filter

        Returns:
            List of matching policy summaries
        """
        results = []
        regimes_to_search = [regime] if regime else self._discover_regimes()

        for reg in regimes_to_search:
            regime_dir = self.policies_dir / reg
            if not regime_dir.exists():
                continue

            for policy_file in regime_dir.rglob("*.json"):
                try:
                    with open(policy_file) as f:
                        policy = json.load(f)

                    # Check category filter
                    if category and category not in policy.get("categories", []):
                        continue

                    # Check query terms
                    policy_text = json.dumps(policy).lower()
                    if all(term.lower() in policy_text for term in query_terms):
                        results.append(
                            {
                                "rule_id": policy.get("rule_id"),
                                "title": policy.get("title"),
                                "cfr_reference": policy.get("cfr_reference"),
                                "regime": reg.upper(),
                                "category": policy.get("primary_category"),
                                "path": str(policy_file.relative_to(self.policies_dir)),
                            }
                        )
                except (json.JSONDecodeError, OSError, KeyError, ValueError):
                    continue

        return results


def create_theory_from_json(
    policies_dir: str | None = None,
    regimes: list[str] | None = None,
) -> DefeasibleTheory:
    """Convenience function to create a theory from JSON policies.

    Args:
        policies_dir: Path to policies directory
        regimes: Regimes to include (default: all)

    Returns:
        DefeasibleTheory with loaded rules
    """
    loader = JsonTheoryLoader(policies_dir)
    return loader.get_combined_theory(regimes)


__all__ = [
    "JsonTheoryLoader",
    "RulesManifest",
    "create_theory_from_json",
]
