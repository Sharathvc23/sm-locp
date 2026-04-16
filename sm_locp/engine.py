"""Defeasible Logic Engine for regulatory reasoning.

Implements:
- Strict rules (always apply)
- Defeasible rules (apply unless defeated)
- Defeaters (block conclusions without asserting opposite)
- Priority-based conflict resolution
- Skeptical reasoning (conclusions must survive all attacks)

This engine is designed for regulatory compliance where rules may have
exceptions, priorities, and complex interactions.

Example:
    >>> theory = (
    ...     RegulatoryTheoryBuilder("ACME")
    ...     .defeasible("R1", ["hazardous_material"], "requires_license", priority=1)
    ...     .defeater("R2", ["small_quantity"], "~requires_license")
    ...     .fact("hazardous_material")
    ...     .fact("small_quantity")
    ...     .build()
    ... )
    >>> result = theory.query(Literal.parse("requires_license"))
    >>> print(result.derived)  # False - defeated by small_quantity exception
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)


class RuleValidationError(ValueError):
    """Raised when a rule fails validation."""


class RuleType(str, Enum):
    """Types of rules in defeasible logic.

    - STRICT: A -> B (always holds if antecedents true)
    - DEFEASIBLE: A => B (holds unless defeated by higher-priority rule)
    - DEFEATER: A ~> ~B (blocks B without asserting ~B)
    """

    STRICT = "strict"
    DEFEASIBLE = "defeasible"
    DEFEATER = "defeater"


@dataclass(frozen=True)
class Literal:
    """A literal (positive or negative fact).

    Attributes:
        predicate: The predicate name (e.g., "requires_license")
        arguments: Arguments to the predicate (e.g., ("ACME", "zone_a"))
        negated: Whether this is a negated literal
    """

    predicate: str
    arguments: tuple[str, ...] = ()
    negated: bool = False

    def __str__(self) -> str:
        """String representation of the literal."""
        base = f"{self.predicate}({', '.join(self.arguments)})" if self.arguments else self.predicate
        return f"\u00ac{base}" if self.negated else base

    def negate(self) -> Literal:
        """Return the negation of this literal."""
        return Literal(self.predicate, self.arguments, not self.negated)

    @classmethod
    def parse(cls, s: str) -> Literal:
        """Parse a literal string.

        Supports formats:
        - "predicate"
        - "predicate(arg1, arg2)"
        - "\u00acpredicate" or "~predicate" or "not_predicate"

        Args:
            s: String representation of literal

        Returns:
            Parsed Literal object
        """
        negated = s.startswith("\u00ac") or s.startswith("~") or s.startswith("not_")
        if negated:
            s = s.lstrip("\u00ac~")
            if s.startswith("not_"):
                s = s[4:]

        if "(" in s:
            predicate, rest = s.split("(", 1)
            args = tuple(arg.strip() for arg in rest.rstrip(")").split(",") if arg.strip())
        else:
            predicate = s
            args = ()

        return cls(predicate.strip(), args, negated)


@dataclass
class Rule:
    """A rule in the defeasible theory.

    Attributes:
        rule_id: Unique identifier for this rule
        rule_type: Type of rule (strict, defeasible, defeater)
        antecedents: List of literals that must be true to fire
        consequent: The conclusion drawn when rule fires
        priority: Higher priority rules defeat lower (for defeasible rules)
        citation: Regulatory citation (e.g., "Section 12.3")
        description: Human-readable description
    """

    rule_id: str
    rule_type: RuleType
    antecedents: list[Literal]
    consequent: Literal
    priority: int = 0
    citation: str = ""
    description: str = ""

    def is_applicable(self, facts: frozenset[Literal]) -> bool:
        """Check if all antecedents are in facts."""
        return all(ant in facts for ant in self.antecedents)

    def content_hash(self) -> str:
        """Hash of rule content for change detection."""
        content = f"{self.rule_id}:{self.rule_type.value}:{self.antecedents}:{self.consequent}"
        return hashlib.sha256(content.encode()).hexdigest()[:16]

    @property
    def regime_prefix(self) -> str:
        """Extract regime prefix from rule_id (e.g., 'DEPT' from 'DEPT-R1')."""
        for sep in ("-", "_", ":"):
            if sep in self.rule_id:
                return self.rule_id.split(sep, 1)[0].upper()
        return self.rule_id.upper()


@dataclass
class DerivationStep:
    """A step in a derivation proof.

    Records which rule was applied and what facts were used.

    Attributes:
        conclusion: The literal that was derived
        rule_applied: The rule that was used
        facts_used: Facts from the knowledge base used in derivation
        timestamp: When this derivation was made
    """

    conclusion: Literal
    rule_applied: Rule
    facts_used: list[Literal]
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))


@dataclass
class QueryResult:
    """Result of querying the defeasible theory.

    Attributes:
        query: The literal that was queried
        derived: Whether the literal was successfully derived
        derivation: Steps taken to derive the conclusion
        confidence: Confidence in the derivation (based on rule priorities)
        blocked_by: If defeated, which rule blocked the derivation
    """

    query: Literal
    derived: bool
    derivation: list[DerivationStep]
    confidence: float
    blocked_by: Rule | None = None

    def as_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "query": str(self.query),
            "derived": self.derived,
            "confidence": round(self.confidence, 4),
            "derivation_steps": len(self.derivation),
            "blocked_by": self.blocked_by.rule_id if self.blocked_by else None,
        }


class DefeasibleTheory:
    """
    A defeasible theory consisting of facts and rules.

    Implements skeptical reasoning: conclusions must survive all possible
    attacks to be accepted. This is appropriate for regulatory compliance
    where we want conservative conclusions.

    Example:
        >>> theory = DefeasibleTheory()
        >>> theory.add_fact(Literal.parse("vehicle"))
        >>> theory.add_rule(Rule(
        ...     "R1", RuleType.DEFEASIBLE,
        ...     [Literal.parse("vehicle")],
        ...     Literal.parse("requires_license")
        ... ))
        >>> result = theory.query(Literal.parse("requires_license"))
        >>> print(result.derived)  # True
    """

    def __init__(self) -> None:
        """Initialize an empty theory."""
        self._facts: set[Literal] = set()
        self._rules: dict[str, Rule] = {}
        self._rule_index: dict[str, list[str]] = {}  # predicate -> rule_ids
        self._conflict_log: list[dict[str, Any]] = []

    def add_fact(self, literal: Literal) -> None:
        """Add a fact to the theory."""
        self._facts.add(literal)

    def add_facts(self, *literals: Literal) -> None:
        """Add multiple facts to the theory."""
        for lit in literals:
            self.add_fact(lit)

    def add_rule(self, rule: Rule) -> None:
        """Add a rule to the theory.

        Raises:
            RuleValidationError: If rule_id is empty, consequent predicate is
                empty, or a defeasible rule has negative priority.
        """
        if not rule.rule_id:
            raise RuleValidationError("rule_id must not be empty")
        if not rule.consequent.predicate:
            raise RuleValidationError(f"Rule {rule.rule_id}: consequent predicate must not be empty")
        if rule.rule_type == RuleType.DEFEASIBLE and rule.priority < 0:
            raise RuleValidationError(f"Rule {rule.rule_id}: defeasible rules must have non-negative priority")

        # Detect conflicting strict rules (same consequent, opposite polarity)
        if rule.rule_type == RuleType.STRICT:
            neg = rule.consequent.negate()
            for existing in self._rules.values():
                if existing.rule_type == RuleType.STRICT and existing.consequent == neg:
                    raise RuleValidationError(
                        f"Rule {rule.rule_id}: conflicts with strict rule {existing.rule_id} "
                        f"(contradictory consequents: {rule.consequent} vs {existing.consequent})"
                    )

        self._rules[rule.rule_id] = rule

        # Index by consequent predicate for efficient lookup
        predicate = rule.consequent.predicate
        if predicate not in self._rule_index:
            self._rule_index[predicate] = []
        self._rule_index[predicate].append(rule.rule_id)

    def query(self, literal: Literal) -> QueryResult:
        """
        Query if a literal is derivable using skeptical reasoning.

        Args:
            literal: The literal to query

        Returns:
            QueryResult indicating whether derivation succeeded
        """
        # Check for defeat cycles and warn
        cycles = self._detect_rule_cycles()
        if cycles:
            logger.warning(
                "Defeat cycles detected in theory (%d cycle(s)): %s",
                len(cycles),
                [" -> ".join(c) for c in cycles],
            )

        derivation: list[DerivationStep] = []
        facts = frozenset(self._facts)

        # Direct fact check
        if literal in facts:
            return QueryResult(query=literal, derived=True, derivation=[], confidence=1.0)

        # Contradiction check
        if literal.negate() in facts:
            return QueryResult(query=literal, derived=False, derivation=[], confidence=1.0)

        # Try to derive via rules
        derived, derivation, confidence, blocker = self._derive(literal, facts, set())

        return QueryResult(
            query=literal,
            derived=derived,
            derivation=derivation,
            confidence=confidence,
            blocked_by=blocker,
        )

    def _derive(
        self,
        literal: Literal,
        facts: frozenset[Literal],
        visited: set[Literal],
    ) -> tuple[bool, list[DerivationStep], float, Rule | None]:
        """Attempt to derive a literal.

        Args:
            literal: Literal to derive
            facts: Current fact base
            visited: Literals already visited (cycle detection)

        Returns:
            Tuple of (derived, derivation_steps, confidence, blocking_rule)
        """
        if literal in visited:
            return False, [], 0.0, None  # Cycle detection

        visited = visited | {literal}

        # Get applicable rules sorted by priority
        applicable = self._get_applicable_rules(literal, facts)
        if not applicable:
            return False, [], 0.0, None

        # Track the first blocker we encounter
        first_blocker: Rule | None = None

        for rule in applicable:
            if rule.rule_type == RuleType.STRICT:
                # Strict rules always fire if applicable
                if rule.is_applicable(facts):
                    step = DerivationStep(
                        conclusion=literal,
                        rule_applied=rule,
                        facts_used=[a for a in rule.antecedents if a in facts],
                    )
                    return True, [step], 1.0, None

            elif rule.rule_type == RuleType.DEFEASIBLE:
                # Check if defeasible rule is defeated
                if rule.is_applicable(facts):
                    defeated, blocker = self._is_defeated(rule, literal, facts, visited)
                    if defeated:
                        # Remember the first blocker we find
                        if first_blocker is None:
                            first_blocker = blocker
                        continue  # Try next rule

                    step = DerivationStep(
                        conclusion=literal,
                        rule_applied=rule,
                        facts_used=[a for a in rule.antecedents if a in facts],
                    )
                    # Confidence based on priority
                    confidence = 0.8 + (rule.priority / 100) * 0.2
                    return True, [step], min(confidence, 1.0), None

        # If we couldn't derive, return the blocker that prevented derivation
        return False, [], 0.0, first_blocker

    def _get_applicable_rules(
        self,
        literal: Literal,
        facts: frozenset[Literal],
    ) -> list[Rule]:
        """Get rules that could derive this literal, sorted by priority."""
        rule_ids = self._rule_index.get(literal.predicate, [])
        rules = [self._rules[rid] for rid in rule_ids]

        # Filter to matching consequent (handles negation correctly)
        matching = [r for r in rules if r.consequent == literal]

        # Sort by priority (high first), then by type (strict first)
        type_order = {RuleType.STRICT: 0, RuleType.DEFEASIBLE: 1, RuleType.DEFEATER: 2}
        return sorted(matching, key=lambda r: (-r.priority, type_order[r.rule_type]))

    def _is_defeated(
        self,
        rule: Rule,
        literal: Literal,
        facts: frozenset[Literal],
        visited: set[Literal],
    ) -> tuple[bool, Rule | None]:
        """Check if a defeasible rule is defeated.

        A rule is defeated if:
        1. A defeater for the negated conclusion is applicable
        2. A higher-priority defeasible rule for the negated conclusion is applicable
        3. A strict rule for the negated conclusion is applicable

        Args:
            rule: The rule to check
            literal: The conclusion we're trying to derive
            facts: Current fact base
            visited: Literals already visited

        Returns:
            Tuple of (is_defeated, blocking_rule)
        """
        neg_literal = literal.negate()
        attacking_rules = self._get_applicable_rules(neg_literal, facts)

        for attacker in attacking_rules:
            if not attacker.is_applicable(facts):
                continue

            # Defeaters always block (that's their purpose)
            if attacker.rule_type == RuleType.DEFEATER:
                self._record_conflict(rule, attacker, literal, "defeater_blocked")
                return True, attacker

            # Higher priority defeasible rules defeat lower priority ones
            if attacker.rule_type == RuleType.DEFEASIBLE and attacker.priority > rule.priority:
                self._record_conflict(rule, attacker, literal, "higher_priority")
                return True, attacker

            # Strict rules always win over defeasible rules
            if attacker.rule_type == RuleType.STRICT:
                self._record_conflict(rule, attacker, literal, "strict_override")
                return True, attacker

        return False, None

    def get_facts(self) -> set[Literal]:
        """Get all facts in the theory."""
        return set(self._facts)

    def get_rules(self) -> list[Rule]:
        """Get all rules in the theory."""
        return list(self._rules.values())

    @property
    def conflict_log(self) -> list[dict[str, Any]]:
        """Return the recorded conflict log."""
        return list(self._conflict_log)

    def _record_conflict(
        self,
        defeated_rule: Rule,
        attacker: Rule,
        literal: Literal,
        reason: str,
    ) -> None:
        """Record a conflict resolution to the internal log.

        Conflicts arise when two regulatory authorities produce contradictory
        conclusions. The defeasible engine resolves these by priority:
        higher-priority rules defeat lower ones, and strict rules always
        win over defeasible rules.
        """
        conflict = {
            "defeated_rule_id": defeated_rule.rule_id,
            "attacker_rule_id": attacker.rule_id,
            "literal": str(literal),
            "defeated_priority": defeated_rule.priority,
            "attacker_priority": attacker.priority,
            "defeated_citation": defeated_rule.citation,
            "attacker_citation": attacker.citation,
            "reason": reason,
        }
        self._conflict_log.append(conflict)

    def _detect_rule_cycles(self) -> list[list[str]]:
        """Detect cycles in the defeat relation between rules.

        Walks the defeat graph: rule A has an edge to rule B if A could
        defeat B (opposite consequent and higher priority).
        Returns a list of cycle paths (each a list of rule_ids).
        """
        # Build adjacency: for each defeasible rule, find rules that defeat it
        defeat_edges: dict[str, list[str]] = {rid: [] for rid in self._rules}

        for rid, rule in self._rules.items():
            if rule.rule_type != RuleType.DEFEASIBLE:
                continue
            neg = rule.consequent.negate()
            for other_id, other in self._rules.items():
                if other_id == rid:
                    continue
                if other.consequent != neg:
                    continue
                # Check if other could defeat rule
                if (
                    other.rule_type == RuleType.DEFEATER
                    or (other.rule_type == RuleType.DEFEASIBLE and other.priority > rule.priority)
                ):
                    defeat_edges[rid].append(other_id)

        # DFS cycle detection
        cycles: list[list[str]] = []
        visited: set[str] = set()
        on_stack: set[str] = set()
        path: list[str] = []

        def _dfs(node: str) -> None:
            visited.add(node)
            on_stack.add(node)
            path.append(node)

            for neighbor in defeat_edges.get(node, []):
                if neighbor not in visited:
                    _dfs(neighbor)
                elif neighbor in on_stack:
                    # Found cycle -- extract from path
                    cycle_start = path.index(neighbor)
                    cycles.append(path[cycle_start:] + [neighbor])

            path.pop()
            on_stack.discard(node)

        for rid in self._rules:
            if rid not in visited:
                _dfs(rid)

        return cycles

    def clear_facts(self) -> None:
        """Clear all facts (keep rules)."""
        self._facts.clear()


class RegulatoryTheoryBuilder:
    """Helper for building regulatory theories with fluent API.

    Example:
        >>> theory = (
        ...     RegulatoryTheoryBuilder("DEPT")
        ...     .strict("R1", ["violation"], "penalty_required",
        ...             citation="Section 1.80")
        ...     .defeasible("R2", ["first_offense"], "warning_only",
        ...                 priority=5, citation="Section 1.80(b)")
        ...     .fact("violation")
        ...     .fact("first_offense")
        ...     .build()
        ... )
    """

    def __init__(self, authority: str = "") -> None:
        """Initialize the builder.

        Args:
            authority: Regulatory authority name (e.g., "DEPT-A", "AGENCY-B")
        """
        self._authority = authority
        self._theory = DefeasibleTheory()

    def strict(
        self,
        rule_id: str,
        antecedents: list[str],
        consequent: str,
        *,
        citation: str = "",
        description: str = "",
    ) -> RegulatoryTheoryBuilder:
        """Add a strict rule.

        Strict rules always derive their consequent when antecedents are true.
        """
        self._theory.add_rule(
            Rule(
                rule_id=rule_id,
                rule_type=RuleType.STRICT,
                antecedents=[Literal.parse(a) for a in antecedents],
                consequent=Literal.parse(consequent),
                citation=citation or f"{self._authority} {rule_id}",
                description=description,
            )
        )
        return self

    def defeasible(
        self,
        rule_id: str,
        antecedents: list[str],
        consequent: str,
        *,
        priority: int = 0,
        citation: str = "",
        description: str = "",
    ) -> RegulatoryTheoryBuilder:
        """Add a defeasible rule.

        Defeasible rules derive their consequent unless defeated by a
        higher-priority rule or defeater.
        """
        self._theory.add_rule(
            Rule(
                rule_id=rule_id,
                rule_type=RuleType.DEFEASIBLE,
                antecedents=[Literal.parse(a) for a in antecedents],
                consequent=Literal.parse(consequent),
                priority=priority,
                citation=citation or f"{self._authority} {rule_id}",
                description=description,
            )
        )
        return self

    def defeater(
        self,
        rule_id: str,
        antecedents: list[str],
        consequent: str,
        *,
        citation: str = "",
        description: str = "",
    ) -> RegulatoryTheoryBuilder:
        """Add a defeater.

        Defeaters block a conclusion without asserting the opposite.
        They're used for exceptions that prevent a rule from firing.
        """
        self._theory.add_rule(
            Rule(
                rule_id=rule_id,
                rule_type=RuleType.DEFEATER,
                antecedents=[Literal.parse(a) for a in antecedents],
                consequent=Literal.parse(consequent),
                citation=citation or f"{self._authority} {rule_id}",
                description=description,
            )
        )
        return self

    def fact(self, literal_str: str) -> RegulatoryTheoryBuilder:
        """Add a fact to the theory."""
        self._theory.add_fact(Literal.parse(literal_str))
        return self

    def facts(self, *literals: str) -> RegulatoryTheoryBuilder:
        """Add multiple facts to the theory."""
        for lit in literals:
            self._theory.add_fact(Literal.parse(lit))
        return self

    def build(self) -> DefeasibleTheory:
        """Return the constructed theory."""
        return self._theory


__all__ = [
    "DefeasibleTheory",
    "DerivationStep",
    "Literal",
    "QueryResult",
    "RegulatoryTheoryBuilder",
    "Rule",
    "RuleType",
    "RuleValidationError",
]
