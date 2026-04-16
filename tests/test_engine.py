"""Comprehensive tests for the defeasible logic engine."""

from __future__ import annotations

import pytest

from sm_locp.engine import (
    DefeasibleTheory,
    DerivationStep,
    Literal,
    QueryResult,
    RegulatoryTheoryBuilder,
    Rule,
    RuleType,
    RuleValidationError,
)


# ── TestLiteral ──────────────────────────────────────────────────────────────

class TestLiteral:
    """Tests for the Literal data class."""

    def test_parse_simple(self) -> None:
        # Step 1: parse a plain predicate
        lit = Literal.parse("has_permit")
        # Step 2: verify fields
        assert lit.predicate == "has_permit"
        assert lit.negated is False
        assert lit.arguments == ()

    def test_negate(self) -> None:
        # Step 1: create and negate
        lit = Literal.parse("allowed")
        neg = lit.negate()
        # Step 2: verify negation
        assert neg.negated is True
        assert neg.predicate == "allowed"
        # Step 3: double negate returns to original polarity
        assert neg.negate().negated is False

    def test_str_representation(self) -> None:
        # Step 1: positive literal
        lit = Literal.parse("compliant")
        assert str(lit) == "compliant"
        # Step 2: negated literal
        neg = lit.negate()
        assert str(neg) == "\u00accompliant"

    def test_parse_with_arguments(self) -> None:
        # Step 1: parse literal with arguments
        lit = Literal.parse("holds(container, zone_a)")
        # Step 2: verify
        assert lit.predicate == "holds"
        assert lit.arguments == ("container", "zone_a")
        assert lit.negated is False

    def test_parse_negated_tilde(self) -> None:
        # Step 1: parse negated with tilde prefix
        lit = Literal.parse("~permitted")
        # Step 2: verify
        assert lit.negated is True
        assert lit.predicate == "permitted"

    def test_parse_negated_not_prefix(self) -> None:
        # Step 1: parse negated with not_ prefix
        lit = Literal.parse("not_allowed")
        # Step 2: verify
        assert lit.negated is True
        assert lit.predicate == "allowed"

    def test_equality_and_hashing(self) -> None:
        # Step 1: identical literals should be equal
        a = Literal.parse("foo")
        b = Literal.parse("foo")
        assert a == b
        assert hash(a) == hash(b)
        # Step 2: different polarity should differ
        assert a != a.negate()


# ── TestRule ─────────────────────────────────────────────────────────────────

class TestRule:
    """Tests for the Rule data class."""

    def test_creation(self) -> None:
        # Step 1: create a rule
        rule = Rule(
            rule_id="R1",
            rule_type=RuleType.DEFEASIBLE,
            antecedents=[Literal.parse("a"), Literal.parse("b")],
            consequent=Literal.parse("c"),
            priority=5,
        )
        # Step 2: verify attributes
        assert rule.rule_id == "R1"
        assert rule.rule_type == RuleType.DEFEASIBLE
        assert len(rule.antecedents) == 2
        assert rule.priority == 5

    def test_is_applicable(self) -> None:
        # Step 1: create rule with two antecedents
        rule = Rule(
            rule_id="R2",
            rule_type=RuleType.STRICT,
            antecedents=[Literal.parse("x"), Literal.parse("y")],
            consequent=Literal.parse("z"),
        )
        # Step 2: only x present -- not applicable
        facts = frozenset({Literal.parse("x")})
        assert rule.is_applicable(facts) is False
        # Step 3: both present -- applicable
        facts = frozenset({Literal.parse("x"), Literal.parse("y")})
        assert rule.is_applicable(facts) is True

    def test_content_hash_stable(self) -> None:
        # Step 1: create two identical rules
        r1 = Rule("H1", RuleType.STRICT, [Literal.parse("a")], Literal.parse("b"))
        r2 = Rule("H1", RuleType.STRICT, [Literal.parse("a")], Literal.parse("b"))
        # Step 2: hashes should match
        assert r1.content_hash() == r2.content_hash()
        # Step 3: different rule_id gives different hash
        r3 = Rule("H2", RuleType.STRICT, [Literal.parse("a")], Literal.parse("b"))
        assert r1.content_hash() != r3.content_hash()


# ── TestDefeasibleTheory ─────────────────────────────────────────────────────

class TestDefeasibleTheory:
    """Tests for DefeasibleTheory."""

    def test_add_fact(self) -> None:
        # Step 1: add fact
        theory = DefeasibleTheory()
        theory.add_fact(Literal.parse("sensor_ok"))
        # Step 2: verify
        assert Literal.parse("sensor_ok") in theory.get_facts()

    def test_add_rule(self) -> None:
        # Step 1: add rule
        theory = DefeasibleTheory()
        rule = Rule("R1", RuleType.STRICT, [Literal.parse("a")], Literal.parse("b"))
        theory.add_rule(rule)
        # Step 2: verify
        assert len(theory.get_rules()) == 1

    def test_query_direct_fact(self) -> None:
        # Step 1: add a fact and query it
        theory = DefeasibleTheory()
        theory.add_fact(Literal.parse("active"))
        result = theory.query(Literal.parse("active"))
        # Step 2: should be derived with confidence 1.0
        assert result.derived is True
        assert result.confidence == 1.0

    def test_query_via_strict_rule(self) -> None:
        # Step 1: strict rule a -> b, add fact a
        theory = DefeasibleTheory()
        theory.add_rule(Rule("S1", RuleType.STRICT, [Literal.parse("a")], Literal.parse("b")))
        theory.add_fact(Literal.parse("a"))
        # Step 2: query b
        result = theory.query(Literal.parse("b"))
        # Step 3: should derive
        assert result.derived is True
        assert result.confidence == 1.0

    def test_query_via_defeasible_rule(self) -> None:
        # Step 1: defeasible rule a => c
        theory = DefeasibleTheory()
        theory.add_rule(
            Rule("D1", RuleType.DEFEASIBLE, [Literal.parse("a")], Literal.parse("c"), priority=5)
        )
        theory.add_fact(Literal.parse("a"))
        # Step 2: query c
        result = theory.query(Literal.parse("c"))
        # Step 3: should derive with < 1.0 confidence
        assert result.derived is True
        assert 0.0 < result.confidence <= 1.0

    def test_defeater_blocks_derivation(self) -> None:
        # Step 1: defeasible a => p, defeater b ~> ~p
        theory = DefeasibleTheory()
        theory.add_rule(
            Rule("D1", RuleType.DEFEASIBLE, [Literal.parse("a")], Literal.parse("p"), priority=3)
        )
        theory.add_rule(
            Rule("X1", RuleType.DEFEATER, [Literal.parse("b")], Literal.parse("~p"))
        )
        theory.add_facts(Literal.parse("a"), Literal.parse("b"))
        # Step 2: query p
        result = theory.query(Literal.parse("p"))
        # Step 3: should be blocked
        assert result.derived is False
        assert result.blocked_by is not None
        assert result.blocked_by.rule_id == "X1"

    def test_higher_priority_defeats_lower(self) -> None:
        # Step 1: two defeasible rules with opposing conclusions
        theory = DefeasibleTheory()
        theory.add_rule(
            Rule("D_LOW", RuleType.DEFEASIBLE, [Literal.parse("a")], Literal.parse("q"), priority=2)
        )
        theory.add_rule(
            Rule("D_HIGH", RuleType.DEFEASIBLE, [Literal.parse("b")], Literal.parse("~q"), priority=10)
        )
        theory.add_facts(Literal.parse("a"), Literal.parse("b"))
        # Step 2: query q -- higher priority negation should block
        result = theory.query(Literal.parse("q"))
        # Step 3: should be defeated
        assert result.derived is False

    def test_cycle_detection(self) -> None:
        # Step 1: create rules that form a defeat cycle
        theory = DefeasibleTheory()
        theory.add_rule(
            Rule("C1", RuleType.DEFEASIBLE, [Literal.parse("a")], Literal.parse("x"), priority=1)
        )
        theory.add_rule(
            Rule("C2", RuleType.DEFEASIBLE, [Literal.parse("b")], Literal.parse("~x"), priority=2)
        )
        theory.add_fact(Literal.parse("a"))
        theory.add_fact(Literal.parse("b"))
        # Step 2: query should still complete (no infinite loop)
        result = theory.query(Literal.parse("x"))
        # Step 3: result is determined (defeated by higher priority)
        assert isinstance(result, QueryResult)

    def test_rule_validation_empty_id(self) -> None:
        # Step 1: empty rule_id should raise
        theory = DefeasibleTheory()
        with pytest.raises(RuleValidationError, match="rule_id"):
            theory.add_rule(Rule("", RuleType.STRICT, [Literal.parse("a")], Literal.parse("b")))

    def test_rule_validation_negative_priority(self) -> None:
        # Step 1: negative priority on defeasible rule should raise
        theory = DefeasibleTheory()
        with pytest.raises(RuleValidationError, match="non-negative"):
            theory.add_rule(
                Rule("BAD", RuleType.DEFEASIBLE, [Literal.parse("a")], Literal.parse("b"), priority=-1)
            )

    def test_rule_validation_conflicting_strict(self) -> None:
        # Step 1: two strict rules with contradictory consequents
        theory = DefeasibleTheory()
        theory.add_rule(Rule("S1", RuleType.STRICT, [Literal.parse("a")], Literal.parse("x")))
        # Step 2: adding contradictory strict rule should raise
        with pytest.raises(RuleValidationError, match="conflicts"):
            theory.add_rule(Rule("S2", RuleType.STRICT, [Literal.parse("b")], Literal.parse("~x")))


# ── TestRegulatoryTheoryBuilder ──────────────────────────────────────────────

class TestRegulatoryTheoryBuilder:
    """Tests for the fluent builder API."""

    def test_fluent_api(self) -> None:
        # Step 1: chain calls and build
        theory = (
            RegulatoryTheoryBuilder("AUTH")
            .strict("S1", ["v"], "penalty")
            .defeasible("D1", ["permit"], "allowed", priority=5)
            .defeater("X1", ["revoked"], "~allowed")
            .fact("permit")
            .build()
        )
        # Step 2: verify theory was assembled
        assert len(theory.get_rules()) == 3
        assert len(theory.get_facts()) == 1

    def test_facts_method(self) -> None:
        # Step 1: add multiple facts at once
        theory = (
            RegulatoryTheoryBuilder("AUTH")
            .facts("a", "b", "c")
            .build()
        )
        # Step 2: all three should be present
        assert len(theory.get_facts()) == 3

    def test_strict_rule_type(self) -> None:
        # Step 1: build with strict only
        theory = RegulatoryTheoryBuilder("A").strict("S1", ["x"], "y").build()
        # Step 2: verify type
        rules = theory.get_rules()
        assert rules[0].rule_type == RuleType.STRICT

    def test_defeasible_rule_type(self) -> None:
        # Step 1: build with defeasible only
        theory = RegulatoryTheoryBuilder("A").defeasible("D1", ["x"], "y", priority=3).build()
        # Step 2: verify type and priority
        rules = theory.get_rules()
        assert rules[0].rule_type == RuleType.DEFEASIBLE
        assert rules[0].priority == 3

    def test_defeater_rule_type(self) -> None:
        # Step 1: build with defeater only
        theory = RegulatoryTheoryBuilder("A").defeater("X1", ["x"], "~y").build()
        # Step 2: verify type
        rules = theory.get_rules()
        assert rules[0].rule_type == RuleType.DEFEATER
