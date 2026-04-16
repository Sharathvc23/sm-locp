"""Tests for regime providers."""

from __future__ import annotations

import pytest

from sm_locp.engine import DefeasibleTheory, Literal, RuleType
from sm_locp.regime import BaseRegimeProvider, RegimeProvider

from examples.example_regime import WarehouseSafetyRegime


class TestWarehouseSafetyRegime:
    """Tests for the example WarehouseSafetyRegime."""

    def test_build_theory_returns_theory(self, warehouse_regime: WarehouseSafetyRegime) -> None:
        # Step 1: build theory
        theory = warehouse_regime.build_theory()
        # Step 2: verify it is a DefeasibleTheory with rules
        assert isinstance(theory, DefeasibleTheory)
        assert len(theory.get_rules()) == 7  # 1 strict + 3 defeasible + 3 defeaters

    def test_query_permitted_operation_with_certification(
        self, warehouse_regime: WarehouseSafetyRegime
    ) -> None:
        # Step 1: build theory and add facts
        theory = warehouse_regime.build_theory()
        theory.add_fact(Literal.parse("forklift_operator"))
        theory.add_fact(Literal.parse("has_certification"))
        # Step 2: query
        result = theory.query(Literal.parse("permitted_operation"))
        # Step 3: should derive
        assert result.derived is True

    def test_defeater_blocks_when_expired(
        self, warehouse_regime: WarehouseSafetyRegime
    ) -> None:
        # Step 1: build theory with certification facts and expiration
        theory = warehouse_regime.build_theory()
        theory.add_fact(Literal.parse("forklift_operator"))
        theory.add_fact(Literal.parse("has_certification"))
        theory.add_fact(Literal.parse("expired_certification"))
        # Step 2: query
        result = theory.query(Literal.parse("permitted_operation"))
        # Step 3: should be defeated
        assert result.derived is False
        assert result.blocked_by is not None
        assert result.blocked_by.rule_id == "WS_X1"

    def test_all_rule_types_present(
        self, warehouse_regime: WarehouseSafetyRegime
    ) -> None:
        # Step 1: build theory
        theory = warehouse_regime.build_theory()
        rules = theory.get_rules()
        # Step 2: check each type is represented
        types = {r.rule_type for r in rules}
        assert RuleType.STRICT in types
        assert RuleType.DEFEASIBLE in types
        assert RuleType.DEFEATER in types

    def test_regime_id(self, warehouse_regime: WarehouseSafetyRegime) -> None:
        # Step 1: verify property
        assert warehouse_regime.regime_id == "warehouse-safety"

    def test_jurisdiction(self, warehouse_regime: WarehouseSafetyRegime) -> None:
        # Step 1: verify property
        assert warehouse_regime.jurisdiction == "US"

    def test_domain(self, warehouse_regime: WarehouseSafetyRegime) -> None:
        # Step 1: verify property
        assert warehouse_regime.domain == "safety"

    def test_implements_protocol(self, warehouse_regime: WarehouseSafetyRegime) -> None:
        # Step 1: verify it satisfies the RegimeProvider protocol
        assert isinstance(warehouse_regime, BaseRegimeProvider)
        assert isinstance(warehouse_regime, RegimeProvider)
