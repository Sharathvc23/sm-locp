"""Warehouse Safety regime -- synthetic example for demonstrations.

Shows all three defeasible rule types (strict, defeasible, defeater)
working together in a realistic warehouse compliance scenario.
"""

from __future__ import annotations

from typing import Any

from sm_locp.engine import DefeasibleTheory, Literal, RegulatoryTheoryBuilder, Rule, RuleType
from sm_locp.regime import BaseRegimeProvider


class WarehouseSafetyRegime(BaseRegimeProvider):
    """Synthetic warehouse-safety regime for testing and demonstrations.

    Rules
    -----
    Strict:
        WS_S1: injury_reported -> investigation_required

    Defeasible:
        WS_D1: forklift_operator AND has_certification -> permitted_operation (priority 5)
        WS_D2: load_within_weight_limit AND proper_ppe -> permitted_handling (priority 4)
        WS_D3: area_inspected AND fire_exits_clear -> area_compliant (priority 3)

    Defeater:
        WS_X1: expired_certification -> NOT permitted_operation
        WS_X2: hazardous_spill_active -> NOT permitted_handling
        WS_X3: emergency_evacuation -> NOT area_compliant
    """

    @property
    def regime_id(self) -> str:
        return "warehouse-safety"

    @property
    def jurisdiction(self) -> str:
        return "US"

    @property
    def domain(self) -> str:
        return "safety"

    def build_theory(self) -> DefeasibleTheory:
        """Build the warehouse-safety defeasible theory."""
        theory = (
            RegulatoryTheoryBuilder("WS")
            # --- Strict rules ------------------------------------------------
            .strict(
                "WS_S1",
                ["injury_reported"],
                "investigation_required",
                description="Any reported injury triggers mandatory investigation",
            )
            # --- Defeasible rules --------------------------------------------
            .defeasible(
                "WS_D1",
                ["forklift_operator", "has_certification"],
                "permitted_operation",
                priority=5,
                description="Certified forklift operators are permitted to operate",
            )
            .defeasible(
                "WS_D2",
                ["load_within_weight_limit", "proper_ppe"],
                "permitted_handling",
                priority=4,
                description="Proper PPE and weight compliance permit material handling",
            )
            .defeasible(
                "WS_D3",
                ["area_inspected", "fire_exits_clear"],
                "area_compliant",
                priority=3,
                description="Inspected area with clear fire exits is compliant",
            )
            # --- Defeaters ---------------------------------------------------
            .defeater(
                "WS_X1",
                ["expired_certification"],
                "~permitted_operation",
                description="Expired certification blocks forklift operation",
            )
            .defeater(
                "WS_X2",
                ["hazardous_spill_active"],
                "~permitted_handling",
                description="Active hazardous spill blocks material handling",
            )
            .defeater(
                "WS_X3",
                ["emergency_evacuation"],
                "~area_compliant",
                description="Emergency evacuation blocks area compliance",
            )
            .build()
        )
        return theory

    def get_applicable_sections(self, context: dict[str, Any]) -> list[str]:
        """Return applicable warehouse-safety sections for *context*."""
        sections: list[str] = []
        if context.get("has_forklifts"):
            sections.append("forklift-operations")
        if context.get("handles_materials"):
            sections.append("material-handling")
        if context.get("has_work_areas"):
            sections.append("area-compliance")
        return sections
