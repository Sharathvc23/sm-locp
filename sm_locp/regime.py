"""Generic regime provider interface for LOCP.

Defines the protocol and base class for regulatory regime providers.
Each regime provider encapsulates rules, jurisdiction info, and theory
construction for a specific regulatory domain.

Example:
    >>> class MyRegime(BaseRegimeProvider):
    ...     @property
    ...     def regime_id(self) -> str:
    ...         return "my-regime"
    ...     @property
    ...     def jurisdiction(self) -> str:
    ...         return "US"
    ...     @property
    ...     def domain(self) -> str:
    ...         return "environmental"
    ...     def build_theory(self) -> DefeasibleTheory:
    ...         builder = RegulatoryTheoryBuilder(self.regime_id)
    ...         builder.strict("R1", ["emissions_exceeded"], "violation")
    ...         return builder.build()
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Protocol, runtime_checkable

from .engine import DefeasibleTheory


@runtime_checkable
class RegimeProvider(Protocol):
    """Protocol for regime providers.

    Any object implementing these properties and methods can be used
    as a regime provider, enabling duck-typed integration.
    """

    @property
    def regime_id(self) -> str:
        """Unique identifier for this regime (e.g., 'env-us', 'finance-eu')."""
        ...

    @property
    def jurisdiction(self) -> str:
        """Jurisdiction this regime applies to (e.g., 'US', 'EU', 'global')."""
        ...

    @property
    def domain(self) -> str:
        """Regulatory domain (e.g., 'environmental', 'financial', 'safety')."""
        ...

    def build_theory(self) -> DefeasibleTheory:
        """Build and return the defeasible theory for this regime."""
        ...

    def get_applicable_sections(self, context: dict[str, Any]) -> list[str]:
        """Return section identifiers applicable to the given context.

        Args:
            context: Dictionary of contextual information used to determine
                     which regulatory sections apply.

        Returns:
            List of applicable section identifiers.
        """
        ...


class BaseRegimeProvider(ABC):
    """Abstract base class for regime providers.

    Provides default implementations where possible. Subclasses must
    implement ``regime_id``, ``jurisdiction``, ``domain``, and
    ``build_theory()``.
    """

    @property
    @abstractmethod
    def regime_id(self) -> str:
        """Unique identifier for this regime."""

    @property
    @abstractmethod
    def jurisdiction(self) -> str:
        """Jurisdiction this regime applies to."""

    @property
    @abstractmethod
    def domain(self) -> str:
        """Regulatory domain."""

    @abstractmethod
    def build_theory(self) -> DefeasibleTheory:
        """Build and return the defeasible theory for this regime."""

    def get_applicable_sections(self, context: dict[str, Any]) -> list[str]:
        """Return section identifiers applicable to the given context.

        Default implementation returns an empty list. Override in subclasses
        to provide context-aware section filtering.

        Args:
            context: Dictionary of contextual information.

        Returns:
            List of applicable section identifiers.
        """
        return []

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(regime_id={self.regime_id!r}, jurisdiction={self.jurisdiction!r})"


__all__ = [
    "BaseRegimeProvider",
    "RegimeProvider",
]
