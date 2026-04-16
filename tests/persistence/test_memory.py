"""Run the full persistence conformance suite against ``InMemoryPersistence``."""

from __future__ import annotations

from sm_locp.persistence import InMemoryPersistence

from .conformance import PersistenceConformance


class TestInMemoryPersistence(PersistenceConformance):
    persistence_factory = staticmethod(InMemoryPersistence)
