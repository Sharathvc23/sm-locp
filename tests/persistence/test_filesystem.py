"""Run the full persistence conformance suite against ``FileSystemPersistence``."""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from sm_locp.persistence import FileSystemPersistence, Persistence

from .conformance import PersistenceConformance


class TestFileSystemPersistence(PersistenceConformance):
    @pytest.fixture
    def persistence(self, tmp_path: Path) -> Persistence:
        return FileSystemPersistence(tmp_path)

    # ``persistence_factory`` isn't used here because we need tmp_path from pytest,
    # but the base class still requires the attribute to exist for the fallback.
    @staticmethod
    def persistence_factory() -> Persistence:
        return FileSystemPersistence(tempfile.mkdtemp(prefix="sm-locp-fs-"))
