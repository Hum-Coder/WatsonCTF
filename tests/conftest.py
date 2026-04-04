"""
pytest configuration and session-scoped fixtures.
Creates all test fixture files before the test session begins.
"""
from __future__ import annotations

from pathlib import Path

import pytest

FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture(scope="session", autouse=True)
def create_all_fixtures():
    """Create all test fixture files before the test session."""
    FIXTURES_DIR.mkdir(exist_ok=True)
    from tests.create_fixtures import create_all
    create_all(FIXTURES_DIR)


@pytest.fixture(scope="session")
def fixtures_dir():
    return FIXTURES_DIR
