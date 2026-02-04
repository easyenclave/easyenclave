"""Pytest configuration and fixtures for EasyEnclave tests."""

import os
import tempfile

import pytest

# Set database path to temporary file before importing app modules
_temp_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
_temp_db.close()
os.environ["EASYENCLAVE_DB_PATH"] = _temp_db.name


@pytest.fixture(scope="session", autouse=True)
def setup_test_database():
    """Initialize test database once per session."""
    from app.database import init_db

    init_db()
    yield

    # Cleanup temp database file after all tests
    try:
        os.unlink(_temp_db.name)
    except OSError:
        pass
    # Also cleanup WAL files
    for suffix in ["-wal", "-shm"]:
        try:
            os.unlink(_temp_db.name + suffix)
        except OSError:
            pass


@pytest.fixture(autouse=True)
def clear_all_stores():
    """Clear all stores before and after each test for isolation."""
    from app.storage import (
        agent_store,
        app_store,
        app_version_store,
        deployment_store,
        store,
        trusted_mrtd_store,
    )

    # Clear before test
    store.clear()
    agent_store.clear()
    deployment_store.clear()
    trusted_mrtd_store.clear()
    app_store.clear()
    app_version_store.clear()

    yield

    # Clear after test
    store.clear()
    agent_store.clear()
    deployment_store.clear()
    trusted_mrtd_store.clear()
    app_store.clear()
    app_version_store.clear()
