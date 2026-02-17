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


@pytest.fixture
def client():
    """FastAPI test client."""
    from fastapi.testclient import TestClient

    from app.main import app

    return TestClient(app)


@pytest.fixture(autouse=True)
def clear_all_stores():
    """Clear all stores before and after each test for isolation."""
    from app.settings import clear_settings, invalidate_cache
    from app.storage import (
        account_store,
        admin_session_store,
        agent_store,
        app_revenue_share_store,
        app_store,
        app_version_store,
        capacity_launch_order_store,
        capacity_pool_target_store,
        capacity_reservation_store,
        deployment_store,
        store,
        transaction_store,
        trusted_mrtd_store,
    )

    def _clear():
        store.clear()
        agent_store.clear()
        deployment_store.clear()
        app_store.clear()
        app_version_store.clear()
        capacity_launch_order_store.clear()
        capacity_pool_target_store.clear()
        capacity_reservation_store.clear()
        app_revenue_share_store.clear()
        transaction_store.clear()
        account_store.clear()
        admin_session_store.clear()
        trusted_mrtd_store.clear()
        clear_settings()
        invalidate_cache()

    # Clear before test
    _clear()

    yield

    # Clear after test
    _clear()
