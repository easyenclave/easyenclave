"""Tests for FastAPI endpoints."""

from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.storage import store


@pytest.fixture(autouse=True)
def clear_store():
    """Clear the store before and after each test."""
    store.clear()
    yield
    store.clear()


@pytest.fixture
def client():
    """Create a test client."""
    return TestClient(app)


@pytest.fixture
def sample_registration():
    """Sample service registration request."""
    return {
        "name": "test-service",
        "description": "A test service for unit tests",
        "source_repo": "https://github.com/test/test-service",
        "source_commit": "abc123def",
        "endpoints": {
            "prod": "https://test.example.com",
            "staging": "https://staging.test.example.com",
        },
        "mrtd": "mrtd-hash-123",
        "intel_ta_token": "test-token-abc123",
        "tags": ["test", "api", "example"],
    }


@pytest.fixture
def mock_health_check():
    """Mock successful health check responses."""
    mock_response = AsyncMock()
    mock_response.status_code = 200

    with patch("app.main.httpx.AsyncClient") as mock_client:
        mock_instance = AsyncMock()
        mock_instance.get.return_value = mock_response
        mock_instance.__aenter__.return_value = mock_instance
        mock_instance.__aexit__.return_value = None
        mock_client.return_value = mock_instance
        yield mock_client


class TestHealthEndpoint:
    def test_health_check(self, client):
        """Test health endpoint returns healthy status."""
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert "timestamp" in data
        assert "version" in data


class TestRootEndpoint:
    def test_root_returns_gui_or_info(self, client):
        """Test root endpoint."""
        response = client.get("/")
        assert response.status_code == 200


class TestRegisterEndpoint:
    def test_register_service(self, client, sample_registration, mock_health_check):
        """Test registering a new service."""
        response = client.post("/api/v1/register", json=sample_registration)
        assert response.status_code == 200
        data = response.json()
        assert "service_id" in data
        assert data["name"] == sample_registration["name"]
        assert data["mrtd"] == sample_registration["mrtd"]

    def test_register_minimal_service(self, client, mock_health_check):
        """Test registering a service with minimal data."""
        response = client.post(
            "/api/v1/register",
            json={
                "name": "minimal",
                "mrtd": "mrtd-123",
                "intel_ta_token": "token-123",
                "endpoints": {"prod": "https://example.com"},
            },
        )
        assert response.status_code == 200
        data = response.json()
        assert data["name"] == "minimal"

    def test_register_without_name_fails(self, client):
        """Test that registration without name fails."""
        response = client.post("/api/v1/register", json={})
        assert response.status_code == 422  # Validation error

    def test_register_without_mrtd_fails(self, client):
        """Test that registration without MRTD fails."""
        response = client.post(
            "/api/v1/register",
            json={"name": "test", "intel_ta_token": "token"},
        )
        assert response.status_code == 400
        assert "MRTD" in response.json()["detail"]

    def test_register_without_token_fails(self, client):
        """Test that registration without Intel TA token fails."""
        response = client.post(
            "/api/v1/register",
            json={"name": "test", "mrtd": "mrtd-123"},
        )
        assert response.status_code == 400
        assert "Intel Trust Authority" in response.json()["detail"]


class TestListServicesEndpoint:
    def test_list_empty(self, client):
        """Test listing services when empty."""
        response = client.get("/api/v1/services")
        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 0
        assert data["services"] == []

    def test_list_services(self, client, sample_registration, mock_health_check):
        """Test listing services."""
        # Register a service first
        client.post("/api/v1/register", json=sample_registration)

        response = client.get("/api/v1/services")
        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 1
        assert len(data["services"]) == 1

    def test_list_filter_by_name(self, client, sample_registration, mock_health_check):
        """Test filtering services by name."""
        client.post("/api/v1/register", json=sample_registration)
        other_reg = {
            **sample_registration,
            "name": "other-service",
        }
        client.post("/api/v1/register", json=other_reg)

        response = client.get("/api/v1/services?name=test")
        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 1
        assert data["services"][0]["name"] == "test-service"

    def test_list_filter_by_tags(self, client, sample_registration, mock_health_check):
        """Test filtering services by tags."""
        client.post("/api/v1/register", json=sample_registration)
        other_reg = {
            **sample_registration,
            "name": "other-service",
            "tags": ["other"],
        }
        client.post("/api/v1/register", json=other_reg)

        response = client.get("/api/v1/services?tags=api")
        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 1

    def test_list_filter_by_environment(self, client, sample_registration, mock_health_check):
        """Test filtering services by environment."""
        client.post("/api/v1/register", json=sample_registration)

        response = client.get("/api/v1/services?environment=prod")
        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 1

    def test_search_services(self, client, sample_registration, mock_health_check):
        """Test searching services."""
        client.post("/api/v1/register", json=sample_registration)

        response = client.get("/api/v1/services?q=test")
        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 1


class TestGetServiceEndpoint:
    def test_get_service(self, client, sample_registration, mock_health_check):
        """Test getting a specific service."""
        reg_response = client.post("/api/v1/register", json=sample_registration)
        service_id = reg_response.json()["service_id"]

        response = client.get(f"/api/v1/services/{service_id}")
        assert response.status_code == 200
        data = response.json()
        assert data["service_id"] == service_id
        assert data["name"] == sample_registration["name"]

    def test_get_service_not_found(self, client):
        """Test getting a non-existent service."""
        response = client.get("/api/v1/services/non-existent-id")
        assert response.status_code == 404


class TestDeleteServiceEndpoint:
    def test_delete_service(self, client, sample_registration, mock_health_check):
        """Test deleting a service."""
        reg_response = client.post("/api/v1/register", json=sample_registration)
        service_id = reg_response.json()["service_id"]

        response = client.delete(f"/api/v1/services/{service_id}")
        assert response.status_code == 200

        # Verify it's deleted
        response = client.get(f"/api/v1/services/{service_id}")
        assert response.status_code == 404

    def test_delete_service_not_found(self, client):
        """Test deleting a non-existent service."""
        response = client.delete("/api/v1/services/non-existent-id")
        assert response.status_code == 404


class TestVerifyEndpoint:
    def test_verify_without_token(self, client, sample_registration, mock_health_check):
        """Test verification without Intel TA configured."""
        reg_response = client.post("/api/v1/register", json=sample_registration)
        service_id = reg_response.json()["service_id"]

        response = client.get(f"/api/v1/services/{service_id}/verify")
        assert response.status_code == 200
        data = response.json()
        assert "verified" in data

    def test_verify_not_found(self, client):
        """Test verification of non-existent service."""
        response = client.get("/api/v1/services/non-existent-id/verify")
        assert response.status_code == 404


class TestTrustedMrtdEndpoints:
    """Tests for trusted MRTD API endpoints."""

    @pytest.fixture(autouse=True)
    def clear_trusted_mrtd_store(self):
        """Clear trusted MRTD store before and after each test."""
        from app.storage import trusted_mrtd_store
        trusted_mrtd_store.clear()
        yield
        trusted_mrtd_store.clear()

    def test_add_trusted_mrtd(self, client):
        """Test adding a trusted MRTD."""
        response = client.post(
            "/api/v1/trusted-mrtds",
            json={
                "mrtd": "abc123def456",
                "type": "app",
                "description": "Test app MRTD",
            },
        )
        assert response.status_code == 200
        data = response.json()
        assert data["mrtd"] == "abc123def456"
        assert data["type"] == "app"
        assert data["locked"] is False

    def test_add_duplicate_mrtd_fails(self, client):
        """Test that adding a duplicate MRTD fails."""
        client.post(
            "/api/v1/trusted-mrtds",
            json={"mrtd": "abc123def456", "type": "app"},
        )
        response = client.post(
            "/api/v1/trusted-mrtds",
            json={"mrtd": "abc123def456", "type": "app"},
        )
        assert response.status_code == 409

    def test_list_trusted_mrtds(self, client):
        """Test listing trusted MRTDs."""
        client.post(
            "/api/v1/trusted-mrtds",
            json={"mrtd": "mrtd1", "type": "app"},
        )
        client.post(
            "/api/v1/trusted-mrtds",
            json={"mrtd": "mrtd2", "type": "agent"},
        )

        response = client.get("/api/v1/trusted-mrtds")
        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 2

    def test_list_trusted_mrtds_filter_by_type(self, client):
        """Test filtering trusted MRTDs by type."""
        client.post(
            "/api/v1/trusted-mrtds",
            json={"mrtd": "mrtd1", "type": "app"},
        )
        client.post(
            "/api/v1/trusted-mrtds",
            json={"mrtd": "mrtd2", "type": "agent"},
        )

        response = client.get("/api/v1/trusted-mrtds?type=app")
        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 1
        assert data["trusted_mrtds"][0]["type"] == "app"

    def test_delete_trusted_mrtd(self, client):
        """Test deleting a trusted MRTD."""
        client.post(
            "/api/v1/trusted-mrtds",
            json={"mrtd": "abc123def456", "type": "app"},
        )

        response = client.delete("/api/v1/trusted-mrtds/abc123def456")
        assert response.status_code == 200

        # Verify it's deleted
        response = client.get("/api/v1/trusted-mrtds/abc123def456")
        assert response.status_code == 404

    def test_deactivate_trusted_mrtd(self, client):
        """Test deactivating a trusted MRTD."""
        client.post(
            "/api/v1/trusted-mrtds",
            json={"mrtd": "abc123def456", "type": "app"},
        )

        response = client.post("/api/v1/trusted-mrtds/abc123def456/deactivate")
        assert response.status_code == 200

        # Verify it's deactivated
        response = client.get("/api/v1/trusted-mrtds/abc123def456")
        assert response.status_code == 200
        assert response.json()["active"] is False


class TestLockedSystemMrtds:
    """Tests for locked system MRTD protection."""

    @pytest.fixture(autouse=True)
    def setup_system_mrtds(self, monkeypatch):
        """Set up system MRTDs via environment variables."""
        from app.storage import trusted_mrtd_store
        trusted_mrtd_store.clear()

        # Set environment variables before re-loading system MRTDs
        monkeypatch.setenv("SYSTEM_AGENT_MRTD", "system-agent-mrtd-123")
        monkeypatch.setenv("SYSTEM_PROXY_MRTD", "system-proxy-mrtd-456")

        # Reload system MRTDs
        trusted_mrtd_store._load_system_mrtds()

        yield

        trusted_mrtd_store.clear()

    def test_system_mrtds_loaded_on_startup(self, client):
        """Test that system MRTDs are loaded from environment."""
        response = client.get("/api/v1/trusted-mrtds")
        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 2

        mrtds = {m["mrtd"]: m for m in data["trusted_mrtds"]}
        assert "system-agent-mrtd-123" in mrtds
        assert "system-proxy-mrtd-456" in mrtds

        # Verify they are locked
        assert mrtds["system-agent-mrtd-123"]["locked"] is True
        assert mrtds["system-proxy-mrtd-456"]["locked"] is True

        # Verify types
        assert mrtds["system-agent-mrtd-123"]["type"] == "agent"
        assert mrtds["system-proxy-mrtd-456"]["type"] == "proxy"

    def test_cannot_delete_locked_mrtd(self, client):
        """Test that locked system MRTDs cannot be deleted."""
        response = client.delete("/api/v1/trusted-mrtds/system-agent-mrtd-123")
        assert response.status_code == 403
        assert "system mrtd" in response.json()["detail"].lower()

        # Verify it still exists
        response = client.get("/api/v1/trusted-mrtds/system-agent-mrtd-123")
        assert response.status_code == 200

    def test_cannot_deactivate_locked_mrtd(self, client):
        """Test that locked system MRTDs cannot be deactivated."""
        response = client.post("/api/v1/trusted-mrtds/system-agent-mrtd-123/deactivate")
        assert response.status_code == 403
        assert "system mrtd" in response.json()["detail"].lower()

        # Verify it's still active
        response = client.get("/api/v1/trusted-mrtds/system-agent-mrtd-123")
        assert response.status_code == 200
        assert response.json()["active"] is True

    def test_cannot_add_mrtd_with_same_value_as_locked(self, client):
        """Test that you cannot add an MRTD with the same value as a locked one."""
        response = client.post(
            "/api/v1/trusted-mrtds",
            json={
                "mrtd": "system-agent-mrtd-123",
                "type": "app",
                "description": "Trying to overwrite",
            },
        )
        assert response.status_code == 403
        assert "system mrtd" in response.json()["detail"].lower()

    def test_regular_mrtds_can_still_be_deleted(self, client):
        """Test that regular (non-locked) MRTDs can still be deleted."""
        # Add a regular MRTD
        client.post(
            "/api/v1/trusted-mrtds",
            json={"mrtd": "regular-mrtd-789", "type": "app"},
        )

        # Delete it
        response = client.delete("/api/v1/trusted-mrtds/regular-mrtd-789")
        assert response.status_code == 200

        # Verify it's deleted
        response = client.get("/api/v1/trusted-mrtds/regular-mrtd-789")
        assert response.status_code == 404

    def test_regular_mrtds_can_still_be_deactivated(self, client):
        """Test that regular (non-locked) MRTDs can still be deactivated."""
        # Add a regular MRTD
        client.post(
            "/api/v1/trusted-mrtds",
            json={"mrtd": "regular-mrtd-789", "type": "app"},
        )

        # Deactivate it
        response = client.post("/api/v1/trusted-mrtds/regular-mrtd-789/deactivate")
        assert response.status_code == 200

        # Verify it's deactivated
        response = client.get("/api/v1/trusted-mrtds/regular-mrtd-789")
        assert response.status_code == 200
        assert response.json()["active"] is False
