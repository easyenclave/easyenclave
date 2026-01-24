"""Tests for FastAPI endpoints."""

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
        "endpoints": {"prod": "https://test.example.com", "staging": "https://staging.test.example.com"},
        "mrtd": "mrtd-hash-123",
        "tags": ["test", "api", "example"],
    }


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
    def test_register_service(self, client, sample_registration):
        """Test registering a new service."""
        response = client.post("/api/v1/register", json=sample_registration)
        assert response.status_code == 200
        data = response.json()
        assert "service_id" in data
        assert data["name"] == sample_registration["name"]
        assert data["description"] == sample_registration["description"]

    def test_register_minimal_service(self, client):
        """Test registering a service with minimal data."""
        response = client.post("/api/v1/register", json={"name": "minimal"})
        assert response.status_code == 200
        data = response.json()
        assert data["name"] == "minimal"
        assert data["description"] == ""

    def test_register_without_name_fails(self, client):
        """Test that registration without a name fails."""
        response = client.post("/api/v1/register", json={})
        assert response.status_code == 422


class TestListServicesEndpoint:
    def test_list_empty(self, client):
        """Test listing services when none exist."""
        response = client.get("/api/v1/services")
        assert response.status_code == 200
        data = response.json()
        assert data["services"] == []
        assert data["total"] == 0

    def test_list_services(self, client, sample_registration):
        """Test listing services."""
        # Register a service first
        client.post("/api/v1/register", json=sample_registration)

        response = client.get("/api/v1/services")
        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 1
        assert len(data["services"]) == 1

    def test_list_filter_by_name(self, client, sample_registration):
        """Test filtering services by name."""
        client.post("/api/v1/register", json=sample_registration)
        client.post("/api/v1/register", json={"name": "other-service"})

        response = client.get("/api/v1/services?name=test")
        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 1
        assert data["services"][0]["name"] == "test-service"

    def test_list_filter_by_tags(self, client, sample_registration):
        """Test filtering services by tags."""
        client.post("/api/v1/register", json=sample_registration)
        client.post("/api/v1/register", json={"name": "other", "tags": ["other"]})

        response = client.get("/api/v1/services?tags=api")
        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 1

    def test_list_filter_by_environment(self, client, sample_registration):
        """Test filtering by environment."""
        client.post("/api/v1/register", json=sample_registration)

        response = client.get("/api/v1/services?environment=prod")
        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 1

        response = client.get("/api/v1/services?environment=dev")
        data = response.json()
        assert data["total"] == 0

    def test_search_services(self, client, sample_registration):
        """Test searching services."""
        client.post("/api/v1/register", json=sample_registration)

        response = client.get("/api/v1/services?q=test")
        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 1


class TestGetServiceEndpoint:
    def test_get_service(self, client, sample_registration):
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
        response = client.get("/api/v1/services/nonexistent")
        assert response.status_code == 404


class TestDeleteServiceEndpoint:
    def test_delete_service(self, client, sample_registration):
        """Test deleting a service."""
        reg_response = client.post("/api/v1/register", json=sample_registration)
        service_id = reg_response.json()["service_id"]

        response = client.delete(f"/api/v1/services/{service_id}")
        assert response.status_code == 200
        assert response.json()["status"] == "deleted"

        # Verify it's gone
        response = client.get(f"/api/v1/services/{service_id}")
        assert response.status_code == 404

    def test_delete_service_not_found(self, client):
        """Test deleting a non-existent service."""
        response = client.delete("/api/v1/services/nonexistent")
        assert response.status_code == 404


class TestVerifyEndpoint:
    def test_verify_without_token(self, client, sample_registration):
        """Test verification without an ITA token."""
        reg_response = client.post("/api/v1/register", json=sample_registration)
        service_id = reg_response.json()["service_id"]

        response = client.get(f"/api/v1/services/{service_id}/verify")
        assert response.status_code == 200
        data = response.json()
        assert data["verified"] is False
        assert "no Intel Trust Authority token" in data["error"].lower()

    def test_verify_not_found(self, client):
        """Test verifying a non-existent service."""
        response = client.get("/api/v1/services/nonexistent/verify")
        assert response.status_code == 404
