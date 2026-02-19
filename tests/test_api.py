"""Tests for FastAPI endpoints."""

import pytest
from fastapi.testclient import TestClient

from app.main import app


@pytest.fixture
def client():
    """Create a test client."""
    return TestClient(app)


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


class TestLegacyServiceRoutesRemoved:
    def test_legacy_register_removed(self, client):
        response = client.post("/api/v1/register", json={})
        assert response.status_code == 404

    def test_legacy_services_list_removed(self, client):
        response = client.get("/api/v1/services")
        assert response.status_code == 404

    def test_legacy_services_get_removed(self, client):
        response = client.get("/api/v1/services/non-existent-id")
        assert response.status_code == 404

    def test_legacy_services_delete_removed(self, client):
        response = client.delete("/api/v1/services/non-existent-id")
        assert response.status_code == 404

    def test_legacy_services_verify_removed(self, client):
        response = client.get("/api/v1/services/non-existent-id/verify")
        assert response.status_code == 404


class TestTrustedMrtdEndpoints:
    """Tests for read-only trusted MRTD endpoint."""

    def test_list_empty(self, client):
        """Test listing when no MRTDs configured."""
        response = client.get("/api/v1/trusted-mrtds")
        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 0
        assert data["trusted_mrtds"] == []

    def test_list_from_env_vars(self, client, monkeypatch):
        """Test that MRTDs are loaded from env vars."""
        from app.storage import load_trusted_mrtds

        monkeypatch.setenv("TRUSTED_AGENT_MRTDS", "abc123,def456")
        monkeypatch.setenv("TRUSTED_PROXY_MRTDS", "ghi789")
        load_trusted_mrtds()

        response = client.get("/api/v1/trusted-mrtds")
        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 3

        mrtds = {m["mrtd"]: m["type"] for m in data["trusted_mrtds"]}
        assert mrtds["abc123"] == "agent"
        assert mrtds["def456"] == "agent"
        assert mrtds["ghi789"] == "proxy"

        # Cleanup
        monkeypatch.delenv("TRUSTED_AGENT_MRTDS")
        monkeypatch.delenv("TRUSTED_PROXY_MRTDS")
        load_trusted_mrtds()

    def test_backward_compat_env_vars(self, client, monkeypatch):
        """Test backward compat with old SYSTEM_AGENT_MRTD / SYSTEM_PROXY_MRTD."""
        from app.storage import load_trusted_mrtds

        monkeypatch.setenv("SYSTEM_AGENT_MRTD", "old-agent-mrtd")
        monkeypatch.setenv("SYSTEM_PROXY_MRTD", "old-proxy-mrtd")
        load_trusted_mrtds()

        response = client.get("/api/v1/trusted-mrtds")
        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 2

        mrtds = {m["mrtd"]: m["type"] for m in data["trusted_mrtds"]}
        assert mrtds["old-agent-mrtd"] == "agent"
        assert mrtds["old-proxy-mrtd"] == "proxy"

        # Cleanup
        monkeypatch.delenv("SYSTEM_AGENT_MRTD")
        monkeypatch.delenv("SYSTEM_PROXY_MRTD")
        load_trusted_mrtds()

    def test_crud_endpoints_removed(self, client):
        """Test that CRUD endpoints no longer exist."""
        assert client.post("/api/v1/trusted-mrtds", json={"mrtd": "x"}).status_code == 405
        assert client.get("/api/v1/trusted-mrtds/some-mrtd").status_code in (404, 405)
        assert client.post("/api/v1/trusted-mrtds/x/deactivate").status_code in (404, 405)
        assert client.post("/api/v1/trusted-mrtds/x/activate").status_code in (404, 405)
        assert client.delete("/api/v1/trusted-mrtds/x").status_code in (404, 405)
