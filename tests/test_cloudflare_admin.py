"""Tests for Cloudflare admin tab API routes."""

from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

from app.auth import verify_admin_token
from app.db_models import AdminSession
from app.main import app
from app.storage import agent_store


async def mock_verify_admin_token():
    return AdminSession(
        token_hash="x",
        token_prefix="x",
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        auth_method="password",
    )


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture(autouse=True)
def override_admin_auth():
    app.dependency_overrides[verify_admin_token] = mock_verify_admin_token
    yield
    app.dependency_overrides.pop(verify_admin_token, None)


AUTH = {"Authorization": "Bearer mock"}


class TestCloudflareStatus:
    def test_status_configured(self, client):
        from app.settings import invalidate_cache, set_setting

        set_setting("cloudflare.domain", "example.com")
        invalidate_cache()
        with patch("app.main.cloudflare.is_configured", return_value=True):
            resp = client.get("/api/v1/admin/cloudflare/status", headers=AUTH)
        assert resp.status_code == 200
        data = resp.json()
        assert data["configured"] is True
        assert data["domain"] == "example.com"
        assert "easyenclave-control-plane" in data["protected_tunnel_names"]

    def test_status_not_configured(self, client):
        with patch("app.main.cloudflare.is_configured", return_value=False):
            resp = client.get("/api/v1/admin/cloudflare/status", headers=AUTH)
        assert resp.status_code == 200
        assert resp.json()["configured"] is False


class TestCloudflareTunnels:
    def test_list_tunnels_empty(self, client):
        with patch("app.main.cloudflare.is_configured", return_value=True):
            with patch("app.main.cloudflare.list_tunnels", new_callable=AsyncMock, return_value=[]):
                resp = client.get("/api/v1/admin/cloudflare/tunnels", headers=AUTH)
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 0
        assert data["orphaned_count"] == 0

    def test_list_tunnels_with_agent(self, client):
        from app.db_models import Agent

        agent = Agent(
            vm_name="test-vm", tunnel_id="tun-123", hostname="test.example.com", status="deployed"
        )
        agent_store.register(agent)

        tunnels = [
            {
                "tunnel_id": "tun-123",
                "name": "agent-test",
                "status": "active",
                "has_connections": True,
                "connection_count": 1,
                "created_at": "2026-01-01T00:00:00Z",
            }
        ]

        with patch("app.main.cloudflare.is_configured", return_value=True):
            with patch(
                "app.main.cloudflare.list_tunnels", new_callable=AsyncMock, return_value=tunnels
            ):
                resp = client.get("/api/v1/admin/cloudflare/tunnels", headers=AUTH)

        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 1
        assert data["orphaned_count"] == 0
        assert data["tunnels"][0]["agent_vm_name"] == "test-vm"
        assert data["tunnels"][0]["orphaned"] is False

    def test_list_tunnels_orphaned(self, client):
        tunnels = [
            {
                "tunnel_id": "tun-orphan",
                "name": "agent-gone",
                "status": "inactive",
                "has_connections": False,
                "connection_count": 0,
                "created_at": "2026-01-01T00:00:00Z",
            }
        ]

        with patch("app.main.cloudflare.is_configured", return_value=True):
            with patch(
                "app.main.cloudflare.list_tunnels", new_callable=AsyncMock, return_value=tunnels
            ):
                resp = client.get("/api/v1/admin/cloudflare/tunnels", headers=AUTH)

        data = resp.json()
        assert data["orphaned_count"] == 1
        assert data["tunnels"][0]["orphaned"] is True
        assert data["tunnels"][0]["agent_id"] is None
        assert data["tunnels"][0]["owner"] == "agent"

    def test_control_plane_tunnel_is_protected_not_orphaned(self, client):
        tunnels = [
            {
                "tunnel_id": "tun-cp",
                "name": "easyenclave-control-plane",
                "status": "active",
                "has_connections": True,
                "connection_count": 1,
                "created_at": "2026-01-01T00:00:00Z",
            }
        ]

        with patch("app.main.cloudflare.is_configured", return_value=True):
            with patch(
                "app.main.cloudflare.list_tunnels", new_callable=AsyncMock, return_value=tunnels
            ):
                resp = client.get("/api/v1/admin/cloudflare/tunnels", headers=AUTH)

        assert resp.status_code == 200
        data = resp.json()
        assert data["orphaned_count"] == 0
        assert data["tunnels"][0]["protected"] is True
        assert data["tunnels"][0]["orphaned"] is False
        assert data["tunnels"][0]["owner"] == "control-plane"

    def test_not_configured_returns_400(self, client):
        with patch("app.main.cloudflare.is_configured", return_value=False):
            resp = client.get("/api/v1/admin/cloudflare/tunnels", headers=AUTH)
        assert resp.status_code == 400


class TestCloudflareDns:
    def test_list_dns_with_linked_and_orphaned(self, client):
        tunnels = [
            {
                "tunnel_id": "tun-1",
                "name": "agent-1",
                "status": "active",
                "has_connections": True,
                "connection_count": 1,
                "created_at": None,
            }
        ]
        records = [
            {
                "record_id": "rec-1",
                "name": "agent-1.example.com",
                "content": "tun-1.cfargotunnel.com",
                "proxied": True,
                "created_on": None,
            },
            {
                "record_id": "rec-2",
                "name": "agent-gone.example.com",
                "content": "tun-gone.cfargotunnel.com",
                "proxied": True,
                "created_on": None,
            },
            {
                "record_id": "rec-3",
                "name": "other.example.com",
                "content": "some-server.example.com",
                "proxied": False,
                "created_on": None,
            },
        ]

        with patch("app.main.cloudflare.is_configured", return_value=True):
            with patch(
                "app.main.cloudflare.list_dns_records", new_callable=AsyncMock, return_value=records
            ):
                with patch(
                    "app.main.cloudflare.list_tunnels", new_callable=AsyncMock, return_value=tunnels
                ):
                    resp = client.get("/api/v1/admin/cloudflare/dns", headers=AUTH)

        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 3
        assert data["tunnel_record_count"] == 2
        assert data["orphaned_count"] == 1  # tun-gone not in tunnels

        linked = next(r for r in data["records"] if r["record_id"] == "rec-1")
        assert linked["orphaned"] is False
        assert linked["linked_tunnel_id"] == "tun-1"

        orphaned = next(r for r in data["records"] if r["record_id"] == "rec-2")
        assert orphaned["orphaned"] is True

        other = next(r for r in data["records"] if r["record_id"] == "rec-3")
        assert other["is_tunnel_record"] is False
        assert other["orphaned"] is False


class TestCloudflareDelete:
    def test_delete_tunnel_clears_agent(self, client):
        from app.db_models import Agent

        agent = Agent(
            vm_name="test-vm",
            tunnel_id="tun-del",
            hostname="test.example.com",
            tunnel_token="tok",
            status="deployed",
        )
        agent_store.register(agent)
        agent_id = agent.agent_id

        with patch("app.main.cloudflare.is_configured", return_value=True):
            with patch("app.main.cloudflare.list_tunnels", new_callable=AsyncMock, return_value=[]):
                with patch(
                    "app.main.cloudflare.delete_tunnel", new_callable=AsyncMock, return_value=True
                ):
                    resp = client.delete("/api/v1/admin/cloudflare/tunnels/tun-del", headers=AUTH)

        assert resp.status_code == 200
        assert resp.json()["deleted"] is True

        # Verify agent tunnel info was cleared
        updated = agent_store.get(agent_id)
        assert updated.tunnel_id is None
        assert updated.hostname is None
        assert updated.tunnel_token is None

    def test_delete_dns_record(self, client):
        with patch("app.main.cloudflare.is_configured", return_value=True):
            with patch(
                "app.main.cloudflare.delete_dns_record_by_id",
                new_callable=AsyncMock,
                return_value=True,
            ):
                resp = client.delete("/api/v1/admin/cloudflare/dns/rec-123", headers=AUTH)

        assert resp.status_code == 200
        assert resp.json()["deleted"] is True


class TestCloudflareCleanup:
    def test_cleanup_deletes_orphans(self, client):
        from app.db_models import Agent

        agent = Agent(
            vm_name="keep-vm", tunnel_id="tun-keep", hostname="keep.example.com", status="deployed"
        )
        agent_store.register(agent)

        tunnels = [
            {
                "tunnel_id": "tun-keep",
                "name": "agent-keep",
                "status": "active",
                "has_connections": True,
                "connection_count": 1,
                "created_at": None,
            },
            {
                "tunnel_id": "tun-cp",
                "name": "easyenclave-control-plane",
                "status": "active",
                "has_connections": True,
                "connection_count": 1,
                "created_at": None,
            },
            {
                "tunnel_id": "tun-orphan",
                "name": "agent-orphan",
                "status": "inactive",
                "has_connections": False,
                "connection_count": 0,
                "created_at": None,
            },
        ]

        dns_records = [
            {
                "record_id": "rec-keep",
                "name": "keep.example.com",
                "content": "tun-keep.cfargotunnel.com",
                "proxied": True,
                "created_on": None,
            },
            {
                "record_id": "rec-orphan",
                "name": "orphan.example.com",
                "content": "tun-dead.cfargotunnel.com",
                "proxied": True,
                "created_on": None,
            },
        ]

        delete_tunnel_mock = AsyncMock(return_value=True)
        delete_dns_mock = AsyncMock(return_value=True)
        list_tunnels_mock = AsyncMock(return_value=tunnels)

        with patch("app.main.cloudflare.is_configured", return_value=True):
            with patch("app.main.cloudflare.list_tunnels", list_tunnels_mock):
                with patch(
                    "app.main.cloudflare.list_dns_records",
                    new_callable=AsyncMock,
                    return_value=dns_records,
                ):
                    with patch("app.main.cloudflare.delete_tunnel", delete_tunnel_mock):
                        with patch("app.main.cloudflare.delete_dns_record_by_id", delete_dns_mock):
                            resp = client.post("/api/v1/admin/cloudflare/cleanup", headers=AUTH)

        assert resp.status_code == 200
        data = resp.json()
        assert data["tunnels_deleted"] == 1
        assert data["dns_deleted"] == 1
        assert data["tunnels_candidates"] == 1
        assert data["dns_candidates"] == 1
        assert data["tunnels_failed"] == 0
        assert data["dns_failed"] == 0

        # Only the orphan tunnel should have been deleted
        delete_tunnel_mock.assert_called_once_with("tun-orphan")
        delete_dns_mock.assert_called_once_with("rec-orphan")
