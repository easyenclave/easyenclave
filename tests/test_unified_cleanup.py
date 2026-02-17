"""Tests for unified cleanup endpoints (Cloudflare + external provisioner + agent delete)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, patch

from fastapi.testclient import TestClient

from app.auth import verify_admin_token
from app.db_models import AdminSession, Agent
from app.main import app
from app.settings import invalidate_cache, set_setting
from app.storage import agent_store


async def _mock_verify_admin_token():
    return AdminSession(
        token_hash="x",
        token_prefix="x",
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        auth_method="password",
    )


AUTH = {"Authorization": "Bearer mock"}


def _mk_agent(vm_name: str, *, tunnel_id: str = "tun-1", hostname: str = "a.example.com") -> Agent:
    return Agent(
        vm_name=vm_name,
        attestation={"tdx": {"intel_ta_token": "fake.token"}},
        mrtd="f" * 96,
        verified=True,
        health_status="healthy",
        status="undeployed",
        hostname=hostname,
        tunnel_id=tunnel_id,
        node_size="tiny",
        datacenter="gcp:us-central1-a",
    )


def test_unified_orphan_cleanup_not_configured(client: TestClient):
    app.dependency_overrides[verify_admin_token] = _mock_verify_admin_token
    try:
        resp = client.post(
            "/api/v1/admin/cleanup/orphans",
            headers=AUTH,
            json={"dry_run": True, "cloudflare": True, "external_cloud": True},
        )
    finally:
        app.dependency_overrides.clear()

    assert resp.status_code == 200
    data = resp.json()
    assert data["dry_run"] is True
    assert data["cloudflare_configured"] is False
    assert data["external_cloud_configured"] is False


def test_unified_orphan_cleanup_cloudflare_dry_run(client: TestClient):
    agent = _mk_agent("agent-1", tunnel_id="tun-keep")
    agent_store.register(agent)

    tunnels = [
        {
            "tunnel_id": "tun-cp",
            "name": "easyenclave-control-plane",
            "status": "active",
            "has_connections": True,
            "connection_count": 1,
            "created_at": None,
        },
        {
            "tunnel_id": "tun-keep",
            "name": "agent-keep",
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
            "content": "tun-orphan.cfargotunnel.com",
            "proxied": True,
            "created_on": None,
        },
    ]

    app.dependency_overrides[verify_admin_token] = _mock_verify_admin_token
    try:
        with patch("app.main.cloudflare.is_configured", return_value=True):
            with patch(
                "app.main.cloudflare.list_tunnels", new_callable=AsyncMock, return_value=tunnels
            ):
                with patch(
                    "app.main.cloudflare.list_dns_records",
                    new_callable=AsyncMock,
                    return_value=dns_records,
                ):
                    resp = client.post(
                        "/api/v1/admin/cleanup/orphans",
                        headers=AUTH,
                        json={"dry_run": True, "cloudflare": True, "external_cloud": False},
                    )
    finally:
        app.dependency_overrides.clear()

    assert resp.status_code == 200
    data = resp.json()
    assert data["cloudflare_configured"] is True
    assert data["cloudflare"]["dry_run"] is True
    assert data["cloudflare"]["tunnels_candidates"] == 1
    assert data["cloudflare"]["dns_candidates"] == 1


def test_admin_agent_cleanup_deletes_linked_external_resources(client: TestClient, monkeypatch):
    # Configure external cleanup URL so the endpoint will dispatch deletion.
    set_setting("provisioner.cleanup_url", "https://provisioner.example.com/cleanup")
    set_setting("provisioner.inventory_url", "https://provisioner.example.com/inventory")
    invalidate_cache()

    agent = _mk_agent("gcp-tiny-1", tunnel_id="tun-del", hostname="gcp-tiny-1.example.com")
    agent_store.register(agent)

    async def _fake_fetch_external_inventory():
        return (
            True,
            200,
            None,
            {
                "resources": [
                    {
                        "provider": "gcp",
                        "resource_id": "inst-1",
                        "resource_type": "vm",
                        "name": "gcp-tiny-1",
                        "zone": "us-central1-a",
                        "status": "running",
                    },
                    {
                        "provider": "gcp",
                        "resource_id": "disk-1",
                        "resource_type": "disk",
                        "name": "gcp-tiny-1-disk",
                        "zone": "us-central1-a",
                        "status": "ready",
                    },
                ]
            },
        )

    monkeypatch.setattr("app.main.fetch_external_inventory", _fake_fetch_external_inventory)

    dispatch_mock = AsyncMock(
        return_value=(
            True,
            True,
            202,
            None,
            {"requested_count": 1, "detail": "queued"},
        )
    )
    monkeypatch.setattr("app.main.dispatch_external_cleanup", dispatch_mock)

    app.dependency_overrides[verify_admin_token] = _mock_verify_admin_token
    try:
        with patch("app.main.cloudflare.is_configured", return_value=True):
            with patch(
                "app.main.cloudflare.delete_tunnel", new_callable=AsyncMock, return_value=True
            ):
                with patch(
                    "app.main.cloudflare.delete_dns_record",
                    new_callable=AsyncMock,
                    return_value=True,
                ):
                    resp = client.post(
                        f"/api/v1/admin/agents/{agent.agent_id}/cleanup",
                        headers=AUTH,
                        json={"dry_run": False, "reason": "test"},
                    )
    finally:
        app.dependency_overrides.clear()

    assert resp.status_code == 200
    data = resp.json()
    assert data["dry_run"] is False
    assert data["agent_deleted"] is True
    assert data["cloudflare_deleted"] is True
    assert data["external_candidates"] == 1  # only the VM is linked by name/vm_name
    assert data["external_cloud"]["dispatched"] is True
    # Ensure we dispatched deletion for the linked VM resource id.
    sent = dispatch_mock.call_args.args[0]
    assert sent["resource_ids"] == ["inst-1"]
