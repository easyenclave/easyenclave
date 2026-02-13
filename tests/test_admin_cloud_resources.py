"""Tests for admin cloud resource inventory and cleanup APIs."""

from __future__ import annotations

from fastapi.testclient import TestClient

from app.auth import verify_admin_token
from app.db_models import Agent
from app.main import app
from app.storage import agent_store


async def _mock_verify_admin_token():
    return True


AUTH = {"Authorization": "Bearer mock"}


def _mk_agent(vm_name: str, datacenter: str, node_size: str = "tiny") -> Agent:
    return Agent(
        vm_name=vm_name,
        attestation={"tdx": {"intel_ta_token": "fake.token"}},
        mrtd="f" * 96,
        verified=True,
        health_status="healthy",
        status="undeployed",
        hostname=f"{vm_name}.example.com",
        node_size=node_size,
        datacenter=datacenter,
    )


def test_external_inventory_not_configured(client: TestClient):
    app.dependency_overrides[verify_admin_token] = _mock_verify_admin_token
    try:
        resp = client.get("/api/v1/admin/cloud/resources/external", headers=AUTH)
    finally:
        app.dependency_overrides.clear()

    assert resp.status_code == 200
    data = resp.json()
    assert data["configured"] is False
    assert data["total_resources"] == 0
    assert data["tracked_count"] == 0
    assert data["orphaned_count"] == 0
    assert "not configured" in (data["detail"] or "").lower()


def test_external_inventory_cross_links_registered_agents(client: TestClient, monkeypatch):
    agent = _mk_agent("gcp-tiny-1", "gcp:us-central1-a")
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
                        "provider": "azure",
                        "resource_id": "vm-2",
                        "resource_type": "vm",
                        "name": "azure-orphan",
                        "zone": "eastus2-1",
                        "status": "running",
                    },
                ]
            },
        )

    monkeypatch.setattr("app.main.fetch_external_inventory", _fake_fetch_external_inventory)
    app.dependency_overrides[verify_admin_token] = _mock_verify_admin_token
    try:
        resp = client.get("/api/v1/admin/cloud/resources/external", headers=AUTH)
    finally:
        app.dependency_overrides.clear()

    assert resp.status_code == 200
    data = resp.json()
    assert data["configured"] is True
    assert data["total_resources"] == 2
    assert data["tracked_count"] == 1
    assert data["orphaned_count"] == 1

    by_id = {resource["resource_id"]: resource for resource in data["resources"]}
    assert by_id["inst-1"]["tracked"] is True
    assert by_id["inst-1"]["orphaned"] is False
    assert by_id["inst-1"]["linked_agent_id"] == agent.agent_id
    assert by_id["vm-2"]["tracked"] is False
    assert by_id["vm-2"]["orphaned"] is True


def test_external_cleanup_dispatch(client: TestClient, monkeypatch):
    async def _fake_dispatch_external_cleanup(_request: dict):
        return (
            True,
            True,
            202,
            None,
            {
                "requested_count": 4,
                "detail": "cleanup queued",
            },
        )

    monkeypatch.setattr("app.main.dispatch_external_cleanup", _fake_dispatch_external_cleanup)
    app.dependency_overrides[verify_admin_token] = _mock_verify_admin_token
    try:
        resp = client.post(
            "/api/v1/admin/cloud/resources/cleanup",
            headers=AUTH,
            json={"dry_run": False, "only_orphaned": True},
        )
    finally:
        app.dependency_overrides.clear()

    assert resp.status_code == 200
    data = resp.json()
    assert data["configured"] is True
    assert data["dispatched"] is True
    assert data["dry_run"] is False
    assert data["requested_count"] == 4
    assert data["status_code"] == 202
    assert data["detail"] == "cleanup queued"
