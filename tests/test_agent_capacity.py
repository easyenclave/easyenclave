"""Tests for agent capacity reconciliation API."""

from __future__ import annotations

from app.auth import verify_admin_token
from app.db_models import Agent
from app.main import app
from app.storage import agent_store


async def _mock_verify_admin_token():
    return True


def _admin_headers():
    app.dependency_overrides[verify_admin_token] = _mock_verify_admin_token
    return {"Authorization": "Bearer mock_token"}


def _mk_agent(
    *,
    vm_name: str,
    datacenter: str,
    node_size: str,
    verified: bool = True,
    health_status: str = "healthy",
    status: str = "undeployed",
    hostname: str = "agent.example.com",
) -> Agent:
    return Agent(
        vm_name=vm_name,
        attestation={"tdx": {"intel_ta_token": "fake.token"}},
        mrtd="f" * 96,
        verified=verified,
        health_status=health_status,
        status=status,
        hostname=hostname,
        node_size=node_size,
        datacenter=datacenter,
    )


def test_reconcile_reports_shortfall_per_target(client):
    agent_store.register(
        _mk_agent(vm_name="gcp-llm-1", datacenter="gcp:us-central1-a", node_size="llm")
    )
    agent_store.register(
        _mk_agent(vm_name="azure-llm-1", datacenter="azure:eastus2-1", node_size="llm")
    )

    try:
        resp = client.post(
            "/api/v1/admin/agents/capacity/reconcile",
            json={
                "targets": [
                    {"datacenter": "gcp:us-central1-a", "node_size": "llm", "min_count": 2},
                    {"datacenter": "azure:eastus2-1", "node_size": "llm", "min_count": 1},
                    {
                        "datacenter": "baremetal:github-runner",
                        "node_size": "standard",
                        "min_count": 1,
                    },
                ]
            },
            headers=_admin_headers(),
        )
    finally:
        app.dependency_overrides.clear()

    assert resp.status_code == 200
    data = resp.json()
    assert data["eligible"] is False
    assert data["total_shortfall"] == 2

    by_key = {(t["datacenter"], t["node_size"]): t for t in data["targets"]}
    assert by_key[("gcp:us-central1-a", "llm")]["eligible_count"] == 1
    assert by_key[("gcp:us-central1-a", "llm")]["shortfall"] == 1
    assert by_key[("azure:eastus2-1", "llm")]["eligible_count"] == 1
    assert by_key[("azure:eastus2-1", "llm")]["shortfall"] == 0
    assert by_key[("baremetal:github-runner", "standard")]["eligible_count"] == 0
    assert by_key[("baremetal:github-runner", "standard")]["shortfall"] == 1


def test_reconcile_default_filters_exclude_unhealthy_unverified_and_no_hostname(client):
    agent_store.register(
        _mk_agent(
            vm_name="gcp-unverified",
            datacenter="gcp:us-central1-a",
            node_size="standard",
            verified=False,
        )
    )
    agent_store.register(
        _mk_agent(
            vm_name="gcp-unhealthy",
            datacenter="gcp:us-central1-a",
            node_size="standard",
            health_status="unhealthy",
        )
    )
    agent_store.register(
        _mk_agent(
            vm_name="gcp-no-hostname",
            datacenter="gcp:us-central1-a",
            node_size="standard",
            hostname="",
        )
    )
    agent_store.register(
        _mk_agent(
            vm_name="gcp-good",
            datacenter="gcp:us-central1-a",
            node_size="standard",
        )
    )

    try:
        resp = client.post(
            "/api/v1/admin/agents/capacity/reconcile",
            json={
                "targets": [
                    {"datacenter": "gcp:us-central1-a", "node_size": "standard", "min_count": 2}
                ]
            },
            headers=_admin_headers(),
        )
    finally:
        app.dependency_overrides.clear()

    assert resp.status_code == 200
    data = resp.json()
    assert data["total_shortfall"] == 1
    assert data["targets"][0]["eligible_count"] == 1
    assert data["targets"][0]["shortfall"] == 1


def test_reconcile_dispatch_calls_provisioner_for_each_shortfall(client, monkeypatch):
    calls: list[tuple[str, str, int, str]] = []

    async def _fake_dispatch_provision_request(
        *, datacenter: str, node_size: str, count: int, reason: str
    ):
        calls.append((datacenter, node_size, count, reason))
        return (True, 202, None)

    monkeypatch.setattr("app.main.dispatch_provision_request", _fake_dispatch_provision_request)
    agent_store.register(
        _mk_agent(vm_name="azure-std-1", datacenter="azure:eastus2-1", node_size="standard")
    )

    try:
        resp = client.post(
            "/api/v1/admin/agents/capacity/reconcile",
            json={
                "targets": [
                    {"datacenter": "azure:eastus2-1", "node_size": "standard", "min_count": 3},
                    {"datacenter": "gcp:us-central1-a", "node_size": "llm", "min_count": 1},
                ],
                "dispatch": True,
                "reason": "ci-cloud-check",
            },
            headers=_admin_headers(),
        )
    finally:
        app.dependency_overrides.clear()

    assert resp.status_code == 200
    data = resp.json()
    assert data["total_shortfall"] == 3
    assert len(data["dispatches"]) == 2
    assert calls == [
        ("azure:eastus2-1", "standard", 2, "ci-cloud-check"),
        ("gcp:us-central1-a", "llm", 1, "ci-cloud-check"),
    ]


def test_reconcile_requires_admin_auth(client):
    resp = client.post(
        "/api/v1/admin/agents/capacity/reconcile",
        json={
            "targets": [
                {"datacenter": "gcp:us-central1-a", "node_size": "standard", "min_count": 1}
            ]
        },
    )
    assert resp.status_code in (401, 403)
