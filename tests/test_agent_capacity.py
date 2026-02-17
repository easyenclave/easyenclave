"""Tests for agent capacity reconciliation API."""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone

from app.auth import verify_admin_token
from app.db_models import AdminSession, Agent, App, AppVersion
from app.main import _ensure_default_gcp_tiny_capacity_target, app, reconcile_capacity_targets_once
from app.settings import set_setting
from app.storage import (
    agent_store,
    app_store,
    app_version_store,
    capacity_launch_order_store,
    capacity_pool_target_store,
    capacity_reservation_store,
)


async def _mock_verify_admin_token():
    return AdminSession(
        token_hash="x",
        token_prefix="x",
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        auth_method="password",
    )


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


def test_reconcile_dispatch_queues_launch_orders_for_each_shortfall(client):
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
    assert data["dispatches"][0]["dispatched"] is True
    assert data["dispatches"][1]["dispatched"] is True

    azure_orders = capacity_launch_order_store.list(
        "open",
        datacenter="azure:eastus2-1",
        node_size="standard",
    )
    gcp_orders = capacity_launch_order_store.list(
        "open",
        datacenter="gcp:us-central1-a",
        node_size="llm",
    )
    assert len(azure_orders) == 2
    assert len(gcp_orders) == 1


def test_admin_can_list_capacity_launch_orders(client):
    capacity_launch_order_store.create_open(
        datacenter="gcp:us-central1-a",
        node_size="tiny",
        reason="test-order",
    )

    try:
        resp = client.get(
            "/api/v1/admin/agents/capacity/orders?status=open",
            headers=_admin_headers(),
        )
    finally:
        app.dependency_overrides.clear()

    assert resp.status_code == 200
    payload = resp.json()
    assert payload["total"] == 1
    assert payload["orders"][0]["status"] == "open"
    assert payload["orders"][0]["datacenter"] == "gcp:us-central1-a"


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


def test_reconcile_once_creates_open_reservation_for_target():
    agent = _mk_agent(
        vm_name="gcp-tiny-1",
        datacenter="gcp:us-central1-a",
        node_size="tiny",
    )
    agent_store.register(agent)
    capacity_pool_target_store.upsert(
        datacenter="gcp:us-central1-a",
        node_size="tiny",
        min_warm_count=1,
        enabled=True,
        dispatch=False,
    )

    stats = asyncio.run(reconcile_capacity_targets_once())
    assert stats["targets"] == 1
    assert stats["created"] == 1
    assert stats["shortfall"] == 0

    open_reservations = capacity_reservation_store.list("open")
    assert len(open_reservations) == 1
    assert open_reservations[0].agent_id == agent.agent_id
    assert open_reservations[0].datacenter == "gcp:us-central1-a"
    assert open_reservations[0].node_size == "tiny"


def test_preflight_returns_no_warm_capacity_when_targets_enabled(client):
    agent = _mk_agent(
        vm_name="gcp-tiny-2",
        datacenter="gcp:us-central1-a",
        node_size="tiny",
    )
    agent_store.register(agent)

    app_store.register(App(name="hello-tdx"))
    app_version_store.create(
        AppVersion(
            app_name="hello-tdx",
            version="1.0.0",
            node_size="tiny",
            compose="services:\n  app:\n    image: hello:latest\n",
            status="attested",
            mrtd=agent.mrtd,
            attestation={
                "measurement_type": "agent_reference",
                "node_size": "tiny",
                "rtmrs": {f"rtmr{i}": str(i) * 96 for i in range(4)},
            },
        )
    )
    capacity_pool_target_store.upsert(
        datacenter="gcp:us-central1-a",
        node_size="tiny",
        min_warm_count=1,
        enabled=True,
        dispatch=False,
    )

    resp = client.post(
        "/api/v1/apps/hello-tdx/versions/1.0.0/deploy/preflight",
        json={"node_size": "tiny", "allowed_datacenters": ["gcp:us-central1-a"]},
    )

    assert resp.status_code == 200
    data = resp.json()
    assert data["eligible"] is False
    assert any(issue["code"] == "NO_WARM_CAPACITY" for issue in data["issues"])


def test_preflight_ignores_unrelated_warm_targets(client):
    agent = _mk_agent(
        vm_name="baremetal-tiny-1",
        datacenter="baremetal:github-runner",
        node_size="tiny",
    )
    agent_store.register(agent)

    app_store.register(App(name="hello-tdx"))
    app_version_store.create(
        AppVersion(
            app_name="hello-tdx",
            version="1.0.0",
            node_size="tiny",
            compose="services:\n  app:\n    image: hello:latest\n",
            status="attested",
            mrtd=agent.mrtd,
            attestation={
                "measurement_type": "agent_reference",
                "node_size": "tiny",
                "rtmrs": {f"rtmr{i}": str(i) * 96 for i in range(4)},
            },
        )
    )
    capacity_pool_target_store.upsert(
        datacenter="gcp:us-central1-a",
        node_size="tiny",
        min_warm_count=1,
        enabled=True,
        dispatch=False,
    )

    resp = client.post(
        "/api/v1/apps/hello-tdx/versions/1.0.0/deploy/preflight",
        json={"node_size": "tiny", "allowed_datacenters": ["baremetal:github-runner"]},
    )

    assert resp.status_code == 200
    data = resp.json()
    assert data["eligible"] is True
    assert data["selected_agent_id"] == agent.agent_id
    assert not any(issue["code"] == "NO_WARM_CAPACITY" for issue in data["issues"])


def test_preflight_returns_no_verified_capacity_when_targets_enabled(client):
    agent = _mk_agent(
        vm_name="gcp-tiny-3",
        datacenter="gcp:us-central1-a",
        node_size="tiny",
        verified=False,
    )
    agent_store.register(agent)

    app_store.register(App(name="hello-tdx"))
    app_version_store.create(
        AppVersion(
            app_name="hello-tdx",
            version="1.0.0",
            node_size="tiny",
            compose="services:\n  app:\n    image: hello:latest\n",
            status="attested",
            mrtd="f" * 96,
            attestation={
                "measurement_type": "agent_reference",
                "node_size": "tiny",
                "rtmrs": {f"rtmr{i}": str(i) * 96 for i in range(4)},
            },
        )
    )
    capacity_pool_target_store.upsert(
        datacenter="gcp:us-central1-a",
        node_size="tiny",
        min_warm_count=1,
        enabled=True,
        dispatch=False,
    )

    resp = client.post(
        "/api/v1/apps/hello-tdx/versions/1.0.0/deploy/preflight",
        json={"node_size": "tiny", "allowed_datacenters": ["gcp:us-central1-a"]},
    )

    assert resp.status_code == 200
    data = resp.json()
    assert data["eligible"] is False
    assert any(issue["code"] == "NO_VERIFIED_CAPACITY" for issue in data["issues"])


def test_capacity_purchase_uses_billing_auth_and_queues_capacity(client):
    create_resp = client.post(
        "/api/v1/accounts",
        json={"name": "capacity-deployer", "account_type": "deployer"},
    )
    assert create_resp.status_code == 200
    created = create_resp.json()

    request_resp = client.post(
        f"/api/v1/accounts/{created['account_id']}/capacity/request",
        headers={"Authorization": f"Bearer {created['api_key']}"},
        json={
            "datacenter": "gcp:us-central1-a",
            "node_size": "tiny",
            "min_warm_count": 1,
            "months": 1,
            "reason": "ci-test",
        },
    )
    assert request_resp.status_code == 200
    payload = request_resp.json()

    assert payload["account_id"] == created["account_id"]
    assert payload["datacenter"] == "gcp:us-central1-a"
    assert payload["node_size"] == "tiny"
    assert payload["simulated_payment"] is True
    assert payload["charged_amount_usd"] > 0
    assert payload["capacity"]["dispatches"][0]["dispatched"] is True
    orders = capacity_launch_order_store.list(
        "open",
        datacenter="gcp:us-central1-a",
        node_size="tiny",
    )
    assert len(orders) == 1
    assert orders[0].account_id == created["account_id"]


def test_capacity_purchase_requires_funds_when_simulation_disabled(client):
    set_setting("billing.capacity_request_dev_simulation", "false")

    create_resp = client.post(
        "/api/v1/accounts",
        json={"name": "capacity-deployer-funded", "account_type": "deployer"},
    )
    assert create_resp.status_code == 200
    created = create_resp.json()

    request_resp = client.post(
        f"/api/v1/accounts/{created['account_id']}/capacity/request",
        headers={"Authorization": f"Bearer {created['api_key']}"},
        json={
            "datacenter": "gcp:us-central1-a",
            "node_size": "tiny",
            "min_warm_count": 1,
            "months": 1,
        },
    )
    assert request_resp.status_code == 400
    assert "Insufficient funds" in request_resp.json().get("detail", "")


def test_default_gcp_tiny_capacity_target_can_be_ensured_from_settings():
    set_setting("operational.default_gcp_tiny_capacity_enabled", "true")
    set_setting("operational.default_gcp_tiny_datacenter", "gcp:us-central1-a")
    set_setting("operational.default_gcp_tiny_capacity_count", "1")
    set_setting("operational.default_gcp_tiny_capacity_dispatch", "true")

    _ensure_default_gcp_tiny_capacity_target()
    targets = capacity_pool_target_store.list(enabled_only=True)
    assert len(targets) == 1
    assert targets[0].datacenter == "gcp:us-central1-a"
    assert targets[0].node_size == "tiny"
    assert targets[0].min_warm_count == 1
    assert targets[0].dispatch is True
