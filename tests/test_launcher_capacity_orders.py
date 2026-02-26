"""Tests for launcher-key capacity launch order APIs."""

from app.storage import capacity_launch_order_store


def _create_account(client, name: str, account_type: str):
    resp = client.post("/api/v1/accounts", json={"name": name, "account_type": account_type})
    assert resp.status_code == 200
    return resp.json()


def test_launcher_can_claim_and_fulfill_capacity_order(client):
    launcher = _create_account(client, "launcher-a", "launcher")
    order = capacity_launch_order_store.create_open(
        datacenter="gcp:us-central1-a",
        node_size="tiny",
        reason="test-order",
    )

    claim_resp = client.post(
        "/api/v1/launchers/capacity/orders/claim",
        headers={"Authorization": f"Bearer {launcher['api_key']}"},
        json={"datacenter": "gcp:us-central1-a", "node_size": "tiny"},
    )
    assert claim_resp.status_code == 200
    claim_payload = claim_resp.json()
    assert claim_payload["claimed"] is True
    assert claim_payload["order"]["order_id"] == order.order_id
    assert claim_payload["order"]["status"] == "claimed"
    assert claim_payload["bootstrap_token"]

    update_resp = client.post(
        f"/api/v1/launchers/capacity/orders/{order.order_id}",
        headers={"Authorization": f"Bearer {launcher['api_key']}"},
        json={"status": "provisioning", "vm_name": "tdx-agent-123"},
    )
    assert update_resp.status_code == 200
    assert update_resp.json()["status"] == "provisioning"
    assert update_resp.json()["vm_name"] == "tdx-agent-123"

    fulfill_resp = client.post(
        f"/api/v1/launchers/capacity/orders/{order.order_id}",
        headers={"Authorization": f"Bearer {launcher['api_key']}"},
        json={"status": "fulfilled"},
    )
    assert fulfill_resp.status_code == 200
    assert fulfill_resp.json()["status"] == "fulfilled"


def test_non_launcher_account_cannot_claim_launch_order(client):
    deployer = _create_account(client, "deployer-a", "deployer")
    capacity_launch_order_store.create_open(
        datacenter="gcp:us-central1-a",
        node_size="tiny",
        reason="test-order",
    )

    claim_resp = client.post(
        "/api/v1/launchers/capacity/orders/claim",
        headers={"Authorization": f"Bearer {deployer['api_key']}"},
        json={"datacenter": "gcp:us-central1-a", "node_size": "tiny"},
    )
    assert claim_resp.status_code == 403
    assert "Launcher API key required" in claim_resp.json().get("detail", "")


def test_claim_returns_false_when_no_orders_match(client):
    launcher = _create_account(client, "launcher-b", "launcher")
    capacity_launch_order_store.create_open(
        datacenter="azure:eastus2-1",
        node_size="tiny",
        reason="test-order",
    )

    claim_resp = client.post(
        "/api/v1/launchers/capacity/orders/claim",
        headers={"Authorization": f"Bearer {launcher['api_key']}"},
        json={"datacenter": "gcp:us-central1-a", "node_size": "tiny"},
    )
    assert claim_resp.status_code == 200
    payload = claim_resp.json()
    assert payload["claimed"] is False
    assert payload["order"] is None
