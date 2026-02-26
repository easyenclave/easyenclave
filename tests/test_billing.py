"""Tests for the billing API (accounts, deposits, transactions, rate card)."""

from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient

from app.auth import verify_admin_token
from app.db_models import AdminSession
from app.main import app

client = TestClient(app)


# Mock admin token verification
async def mock_verify_admin_token():
    return AdminSession(
        token_hash="x",
        token_prefix="x",
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        auth_method="password",
    )


# Helper to create account and return (account_id, api_key)
def create_test_account(name: str, account_type: str = "deployer") -> tuple[str, str]:
    """Create a test account and return (account_id, api_key)."""
    resp = client.post(
        "/api/v1/accounts",
        json={"name": name, "account_type": account_type},
    )
    assert resp.status_code == 200
    data = resp.json()
    return data["account_id"], data["api_key"]


# Helper to get auth headers
def auth_headers(api_key: str) -> dict:
    """Return Authorization headers with API key."""
    return {"Authorization": f"Bearer {api_key}"}


# =============================================================================
# Account CRUD
# =============================================================================


def test_create_account():
    resp = client.post(
        "/api/v1/accounts",
        json={"name": "alice", "account_type": "deployer"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["name"] == "alice"
    assert data["account_type"] == "deployer"
    assert data["balance"] == 0.0
    assert "account_id" in data
    assert "api_key" in data
    assert data["api_key"].startswith("ee_live_")


def test_create_account_agent_type():
    resp = client.post(
        "/api/v1/accounts",
        json={"name": "worker-1", "account_type": "agent"},
    )
    assert resp.status_code == 200
    assert resp.json()["account_type"] == "agent"


def test_create_account_contributor_type():
    resp = client.post(
        "/api/v1/accounts",
        json={"name": "contrib-1", "account_type": "contributor"},
    )
    assert resp.status_code == 200
    assert resp.json()["account_type"] == "contributor"


def test_create_account_launcher_type():
    resp = client.post(
        "/api/v1/accounts",
        json={"name": "launcher-1", "account_type": "launcher"},
    )
    assert resp.status_code == 200
    assert resp.json()["account_type"] == "launcher"


def test_create_account_invalid_type():
    resp = client.post(
        "/api/v1/accounts",
        json={"name": "bad", "account_type": "admin"},
    )
    assert resp.status_code == 400
    assert "account_type" in resp.json()["detail"]


def test_create_account_duplicate():
    client.post("/api/v1/accounts", json={"name": "dup", "account_type": "deployer"})
    resp = client.post("/api/v1/accounts", json={"name": "dup", "account_type": "deployer"})
    assert resp.status_code == 409


def test_list_accounts_empty():
    # Override admin authentication dependency
    app.dependency_overrides[verify_admin_token] = mock_verify_admin_token
    try:
        resp = client.get("/api/v1/accounts", headers={"Authorization": "Bearer admin_token"})
        assert resp.status_code == 200
        assert resp.json()["total"] == 0
    finally:
        app.dependency_overrides.clear()


def test_list_accounts():
    client.post("/api/v1/accounts", json={"name": "a1", "account_type": "deployer"})
    client.post("/api/v1/accounts", json={"name": "a2", "account_type": "agent"})

    # Override admin authentication dependency
    app.dependency_overrides[verify_admin_token] = mock_verify_admin_token
    try:
        resp = client.get("/api/v1/accounts", headers={"Authorization": "Bearer admin_token"})
        assert resp.json()["total"] == 2
    finally:
        app.dependency_overrides.clear()


def test_list_accounts_filter_type():
    client.post("/api/v1/accounts", json={"name": "d1", "account_type": "deployer"})
    client.post("/api/v1/accounts", json={"name": "a1", "account_type": "agent"})

    # Override admin authentication dependency
    app.dependency_overrides[verify_admin_token] = mock_verify_admin_token
    try:
        resp = client.get(
            "/api/v1/accounts?account_type=agent", headers={"Authorization": "Bearer admin_token"}
        )
        data = resp.json()
        assert data["total"] == 1
        assert data["accounts"][0]["account_type"] == "agent"
    finally:
        app.dependency_overrides.clear()


def test_get_account():
    account_id, api_key = create_test_account("getter", "deployer")

    resp = client.get(f"/api/v1/accounts/{account_id}", headers=auth_headers(api_key))
    assert resp.status_code == 200
    assert resp.json()["name"] == "getter"
    assert resp.json()["balance"] == 0.0


def test_link_account_identity():
    account_id, api_key = create_test_account("identity-owner", "contributor")
    resp = client.post(
        f"/api/v1/accounts/{account_id}/identity",
        json={"github_login": "alice-dev", "github_org": "easyenclave"},
        headers=auth_headers(api_key),
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["github_login"] == "alice-dev"
    assert data["github_org"] == "easyenclave"


def test_rotate_api_key_revokes_previous_key():
    account_id, api_key = create_test_account("rotator", "deployer")
    rotate_resp = client.post(
        f"/api/v1/accounts/{account_id}/api-key/rotate",
        headers=auth_headers(api_key),
    )
    assert rotate_resp.status_code == 200
    new_key = rotate_resp.json()["api_key"]

    old_access = client.get(f"/api/v1/accounts/{account_id}", headers=auth_headers(api_key))
    assert old_access.status_code == 401

    new_access = client.get(f"/api/v1/accounts/{account_id}", headers=auth_headers(new_key))
    assert new_access.status_code == 200


def test_get_account_not_found():
    account_id, api_key = create_test_account("test", "deployer")
    resp = client.get("/api/v1/accounts/nonexistent-id", headers=auth_headers(api_key))
    assert resp.status_code == 403  # Forbidden - cannot access other accounts


def test_delete_account():
    account_id, api_key = create_test_account("delme", "deployer")

    resp = client.delete(f"/api/v1/accounts/{account_id}", headers=auth_headers(api_key))
    assert resp.status_code == 200

    # Verify gone - should still return 403 because account is deleted
    resp = client.get(f"/api/v1/accounts/{account_id}", headers=auth_headers(api_key))
    assert resp.status_code == 401  # API key no longer valid


def test_delete_account_nonzero_balance():
    account_id, api_key = create_test_account("funded", "deployer")
    client.post(
        f"/api/v1/accounts/{account_id}/deposit",
        json={"amount": 10.0},
        headers=auth_headers(api_key),
    )

    resp = client.delete(f"/api/v1/accounts/{account_id}", headers=auth_headers(api_key))
    assert resp.status_code == 400
    assert "non-zero balance" in resp.json()["detail"]


def test_delete_account_not_found():
    account_id, api_key = create_test_account("test", "deployer")
    resp = client.delete("/api/v1/accounts/nonexistent-id", headers=auth_headers(api_key))
    assert resp.status_code == 403  # Cannot delete other accounts


# =============================================================================
# Deposits
# =============================================================================


def test_deposit():
    account_id, api_key = create_test_account("depo", "deployer")

    resp = client.post(
        f"/api/v1/accounts/{account_id}/deposit",
        json={"amount": 50.0, "description": "Initial funding"},
        headers=auth_headers(api_key),
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["amount"] == 50.0
    assert data["balance_after"] == 50.0
    assert data["tx_type"] == "deposit"


def test_deposit_accumulates():
    account_id, api_key = create_test_account("accum", "deployer")

    client.post(
        f"/api/v1/accounts/{account_id}/deposit",
        json={"amount": 25.0},
        headers=auth_headers(api_key),
    )
    resp = client.post(
        f"/api/v1/accounts/{account_id}/deposit",
        json={"amount": 75.0},
        headers=auth_headers(api_key),
    )
    assert resp.json()["balance_after"] == 100.0

    # Verify account balance
    acct = client.get(f"/api/v1/accounts/{account_id}", headers=auth_headers(api_key)).json()
    assert acct["balance"] == 100.0


def test_deposit_zero_rejected():
    account_id, api_key = create_test_account("zero", "deployer")

    resp = client.post(
        f"/api/v1/accounts/{account_id}/deposit",
        json={"amount": 0.0},
        headers=auth_headers(api_key),
    )
    assert resp.status_code == 422  # Pydantic validation (gt=0)


def test_deposit_negative_rejected():
    account_id, api_key = create_test_account("neg", "deployer")

    resp = client.post(
        f"/api/v1/accounts/{account_id}/deposit",
        json={"amount": -10.0},
        headers=auth_headers(api_key),
    )
    assert resp.status_code == 422


def test_deposit_nonexistent_account():
    account_id, api_key = create_test_account("test", "deployer")
    resp = client.post(
        "/api/v1/accounts/nonexistent-id/deposit",
        json={"amount": 10.0},
        headers=auth_headers(api_key),
    )
    assert resp.status_code == 403  # Cannot deposit to other accounts


# =============================================================================
# Transaction history
# =============================================================================


def test_list_transactions():
    account_id, api_key = create_test_account("txlist", "deployer")

    client.post(
        f"/api/v1/accounts/{account_id}/deposit",
        json={"amount": 10.0},
        headers=auth_headers(api_key),
    )
    client.post(
        f"/api/v1/accounts/{account_id}/deposit",
        json={"amount": 20.0},
        headers=auth_headers(api_key),
    )

    resp = client.get(
        f"/api/v1/accounts/{account_id}/transactions",
        headers=auth_headers(api_key),
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 2
    # Newest first
    assert data["transactions"][0]["amount"] == 20.0
    assert data["transactions"][1]["amount"] == 10.0


def test_list_transactions_pagination():
    account_id, api_key = create_test_account("paged", "deployer")

    for i in range(5):
        client.post(
            f"/api/v1/accounts/{account_id}/deposit",
            json={"amount": float(i + 1)},
            headers=auth_headers(api_key),
        )

    resp = client.get(
        f"/api/v1/accounts/{account_id}/transactions?limit=2&offset=0",
        headers=auth_headers(api_key),
    )
    data = resp.json()
    assert len(data["transactions"]) == 2
    assert data["total"] == 5


def test_list_transactions_empty():
    account_id, api_key = create_test_account("empty", "deployer")

    resp = client.get(
        f"/api/v1/accounts/{account_id}/transactions",
        headers=auth_headers(api_key),
    )
    assert resp.json()["total"] == 0


def test_list_transactions_account_not_found():
    account_id, api_key = create_test_account("test", "deployer")
    resp = client.get(
        "/api/v1/accounts/nonexistent-id/transactions",
        headers=auth_headers(api_key),
    )
    assert resp.status_code == 403  # Cannot access other accounts' transactions


# =============================================================================
# Rate card
# =============================================================================


def test_rate_card():
    resp = client.get("/api/v1/billing/rates")
    assert resp.status_code == 200
    data = resp.json()
    assert data["currency"] == "USD"
    assert "cpu_per_vcpu_hr" in data["rates"]
    assert data["rates"]["cpu_per_vcpu_hr"] == 0.04
    assert data["rates"]["gpu_per_gpu_hr"] == 0.50


def test_app_revenue_share_crud():
    contributor_id, _ = create_test_account("contrib-share", "contributor")
    app_resp = client.post("/api/v1/apps", json={"name": "contacts", "description": "Contacts app"})
    assert app_resp.status_code == 200

    app.dependency_overrides[verify_admin_token] = mock_verify_admin_token
    try:
        create_resp = client.post(
            "/api/v1/apps/contacts/revenue-shares",
            json={"account_id": contributor_id, "share_bps": 2500, "label": "core-dev"},
            headers={"Authorization": "Bearer admin_token"},
        )
        assert create_resp.status_code == 200
        share_id = create_resp.json()["share_id"]

        list_resp = client.get("/api/v1/apps/contacts/revenue-shares")
        assert list_resp.status_code == 200
        body = list_resp.json()
        assert body["total_bps"] == 2500
        assert body["shares"][0]["account_id"] == contributor_id

        delete_resp = client.delete(
            f"/api/v1/apps/contacts/revenue-shares/{share_id}",
            headers={"Authorization": "Bearer admin_token"},
        )
        assert delete_resp.status_code == 200
    finally:
        app.dependency_overrides.clear()
