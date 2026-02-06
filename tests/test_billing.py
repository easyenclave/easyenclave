"""Tests for the billing API (accounts, deposits, transactions, rate card)."""

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


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


def test_create_account_agent_type():
    resp = client.post(
        "/api/v1/accounts",
        json={"name": "worker-1", "account_type": "agent"},
    )
    assert resp.status_code == 200
    assert resp.json()["account_type"] == "agent"


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
    resp = client.get("/api/v1/accounts")
    assert resp.status_code == 200
    assert resp.json()["total"] == 0


def test_list_accounts():
    client.post("/api/v1/accounts", json={"name": "a1", "account_type": "deployer"})
    client.post("/api/v1/accounts", json={"name": "a2", "account_type": "agent"})
    resp = client.get("/api/v1/accounts")
    assert resp.json()["total"] == 2


def test_list_accounts_filter_type():
    client.post("/api/v1/accounts", json={"name": "d1", "account_type": "deployer"})
    client.post("/api/v1/accounts", json={"name": "a1", "account_type": "agent"})
    resp = client.get("/api/v1/accounts?account_type=agent")
    data = resp.json()
    assert data["total"] == 1
    assert data["accounts"][0]["account_type"] == "agent"


def test_get_account():
    create_resp = client.post(
        "/api/v1/accounts", json={"name": "getter", "account_type": "deployer"}
    )
    account_id = create_resp.json()["account_id"]

    resp = client.get(f"/api/v1/accounts/{account_id}")
    assert resp.status_code == 200
    assert resp.json()["name"] == "getter"
    assert resp.json()["balance"] == 0.0


def test_get_account_not_found():
    resp = client.get("/api/v1/accounts/nonexistent-id")
    assert resp.status_code == 404


def test_delete_account():
    create_resp = client.post(
        "/api/v1/accounts", json={"name": "delme", "account_type": "deployer"}
    )
    account_id = create_resp.json()["account_id"]

    resp = client.delete(f"/api/v1/accounts/{account_id}")
    assert resp.status_code == 200

    # Verify gone
    resp = client.get(f"/api/v1/accounts/{account_id}")
    assert resp.status_code == 404


def test_delete_account_nonzero_balance():
    create_resp = client.post(
        "/api/v1/accounts", json={"name": "funded", "account_type": "deployer"}
    )
    account_id = create_resp.json()["account_id"]
    client.post(
        f"/api/v1/accounts/{account_id}/deposit",
        json={"amount": 10.0},
    )

    resp = client.delete(f"/api/v1/accounts/{account_id}")
    assert resp.status_code == 400
    assert "non-zero balance" in resp.json()["detail"]


def test_delete_account_not_found():
    resp = client.delete("/api/v1/accounts/nonexistent-id")
    assert resp.status_code == 404


# =============================================================================
# Deposits
# =============================================================================


def test_deposit():
    create_resp = client.post("/api/v1/accounts", json={"name": "depo", "account_type": "deployer"})
    account_id = create_resp.json()["account_id"]

    resp = client.post(
        f"/api/v1/accounts/{account_id}/deposit",
        json={"amount": 50.0, "description": "Initial funding"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["amount"] == 50.0
    assert data["balance_after"] == 50.0
    assert data["tx_type"] == "deposit"


def test_deposit_accumulates():
    create_resp = client.post(
        "/api/v1/accounts", json={"name": "accum", "account_type": "deployer"}
    )
    account_id = create_resp.json()["account_id"]

    client.post(f"/api/v1/accounts/{account_id}/deposit", json={"amount": 25.0})
    resp = client.post(f"/api/v1/accounts/{account_id}/deposit", json={"amount": 75.0})
    assert resp.json()["balance_after"] == 100.0

    # Verify account balance
    acct = client.get(f"/api/v1/accounts/{account_id}").json()
    assert acct["balance"] == 100.0


def test_deposit_zero_rejected():
    create_resp = client.post("/api/v1/accounts", json={"name": "zero", "account_type": "deployer"})
    account_id = create_resp.json()["account_id"]

    resp = client.post(
        f"/api/v1/accounts/{account_id}/deposit",
        json={"amount": 0.0},
    )
    assert resp.status_code == 422  # Pydantic validation (gt=0)


def test_deposit_negative_rejected():
    create_resp = client.post("/api/v1/accounts", json={"name": "neg", "account_type": "deployer"})
    account_id = create_resp.json()["account_id"]

    resp = client.post(
        f"/api/v1/accounts/{account_id}/deposit",
        json={"amount": -10.0},
    )
    assert resp.status_code == 422


def test_deposit_nonexistent_account():
    resp = client.post(
        "/api/v1/accounts/nonexistent-id/deposit",
        json={"amount": 10.0},
    )
    assert resp.status_code == 404


# =============================================================================
# Transaction history
# =============================================================================


def test_list_transactions():
    create_resp = client.post(
        "/api/v1/accounts", json={"name": "txlist", "account_type": "deployer"}
    )
    account_id = create_resp.json()["account_id"]

    client.post(f"/api/v1/accounts/{account_id}/deposit", json={"amount": 10.0})
    client.post(f"/api/v1/accounts/{account_id}/deposit", json={"amount": 20.0})

    resp = client.get(f"/api/v1/accounts/{account_id}/transactions")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 2
    # Newest first
    assert data["transactions"][0]["amount"] == 20.0
    assert data["transactions"][1]["amount"] == 10.0


def test_list_transactions_pagination():
    create_resp = client.post(
        "/api/v1/accounts", json={"name": "paged", "account_type": "deployer"}
    )
    account_id = create_resp.json()["account_id"]

    for i in range(5):
        client.post(
            f"/api/v1/accounts/{account_id}/deposit",
            json={"amount": float(i + 1)},
        )

    resp = client.get(f"/api/v1/accounts/{account_id}/transactions?limit=2&offset=0")
    data = resp.json()
    assert len(data["transactions"]) == 2
    assert data["total"] == 5


def test_list_transactions_empty():
    create_resp = client.post(
        "/api/v1/accounts", json={"name": "empty", "account_type": "deployer"}
    )
    account_id = create_resp.json()["account_id"]

    resp = client.get(f"/api/v1/accounts/{account_id}/transactions")
    assert resp.json()["total"] == 0


def test_list_transactions_account_not_found():
    resp = client.get("/api/v1/accounts/nonexistent-id/transactions")
    assert resp.status_code == 404


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
