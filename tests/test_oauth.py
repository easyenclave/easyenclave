"""Tests for GitHub OAuth authentication."""

import pytest

from app.oauth import (
    GITHUB_CLIENT_ID,
    create_oauth_state,
    get_github_authorize_url,
    verify_oauth_state,
)


def test_create_and_verify_oauth_state():
    """Test CSRF state token creation and verification."""
    state = create_oauth_state()
    assert len(state) > 20
    assert verify_oauth_state(state)


def test_verify_oauth_state_rejects_invalid():
    """Test that invalid state tokens are rejected."""
    assert not verify_oauth_state("invalid-state-token")


def test_verify_oauth_state_one_time_use():
    """Test that state tokens can only be used once."""
    state = create_oauth_state()
    assert verify_oauth_state(state)
    assert not verify_oauth_state(state)  # Should fail on second use


@pytest.mark.skipif(not GITHUB_CLIENT_ID, reason="GitHub OAuth not configured")
def test_github_authorize_url():
    """Test GitHub OAuth authorization URL generation."""
    url = get_github_authorize_url("test-state")
    assert "github.com/login/oauth/authorize" in url
    assert "client_id=" in url
    assert "state=test-state" in url
    assert "scope=read:user" in url


def test_github_authorize_url_requires_config(monkeypatch):
    """Test that authorize URL requires GitHub OAuth configuration."""
    from fastapi import HTTPException

    monkeypatch.setattr("app.oauth.GITHUB_CLIENT_ID", None)

    with pytest.raises(HTTPException) as exc_info:
        get_github_authorize_url("test-state")
    assert exc_info.value.status_code == 503


def test_oauth_start_endpoint(client, monkeypatch):
    """Test GitHub OAuth start endpoint."""
    monkeypatch.setattr("app.oauth.GITHUB_CLIENT_ID", "test-client-id")

    resp = client.get("/auth/github")
    assert resp.status_code == 200
    data = resp.json()
    assert "auth_url" in data
    assert "state" in data
    assert "github.com/login/oauth/authorize" in data["auth_url"]


def test_oauth_start_endpoint_not_configured(client, monkeypatch):
    """Test OAuth start endpoint when not configured."""
    monkeypatch.setattr("app.oauth.GITHUB_CLIENT_ID", None)

    resp = client.get("/auth/github")
    assert resp.status_code == 503
    assert "not configured" in resp.json()["detail"].lower()


def test_oauth_callback_invalid_state(client):
    """Test OAuth callback with invalid state token."""
    resp = client.get("/auth/github/callback?code=test-code&state=invalid-state")
    assert resp.status_code == 400
    assert "invalid or expired state" in resp.json()["detail"].lower()


def test_oauth_integration_flow(client, monkeypatch):
    """Test complete OAuth flow integration."""

    async def mock_exchange(code: str):
        return "gho_test_token_from_github"

    async def mock_get_user(token: str):
        return {
            "github_id": 99999,
            "github_login": "oauthuser",
            "github_email": "oauth@example.com",
            "github_avatar_url": "https://avatars.githubusercontent.com/u/99999",
        }

    # Mock the OAuth functions imported in main.py
    import app.oauth as oauth_module

    monkeypatch.setattr(oauth_module, "GITHUB_CLIENT_ID", "test-client-id")
    monkeypatch.setattr(oauth_module, "GITHUB_CLIENT_SECRET", "test-client-secret")
    monkeypatch.setattr(oauth_module, "exchange_code_for_token", mock_exchange)
    monkeypatch.setattr(oauth_module, "get_github_user", mock_get_user)

    # Step 1: Start OAuth flow
    resp = client.get("/auth/github")
    assert resp.status_code == 200
    data = resp.json()
    assert "auth_url" in data
    assert "state" in data
    state = data["state"]

    # Step 2: Callback with code
    resp = client.get(f"/auth/github/callback?code=test-code&state={state}", follow_redirects=False)
    assert resp.status_code == 302
    assert "/admin?token=" in resp.headers["location"]

    # Extract token from redirect
    token = resp.headers["location"].split("token=")[1]

    # Step 3: Verify we can use the token
    resp = client.get("/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    assert resp.json()["authenticated"] is True
