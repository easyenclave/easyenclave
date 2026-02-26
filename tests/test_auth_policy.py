"""Tests for admin auth policy behavior."""

import pytest

from app.main import validate_environment
from app.settings import delete_setting, set_setting


def test_admin_password_login_can_be_disabled(client):
    set_setting("auth.password_login_enabled", "false")

    resp = client.post("/admin/login", json={"password": "anything"})
    assert resp.status_code == 403
    assert "disabled" in resp.json().get("detail", "").lower()


def test_auth_methods_disable_password_in_production_by_default(client, monkeypatch):
    monkeypatch.setenv("EASYENCLAVE_ENV", "production")
    set_setting("auth.password_login_enabled", "true")
    set_setting("auth.allow_password_login_in_production", "false")

    resp = client.get("/auth/methods")
    assert resp.status_code == 200
    payload = resp.json()
    assert payload["password"] is False


def test_validate_environment_requires_github_oauth_in_production(monkeypatch):
    monkeypatch.setenv("EASYENCLAVE_ENV", "production")
    set_setting("auth.require_github_oauth_in_production", "true")
    delete_setting("github_oauth.client_id")
    delete_setting("github_oauth.client_secret")
    delete_setting("github_oauth.redirect_uri")

    with pytest.raises(RuntimeError) as exc:
        validate_environment()
    assert "requires GitHub OAuth" in str(exc.value)
