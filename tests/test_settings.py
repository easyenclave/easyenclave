"""Tests for DB-backed settings system."""

import os

import pytest

from app.auth import verify_admin_token
from app.main import app


async def _mock_verify_admin_token():
    return True


def _admin_headers():
    app.dependency_overrides[verify_admin_token] = _mock_verify_admin_token
    return {"Authorization": "Bearer mock_token"}


# ── Resolution order ─────────────────────────────────────────────────────────


def test_default_value():
    """Setting returns default when no DB or env value."""
    from app.settings import get_setting, get_setting_source

    # cloudflare.domain has default "easyenclave.com"
    # Remove env var if set
    old = os.environ.pop("EASYENCLAVE_DOMAIN", None)
    try:
        assert get_setting("cloudflare.domain") == "easyenclave.com"
        assert get_setting_source("cloudflare.domain") == "default"
    finally:
        if old is not None:
            os.environ["EASYENCLAVE_DOMAIN"] = old


def test_env_overrides_default():
    """Env var overrides default."""
    from app.settings import get_setting, get_setting_source, invalidate_cache

    old = os.environ.get("EASYENCLAVE_DOMAIN")
    os.environ["EASYENCLAVE_DOMAIN"] = "test.example.com"
    invalidate_cache()
    try:
        assert get_setting("cloudflare.domain") == "test.example.com"
        assert get_setting_source("cloudflare.domain") == "env"
    finally:
        if old is not None:
            os.environ["EASYENCLAVE_DOMAIN"] = old
        else:
            del os.environ["EASYENCLAVE_DOMAIN"]
        invalidate_cache()


def test_db_overrides_env():
    """DB value overrides env var."""
    from app.settings import get_setting, get_setting_source, invalidate_cache, set_setting

    old = os.environ.get("EASYENCLAVE_DOMAIN")
    os.environ["EASYENCLAVE_DOMAIN"] = "env.example.com"
    invalidate_cache()
    try:
        set_setting("cloudflare.domain", "db.example.com")
        assert get_setting("cloudflare.domain") == "db.example.com"
        assert get_setting_source("cloudflare.domain") == "db"
    finally:
        if old is not None:
            os.environ["EASYENCLAVE_DOMAIN"] = old
        else:
            del os.environ["EASYENCLAVE_DOMAIN"]
        invalidate_cache()


def test_delete_reverts_to_env():
    """Deleting a DB setting reverts to env var."""
    from app.settings import (
        delete_setting,
        get_setting,
        get_setting_source,
        invalidate_cache,
        set_setting,
    )

    old = os.environ.get("EASYENCLAVE_DOMAIN")
    os.environ["EASYENCLAVE_DOMAIN"] = "env.example.com"
    invalidate_cache()
    try:
        set_setting("cloudflare.domain", "db.example.com")
        assert get_setting_source("cloudflare.domain") == "db"

        delete_setting("cloudflare.domain")
        assert get_setting("cloudflare.domain") == "env.example.com"
        assert get_setting_source("cloudflare.domain") == "env"
    finally:
        if old is not None:
            os.environ["EASYENCLAVE_DOMAIN"] = old
        else:
            del os.environ["EASYENCLAVE_DOMAIN"]
        invalidate_cache()


# ── Type helpers ─────────────────────────────────────────────────────────────


def test_get_setting_int():
    """get_setting_int returns integer."""
    from app.settings import get_setting_int, set_setting

    set_setting("operational.nonce_ttl_seconds", "600")
    assert get_setting_int("operational.nonce_ttl_seconds") == 600


def test_get_setting_int_fallback():
    """get_setting_int uses fallback on bad value."""
    from app.settings import get_setting_int, set_setting

    set_setting("operational.nonce_ttl_seconds", "not-a-number")
    assert get_setting_int("operational.nonce_ttl_seconds", fallback=42) == 42


def test_get_setting_set():
    """get_setting_set splits comma-separated values."""
    from app.settings import get_setting_set, set_setting

    set_setting("operational.allowed_tcb_statuses", "UpToDate, SWHardeningNeeded")
    result = get_setting_set("operational.allowed_tcb_statuses")
    assert result == {"UpToDate", "SWHardeningNeeded"}


# ── List & masking ───────────────────────────────────────────────────────────


def test_list_with_group_filter():
    """list_settings filters by group."""
    from app.settings import list_settings

    stripe_settings = list_settings(group="stripe")
    assert len(stripe_settings) == 2
    assert all(s["group"] == "stripe" for s in stripe_settings)


def test_secret_masking():
    """Secret values are masked in list_settings."""
    from app.settings import list_settings, set_setting

    set_setting("cloudflare.api_token", "abcdefghijklmnop")
    settings = list_settings(group="cloudflare")
    token_setting = next(s for s in settings if s["key"] == "cloudflare.api_token")
    assert token_setting["is_secret"] is True
    assert token_setting["value"] == "abcd****mnop"
    assert "abcdefghijklmnop" not in token_setting["value"]


# ── Unknown key ──────────────────────────────────────────────────────────────


def test_unknown_key_raises():
    """Getting an unknown key raises KeyError."""
    from app.settings import get_setting

    with pytest.raises(KeyError, match="Unknown setting"):
        get_setting("nonexistent.key")


# ── API routes ───────────────────────────────────────────────────────────────


def test_api_list_settings(client):
    """GET /api/v1/admin/settings returns all settings."""
    resp = client.get("/api/v1/admin/settings", headers=_admin_headers())
    assert resp.status_code == 200
    data = resp.json()
    assert "settings" in data
    assert len(data["settings"]) == 21  # total settings defined
    app.dependency_overrides.clear()


def test_api_list_settings_with_group(client):
    """GET /api/v1/admin/settings?group=cloudflare filters by group."""
    resp = client.get(
        "/api/v1/admin/settings?group=cloudflare",
        headers=_admin_headers(),
    )
    assert resp.status_code == 200
    data = resp.json()
    assert all(s["group"] == "cloudflare" for s in data["settings"])
    app.dependency_overrides.clear()


def test_api_update_setting(client):
    """PUT /api/v1/admin/settings/{key} saves to DB."""
    resp = client.put(
        "/api/v1/admin/settings/cloudflare.domain",
        json={"value": "test.com"},
        headers=_admin_headers(),
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "saved"

    # Verify it's now in DB
    from app.settings import get_setting, get_setting_source

    assert get_setting("cloudflare.domain") == "test.com"
    assert get_setting_source("cloudflare.domain") == "db"
    app.dependency_overrides.clear()


def test_api_reset_setting(client):
    """DELETE /api/v1/admin/settings/{key} removes from DB."""
    from app.settings import set_setting

    set_setting("cloudflare.domain", "saved.com")

    resp = client.delete(
        "/api/v1/admin/settings/cloudflare.domain",
        headers=_admin_headers(),
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "reset"
    app.dependency_overrides.clear()


def test_api_auth_required(client):
    """Settings endpoints require admin auth."""
    app.dependency_overrides.clear()
    resp = client.get("/api/v1/admin/settings")
    assert resp.status_code in (401, 403)


def test_api_unknown_key_404(client):
    """PUT/DELETE unknown key returns 404."""
    resp = client.put(
        "/api/v1/admin/settings/nonexistent.key",
        json={"value": "test"},
        headers=_admin_headers(),
    )
    assert resp.status_code == 404

    resp = client.delete(
        "/api/v1/admin/settings/nonexistent.key",
        headers=_admin_headers(),
    )
    assert resp.status_code == 404
    app.dependency_overrides.clear()
