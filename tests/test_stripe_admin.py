"""Tests for Stripe admin status endpoint."""

import os
from datetime import datetime, timedelta, timezone

from app.auth import verify_admin_token
from app.db_models import AdminSession
from app.main import app
from app.settings import invalidate_cache


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


def test_stripe_status_requires_admin(client):
    app.dependency_overrides.clear()
    resp = client.get("/api/v1/admin/stripe/status")
    assert resp.status_code in (401, 403)


def test_stripe_status_defaults_empty(client):
    old_key = os.environ.pop("STRIPE_SECRET_KEY", None)
    old_wh = os.environ.pop("STRIPE_WEBHOOK_SECRET", None)
    invalidate_cache()
    try:
        resp = client.get("/api/v1/admin/stripe/status", headers=_admin_headers())
        assert resp.status_code == 200
        data = resp.json()
        assert data["secret_key_configured"] is False
        assert data["webhook_secret_configured"] is False
        assert data["mode"] == ""
        assert data["webhook_path"] == "/api/v1/webhooks/stripe"
    finally:
        if old_key is not None:
            os.environ["STRIPE_SECRET_KEY"] = old_key
        if old_wh is not None:
            os.environ["STRIPE_WEBHOOK_SECRET"] = old_wh
        invalidate_cache()
        app.dependency_overrides.clear()


def test_stripe_status_env_mode_test(client):
    old_key = os.environ.get("STRIPE_SECRET_KEY")
    old_wh = os.environ.get("STRIPE_WEBHOOK_SECRET")
    os.environ["STRIPE_SECRET_KEY"] = "sk_test_dummy"
    os.environ["STRIPE_WEBHOOK_SECRET"] = "whsec_dummy"
    invalidate_cache()
    try:
        resp = client.get("/api/v1/admin/stripe/status", headers=_admin_headers())
        assert resp.status_code == 200
        data = resp.json()
        assert data["secret_key_configured"] is True
        assert data["webhook_secret_configured"] is True
        assert data["mode"] == "test"
        assert data["secret_key_source"] == "env"
        assert data["webhook_secret_source"] == "env"
    finally:
        if old_key is not None:
            os.environ["STRIPE_SECRET_KEY"] = old_key
        else:
            os.environ.pop("STRIPE_SECRET_KEY", None)
        if old_wh is not None:
            os.environ["STRIPE_WEBHOOK_SECRET"] = old_wh
        else:
            os.environ.pop("STRIPE_WEBHOOK_SECRET", None)
        invalidate_cache()
        app.dependency_overrides.clear()
