"""Tests for the measuring enclave flow."""

import base64

import pytest
from fastapi.testclient import TestClient

from app.auth import verify_admin_token
from app.main import app
from app.storage import app_version_store


# Mock admin token verification
async def mock_verify_admin_token():
    return True


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def admin_token(client):
    """Get a mock admin auth token."""
    # Mock admin authentication since ADMIN_PASSWORD_HASH may not be set in tests
    return "mock_admin_token"


@pytest.fixture
def sample_app(client):
    """Register a test app."""
    client.post(
        "/api/v1/apps",
        json={"name": "test-app", "description": "Test app"},
    )
    return "test-app"


@pytest.fixture
def sample_compose():
    """Base64-encoded compose file."""
    compose_yaml = b"services:\n  web:\n    image: nginx:latest\n"
    return base64.b64encode(compose_yaml).decode()


class TestPublishStaysPending:
    def test_publish_returns_pending(self, client, sample_app, sample_compose):
        """Publishing a version should return status 'pending', not 'attested'."""
        resp = client.post(
            f"/api/v1/apps/{sample_app}/versions",
            json={"version": "1.0.0", "compose": sample_compose},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "pending"
        assert data["version"] == "1.0.0"

    def test_pending_version_cannot_be_deployed(self, client, sample_app, sample_compose):
        """A pending version should not be deployable."""
        client.post(
            f"/api/v1/apps/{sample_app}/versions",
            json={"version": "1.0.0", "compose": sample_compose},
        )
        resp = client.post(
            f"/api/v1/apps/{sample_app}/versions/1.0.0/deploy",
            json={"agent_id": "fake-agent"},
        )
        assert resp.status_code == 400
        assert "not attested" in resp.json()["detail"]


class TestMeasurementCallback:
    def test_callback_success(self, client, sample_app, sample_compose):
        """Successful measurement callback should set status to 'attested'."""
        pub = client.post(
            f"/api/v1/apps/{sample_app}/versions",
            json={"version": "1.0.0", "compose": sample_compose},
        )
        version_id = pub.json()["version_id"]

        measurement = {
            "compose_hash": "abc123",
            "resolved_images": {"web": {"original": "nginx:latest", "digest": "sha256:def456"}},
        }
        resp = client.post(
            "/api/v1/internal/measurement-callback",
            json={
                "version_id": version_id,
                "status": "success",
                "measurement": measurement,
            },
        )
        assert resp.status_code == 200

        # Check version is now attested
        ver = client.get(f"/api/v1/apps/{sample_app}/versions/1.0.0")
        assert ver.json()["status"] == "attested"
        assert ver.json()["attestation"] == measurement

    def test_callback_failure(self, client, sample_app, sample_compose):
        """Failed measurement callback should set status to 'failed'."""
        pub = client.post(
            f"/api/v1/apps/{sample_app}/versions",
            json={"version": "1.0.0", "compose": sample_compose},
        )
        version_id = pub.json()["version_id"]

        resp = client.post(
            "/api/v1/internal/measurement-callback",
            json={
                "version_id": version_id,
                "status": "failed",
                "error": "Could not resolve image",
            },
        )
        assert resp.status_code == 200

        ver = client.get(f"/api/v1/apps/{sample_app}/versions/1.0.0")
        assert ver.json()["status"] == "failed"
        assert ver.json()["rejection_reason"] == "Could not resolve image"

    def test_callback_not_found(self, client):
        """Callback for non-existent version should return 404."""
        resp = client.post(
            "/api/v1/internal/measurement-callback",
            json={"version_id": "nonexistent", "status": "success"},
        )
        assert resp.status_code == 404


class TestManualAttest:
    def test_manual_attest(self, client, admin_token, sample_app, sample_compose):
        """Admin can manually attest a version (bootstrap flow)."""
        client.post(
            f"/api/v1/apps/{sample_app}/versions",
            json={"version": "1.0.0", "compose": sample_compose},
        )

        # Override admin authentication dependency
        app.dependency_overrides[verify_admin_token] = mock_verify_admin_token
        try:
            resp = client.post(
                f"/api/v1/apps/{sample_app}/versions/1.0.0/attest",
                headers={"Authorization": f"Bearer {admin_token}"},
            )
            assert resp.status_code == 200
            assert resp.json()["status"] == "attested"
        finally:
            app.dependency_overrides.clear()

        # Verify version is now attested
        ver = client.get(f"/api/v1/apps/{sample_app}/versions/1.0.0")
        assert ver.json()["status"] == "attested"

    def test_manual_attest_requires_auth(self, client, sample_app, sample_compose):
        """Manual attest without auth should fail."""
        client.post(
            f"/api/v1/apps/{sample_app}/versions",
            json={"version": "1.0.0", "compose": sample_compose},
        )

        resp = client.post(f"/api/v1/apps/{sample_app}/versions/1.0.0/attest")
        assert resp.status_code == 401

    def test_manual_attest_invalid_token(self, client, sample_app, sample_compose):
        """Manual attest with bad token should fail."""
        client.post(
            f"/api/v1/apps/{sample_app}/versions",
            json={"version": "1.0.0", "compose": sample_compose},
        )

        resp = client.post(
            f"/api/v1/apps/{sample_app}/versions/1.0.0/attest",
            headers={"Authorization": "Bearer invalid-token"},
        )
        assert resp.status_code == 401

    def test_manual_attest_not_found(self, client, admin_token, sample_app):
        """Manual attest of nonexistent version should 404."""
        # Override admin authentication dependency
        app.dependency_overrides[verify_admin_token] = mock_verify_admin_token
        try:
            resp = client.post(
                f"/api/v1/apps/{sample_app}/versions/nonexistent/attest",
                headers={"Authorization": f"Bearer {admin_token}"},
            )
            assert resp.status_code == 404
        finally:
            app.dependency_overrides.clear()


class TestListByStatus:
    def test_list_by_status(self, sample_app, sample_compose):
        """AppVersionStore.list_by_status should return matching versions."""
        from app.models import AppVersion

        v1 = AppVersion(
            app_name="test-app", version="1.0.0", compose=sample_compose, status="pending"
        )
        v2 = AppVersion(
            app_name="test-app", version="2.0.0", compose=sample_compose, status="attested"
        )
        v3 = AppVersion(
            app_name="test-app", version="3.0.0", compose=sample_compose, status="pending"
        )

        app_version_store.create(v1)
        app_version_store.create(v2)
        app_version_store.create(v3)

        pending = app_version_store.list_by_status("pending")
        assert len(pending) == 2
        assert all(v.status == "pending" for v in pending)

        attested = app_version_store.list_by_status("attested")
        assert len(attested) == 1
        assert attested[0].version == "2.0.0"
