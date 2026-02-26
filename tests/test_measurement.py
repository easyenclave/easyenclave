"""Tests for the measuring enclave flow."""

import base64
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from app.auth import verify_admin_token
from app.db_models import AdminSession, Agent
from app.main import app
from app.storage import agent_control_credential_store, agent_store, app_version_store


# Mock admin token verification
async def mock_verify_admin_token():
    return AdminSession(
        token_hash="x",
        token_prefix="x",
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        auth_method="password",
    )


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

    def test_publish_with_node_size(self, client, sample_app, sample_compose):
        """Publishing a version with node_size should store it."""
        resp = client.post(
            f"/api/v1/apps/{sample_app}/versions",
            json={"version": "1.0.0", "compose": sample_compose, "node_size": "tiny"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["node_size"] == "tiny"

    def test_same_version_different_sizes(self, client, sample_app, sample_compose):
        """Same version string can exist for different node_sizes."""
        resp1 = client.post(
            f"/api/v1/apps/{sample_app}/versions",
            json={"version": "1.0.0", "compose": sample_compose, "node_size": "tiny"},
        )
        assert resp1.status_code == 200

        resp2 = client.post(
            f"/api/v1/apps/{sample_app}/versions",
            json={"version": "1.0.0", "compose": sample_compose, "node_size": "llm"},
        )
        assert resp2.status_code == 200
        assert resp1.json()["version_id"] != resp2.json()["version_id"]

    def test_duplicate_version_same_size_rejected(self, client, sample_app, sample_compose):
        """Duplicate (version, node_size) should be rejected with 409."""
        client.post(
            f"/api/v1/apps/{sample_app}/versions",
            json={"version": "1.0.0", "compose": sample_compose, "node_size": "tiny"},
        )
        resp = client.post(
            f"/api/v1/apps/{sample_app}/versions",
            json={"version": "1.0.0", "compose": sample_compose, "node_size": "tiny"},
        )
        assert resp.status_code == 409

    def test_get_version_with_node_size(self, client, sample_app, sample_compose):
        """get_app_version should filter by node_size query param."""
        client.post(
            f"/api/v1/apps/{sample_app}/versions",
            json={"version": "1.0.0", "compose": sample_compose, "node_size": "tiny"},
        )
        client.post(
            f"/api/v1/apps/{sample_app}/versions",
            json={"version": "1.0.0", "compose": sample_compose, "node_size": "llm"},
        )

        resp_tiny = client.get(f"/api/v1/apps/{sample_app}/versions/1.0.0?node_size=tiny")
        assert resp_tiny.status_code == 200
        assert resp_tiny.json()["node_size"] == "tiny"

        resp_llm = client.get(f"/api/v1/apps/{sample_app}/versions/1.0.0?node_size=llm")
        assert resp_llm.status_code == 200
        assert resp_llm.json()["node_size"] == "llm"

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
        # Agent not found (fake-agent), but let's verify the flow
        assert resp.status_code in (400, 404)


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
            "mrtd": "deadbeef" * 12,
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
        assert ver.json()["mrtd"] == measurement["mrtd"]
        assert ver.json()["attestation"] == measurement

    def test_callback_signature_strict_rejects_unverified_images(
        self, client, sample_app, sample_compose
    ):
        from app.settings import set_setting

        set_setting("operational.signature_verification_mode", "strict")

        pub = client.post(
            f"/api/v1/apps/{sample_app}/versions",
            json={"version": "1.0.0", "compose": sample_compose},
        )
        version_id = pub.json()["version_id"]

        measurement = {
            "compose_hash": "abc123",
            "resolved_images": {
                "web": {
                    "original": "nginx:latest",
                    "digest": "sha256:def456",
                    "signature_verified": False,
                    "signature_error": "no valid signature found",
                }
            },
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

        ver = client.get(f"/api/v1/apps/{sample_app}/versions/1.0.0")
        assert ver.json()["status"] == "failed"
        assert "Image signature verification failed" in ver.json()["rejection_reason"]

    def test_callback_signature_warn_allows_unverified_images(
        self, client, sample_app, sample_compose
    ):
        from app.settings import set_setting

        set_setting("operational.signature_verification_mode", "warn")

        pub = client.post(
            f"/api/v1/apps/{sample_app}/versions",
            json={"version": "1.0.0", "compose": sample_compose},
        )
        version_id = pub.json()["version_id"]

        measurement = {
            "compose_hash": "abc123",
            "mrtd": "deadbeef" * 12,
            "resolved_images": {
                "web": {
                    "original": "nginx:latest",
                    "digest": "sha256:def456",
                    "signature_verified": False,
                    "signature_error": "no valid signature found",
                }
            },
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

        ver = client.get(f"/api/v1/apps/{sample_app}/versions/1.0.0")
        assert ver.json()["status"] == "attested"

    def test_callback_signature_disabled_skips_checks(self, client, sample_app, sample_compose):
        from app.settings import set_setting

        set_setting("operational.signature_verification_mode", "disabled")

        pub = client.post(
            f"/api/v1/apps/{sample_app}/versions",
            json={"version": "1.0.0", "compose": sample_compose},
        )
        version_id = pub.json()["version_id"]

        measurement = {
            "compose_hash": "abc123",
            "mrtd": "deadbeef" * 12,
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

        ver = client.get(f"/api/v1/apps/{sample_app}/versions/1.0.0")
        assert ver.json()["status"] == "attested"

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

    def test_manual_attest_with_node_size(self, client, admin_token, sample_app, sample_compose):
        """Admin can manually attest a version for a specific node_size."""
        client.post(
            f"/api/v1/apps/{sample_app}/versions",
            json={"version": "1.0.0", "compose": sample_compose, "node_size": "tiny"},
        )

        app.dependency_overrides[verify_admin_token] = mock_verify_admin_token
        try:
            resp = client.post(
                f"/api/v1/apps/{sample_app}/versions/1.0.0/attest?node_size=tiny",
                headers={"Authorization": f"Bearer {admin_token}"},
            )
            assert resp.status_code == 200
            assert resp.json()["status"] == "attested"
        finally:
            app.dependency_overrides.clear()

        # Verify only the tiny version is attested
        ver = client.get(f"/api/v1/apps/{sample_app}/versions/1.0.0?node_size=tiny")
        assert ver.json()["status"] == "attested"

    def test_manual_attest_with_measurement_metadata(
        self, client, admin_token, sample_app, sample_compose
    ):
        """Manual attestation can persist node-size-specific measurement metadata."""
        client.post(
            f"/api/v1/apps/{sample_app}/versions",
            json={"version": "1.0.0", "compose": sample_compose, "node_size": "llm"},
        )

        payload = {
            "mrtd": "cafebabe" * 12,
            "attestation": {
                "bootstrap": True,
                "node_size": "llm",
                "measurement_type": "agent_reference",
                "agent_id": "agent-123",
                "rtmrs": {
                    "rtmr0": "0" * 96,
                    "rtmr1": "1" * 96,
                    "rtmr2": "2" * 96,
                    "rtmr3": "3" * 96,
                },
            },
        }

        app.dependency_overrides[verify_admin_token] = mock_verify_admin_token
        try:
            resp = client.post(
                f"/api/v1/apps/{sample_app}/versions/1.0.0/attest?node_size=llm",
                json=payload,
                headers={"Authorization": f"Bearer {admin_token}"},
            )
            assert resp.status_code == 200
            assert resp.json()["status"] == "attested"
        finally:
            app.dependency_overrides.clear()

        ver = client.get(f"/api/v1/apps/{sample_app}/versions/1.0.0?node_size=llm")
        assert ver.json()["status"] == "attested"
        assert ver.json()["mrtd"] == payload["mrtd"]
        assert ver.json()["attestation"]["node_size"] == "llm"

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


class TestDeployMeasurementValidation:
    @pytest.fixture
    def verified_llm_agent(self, sample_app):
        agent = Agent(
            vm_name="test-llm-vm",
            attestation={"tdx": {"intel_ta_token": "fake.token"}},
            mrtd="f" * 96,
            verified=True,
            hostname="agent-test.easyenclave.com",
            status="deployed",
            node_size="llm",
            deployed_app=sample_app,
        )
        agent_store.register(agent)
        return agent

    def _manual_attest(self, client, admin_token, app_name, payload):
        app.dependency_overrides[verify_admin_token] = mock_verify_admin_token
        try:
            resp = client.post(
                f"/api/v1/apps/{app_name}/versions/1.0.0/attest?node_size=llm",
                json=payload,
                headers={"Authorization": f"Bearer {admin_token}"},
            )
            assert resp.status_code == 200
        finally:
            app.dependency_overrides.clear()

    def test_deploy_rejects_measurement_node_size_mismatch(
        self, client, admin_token, sample_app, sample_compose, verified_llm_agent
    ):
        client.post(
            f"/api/v1/apps/{sample_app}/versions",
            json={"version": "1.0.0", "compose": sample_compose, "node_size": "llm"},
        )

        self._manual_attest(
            client,
            admin_token,
            sample_app,
            {
                "mrtd": verified_llm_agent.mrtd,
                "attestation": {
                    "measurement_type": "agent_reference",
                    "node_size": "tiny",
                    "rtmrs": {f"rtmr{i}": str(i) * 96 for i in range(4)},
                },
            },
        )

        resp = client.post(
            f"/api/v1/apps/{sample_app}/versions/1.0.0/deploy",
            json={"agent_id": verified_llm_agent.agent_id},
        )
        assert resp.status_code == 400
        assert "Measurement node_size mismatch" in resp.json()["detail"]

    def test_deploy_rejects_agent_reference_missing_mrtd(
        self, client, admin_token, sample_app, sample_compose, verified_llm_agent
    ):
        client.post(
            f"/api/v1/apps/{sample_app}/versions",
            json={"version": "1.0.0", "compose": sample_compose, "node_size": "llm"},
        )

        self._manual_attest(
            client,
            admin_token,
            sample_app,
            {
                "attestation": {
                    "measurement_type": "agent_reference",
                    "node_size": "llm",
                    "rtmrs": {f"rtmr{i}": str(i) * 96 for i in range(4)},
                },
            },
        )

        resp = client.post(
            f"/api/v1/apps/{sample_app}/versions/1.0.0/deploy",
            json={"agent_id": verified_llm_agent.agent_id},
        )
        assert resp.status_code == 400
        assert "has no MRTD recorded" in resp.json()["detail"]

    def test_deploy_rejects_agent_reference_mrtd_mismatch(
        self, client, admin_token, sample_app, sample_compose, verified_llm_agent
    ):
        client.post(
            f"/api/v1/apps/{sample_app}/versions",
            json={"version": "1.0.0", "compose": sample_compose, "node_size": "llm"},
        )

        self._manual_attest(
            client,
            admin_token,
            sample_app,
            {
                "mrtd": "a" * 96,
                "attestation": {
                    "measurement_type": "agent_reference",
                    "node_size": "llm",
                    "rtmrs": {f"rtmr{i}": str(i) * 96 for i in range(4)},
                },
            },
        )

        resp = client.post(
            f"/api/v1/apps/{sample_app}/versions/1.0.0/deploy",
            json={"agent_id": verified_llm_agent.agent_id},
        )
        assert resp.status_code == 400
        assert "Measurement MRTD mismatch" in resp.json()["detail"]

    def test_deploy_rejects_explicit_agent_assignment_when_not_upgrade(
        self, client, admin_token, sample_app, sample_compose
    ):
        agent = Agent(
            vm_name="test-llm-non-upgrade",
            attestation={"tdx": {"intel_ta_token": "fake.token"}},
            mrtd="f" * 96,
            verified=True,
            hostname="agent-test2.easyenclave.com",
            status="undeployed",
            node_size="llm",
        )
        agent_store.register(agent)

        client.post(
            f"/api/v1/apps/{sample_app}/versions",
            json={"version": "1.0.0", "compose": sample_compose, "node_size": "llm"},
        )
        self._manual_attest(
            client,
            admin_token,
            sample_app,
            {
                "mrtd": agent.mrtd,
                "attestation": {
                    "measurement_type": "agent_reference",
                    "node_size": "llm",
                    "rtmrs": {f"rtmr{i}": str(i) * 96 for i in range(4)},
                },
            },
        )

        resp = client.post(
            f"/api/v1/apps/{sample_app}/versions/1.0.0/deploy",
            json={"agent_id": agent.agent_id},
        )
        assert resp.status_code == 400
        assert "only allowed for upgrades" in resp.json()["detail"]

    def test_deploy_auto_selects_agent_without_agent_id(
        self, client, admin_token, sample_app, sample_compose
    ):
        agent = Agent(
            vm_name="test-llm-auto",
            attestation={"tdx": {"intel_ta_token": "fake.token"}},
            mrtd="f" * 96,
            verified=True,
            hostname="agent-test3.easyenclave.com",
            status="undeployed",
            health_status="healthy",
            node_size="llm",
        )
        agent_store.register(agent)

        client.post(
            f"/api/v1/apps/{sample_app}/versions",
            json={"version": "1.0.0", "compose": sample_compose, "node_size": "llm"},
        )
        self._manual_attest(
            client,
            admin_token,
            sample_app,
            {
                "mrtd": agent.mrtd,
                "attestation": {
                    "measurement_type": "agent_reference",
                    "node_size": "llm",
                    "rtmrs": {f"rtmr{i}": str(i) * 96 for i in range(4)},
                },
            },
        )

        with patch("app.main.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_response = MagicMock()
            mock_response.status_code = 202
            mock_client.post = AsyncMock(return_value=mock_response)
            mock_ctx = AsyncMock()
            mock_ctx.__aenter__.return_value = mock_client
            mock_ctx.__aexit__.return_value = False
            mock_client_cls.return_value = mock_ctx

            resp = client.post(
                f"/api/v1/apps/{sample_app}/versions/1.0.0/deploy",
                json={},
            )
        assert resp.status_code == 200
        assert resp.json()["deployment_id"]
        assert resp.json()["agent_id"] == agent.agent_id

    def test_admin_undeploy_calls_agent_api_with_control_secret(self, client, admin_token):
        agent = Agent(
            vm_name="test-llm-undeploy",
            attestation={"tdx": {"intel_ta_token": "fake.token"}},
            mrtd="f" * 96,
            verified=True,
            hostname="agent-undeploy.easyenclave.com",
            status="deployed",
            health_status="healthy",
            node_size="llm",
            current_deployment_id="dep-undeploy-1",
        )
        agent_store.register(agent)
        agent_control_credential_store.upsert_secret(agent.agent_id, "secret-123")

        app.dependency_overrides[verify_admin_token] = mock_verify_admin_token
        try:
            with patch("app.main.httpx.AsyncClient") as mock_client_cls:
                mock_client = AsyncMock()
                mock_response = MagicMock()
                mock_response.status_code = 200
                mock_response.text = '{"status":"undeployed"}'
                mock_client.post = AsyncMock(return_value=mock_response)
                mock_ctx = AsyncMock()
                mock_ctx.__aenter__.return_value = mock_client
                mock_ctx.__aexit__.return_value = False
                mock_client_cls.return_value = mock_ctx

                resp = client.post(
                    f"/api/v1/agents/{agent.agent_id}/undeploy",
                    headers={"Authorization": f"Bearer {admin_token}"},
                )
        finally:
            app.dependency_overrides.clear()

        assert resp.status_code == 200
        assert resp.json()["status"] == "undeployed"
        mock_client.post.assert_awaited_once_with(
            f"https://{agent.hostname}/api/undeploy",
            headers={"X-Agent-Secret": "secret-123"},
        )

        updated = agent_store.get(agent.agent_id)
        assert updated is not None
        assert updated.status == "undeployed"
        assert updated.current_deployment_id is None

    def test_preflight_returns_structured_measurement_error(
        self, client, admin_token, sample_app, sample_compose, verified_llm_agent
    ):
        client.post(
            f"/api/v1/apps/{sample_app}/versions",
            json={"version": "1.0.0", "compose": sample_compose, "node_size": "llm"},
        )

        self._manual_attest(
            client,
            admin_token,
            sample_app,
            {
                "mrtd": verified_llm_agent.mrtd,
                "attestation": {
                    "measurement_type": "agent_reference",
                    "node_size": "tiny",
                    "rtmrs": {f"rtmr{i}": str(i) * 96 for i in range(4)},
                },
            },
        )

        resp = client.post(
            f"/api/v1/apps/{sample_app}/versions/1.0.0/deploy/preflight",
            json={"agent_id": verified_llm_agent.agent_id},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["eligible"] is False
        assert any(i["code"] == "MEASUREMENT_NODE_SIZE_MISMATCH" for i in data["issues"])

    def test_preflight_datacenter_filter_selects_matching_agent(
        self, client, admin_token, sample_app, sample_compose
    ):
        gcp_agent = Agent(
            vm_name="test-llm-gcp",
            attestation={"tdx": {"intel_ta_token": "fake.token"}},
            mrtd="f" * 96,
            verified=True,
            hostname="agent-gcp.easyenclave.com",
            status="undeployed",
            health_status="healthy",
            node_size="llm",
            datacenter="gcp:us-central1-a",
        )
        azure_agent = Agent(
            vm_name="test-llm-azure",
            attestation={"tdx": {"intel_ta_token": "fake.token"}},
            mrtd="f" * 96,
            verified=True,
            hostname="agent-azure.easyenclave.com",
            status="undeployed",
            health_status="healthy",
            node_size="llm",
            datacenter="azure:eastus2-1",
        )
        agent_store.register(gcp_agent)
        agent_store.register(azure_agent)

        client.post(
            f"/api/v1/apps/{sample_app}/versions",
            json={"version": "1.0.0", "compose": sample_compose, "node_size": "llm"},
        )
        self._manual_attest(
            client,
            admin_token,
            sample_app,
            {
                "mrtd": gcp_agent.mrtd,
                "attestation": {
                    "measurement_type": "agent_reference",
                    "node_size": "llm",
                    "rtmrs": {f"rtmr{i}": str(i) * 96 for i in range(4)},
                },
            },
        )

        resp = client.post(
            f"/api/v1/apps/{sample_app}/versions/1.0.0/deploy/preflight",
            json={"node_size": "llm", "allowed_datacenters": ["azure:eastus2-1"]},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["eligible"] is True
        assert data["selected_agent_id"] == azure_agent.agent_id
        assert data["selected_datacenter"] == "azure:eastus2-1"
        assert data["selected_cloud"] == "azure"

    def test_preflight_cloud_filter_selects_matching_agent(
        self, client, admin_token, sample_app, sample_compose
    ):
        gcp_agent = Agent(
            vm_name="test-llm-gcp-cloud",
            attestation={"tdx": {"intel_ta_token": "fake.token"}},
            mrtd="f" * 96,
            verified=True,
            hostname="agent-gcp-cloud.easyenclave.com",
            status="undeployed",
            health_status="healthy",
            node_size="llm",
            datacenter="gcp:us-central1-a",
        )
        baremetal_agent = Agent(
            vm_name="test-llm-baremetal-cloud",
            attestation={"tdx": {"intel_ta_token": "fake.token"}},
            mrtd="f" * 96,
            verified=True,
            hostname="agent-baremetal-cloud.easyenclave.com",
            status="undeployed",
            health_status="healthy",
            node_size="llm",
            datacenter="baremetal:runner-a",
        )
        agent_store.register(gcp_agent)
        agent_store.register(baremetal_agent)

        client.post(
            f"/api/v1/apps/{sample_app}/versions",
            json={"version": "1.0.0", "compose": sample_compose, "node_size": "llm"},
        )
        self._manual_attest(
            client,
            admin_token,
            sample_app,
            {
                "mrtd": gcp_agent.mrtd,
                "attestation": {
                    "measurement_type": "agent_reference",
                    "node_size": "llm",
                    "rtmrs": {f"rtmr{i}": str(i) * 96 for i in range(4)},
                },
            },
        )

        resp = client.post(
            f"/api/v1/apps/{sample_app}/versions/1.0.0/deploy/preflight",
            json={"node_size": "llm", "allowed_clouds": ["gcp"]},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["eligible"] is True
        assert data["selected_agent_id"] == gcp_agent.agent_id
        assert data["selected_cloud"] == "gcp"

    def test_preflight_cloud_deny_blocks_matching_agents(
        self, client, admin_token, sample_app, sample_compose
    ):
        gcp_agent = Agent(
            vm_name="test-llm-gcp-deny",
            attestation={"tdx": {"intel_ta_token": "fake.token"}},
            mrtd="f" * 96,
            verified=True,
            hostname="agent-gcp-deny.easyenclave.com",
            status="undeployed",
            health_status="healthy",
            node_size="llm",
            datacenter="gcp:us-central1-a",
        )
        agent_store.register(gcp_agent)

        client.post(
            f"/api/v1/apps/{sample_app}/versions",
            json={"version": "1.0.0", "compose": sample_compose, "node_size": "llm"},
        )
        self._manual_attest(
            client,
            admin_token,
            sample_app,
            {
                "mrtd": gcp_agent.mrtd,
                "attestation": {
                    "measurement_type": "agent_reference",
                    "node_size": "llm",
                    "rtmrs": {f"rtmr{i}": str(i) * 96 for i in range(4)},
                },
            },
        )

        resp = client.post(
            f"/api/v1/apps/{sample_app}/versions/1.0.0/deploy/preflight",
            json={"node_size": "llm", "denied_clouds": ["gcp"]},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["eligible"] is False
        assert any(i["code"] == "AGENT_CLOUD_DENIED" for i in data["issues"])

    def test_preflight_cloud_policy_conflict(self, client, sample_app, sample_compose):
        client.post(
            f"/api/v1/apps/{sample_app}/versions",
            json={"version": "1.0.0", "compose": sample_compose},
        )

        resp = client.post(
            f"/api/v1/apps/{sample_app}/versions/1.0.0/deploy/preflight",
            json={"allowed_clouds": ["gcp"], "denied_clouds": ["gcp"]},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["eligible"] is False
        assert any(i["code"] == "CLOUD_POLICY_CONFLICT" for i in data["issues"])

    def test_deploy_dry_run_returns_preflight_payload(
        self, client, admin_token, sample_app, sample_compose
    ):
        agent = Agent(
            vm_name="test-llm-dry-run",
            attestation={"tdx": {"intel_ta_token": "fake.token"}},
            mrtd="f" * 96,
            verified=True,
            hostname="agent-dry-run.easyenclave.com",
            status="undeployed",
            health_status="healthy",
            node_size="llm",
            datacenter="gcp:us-central1-a",
        )
        agent_store.register(agent)

        client.post(
            f"/api/v1/apps/{sample_app}/versions",
            json={"version": "1.0.0", "compose": sample_compose, "node_size": "llm"},
        )
        self._manual_attest(
            client,
            admin_token,
            sample_app,
            {
                "mrtd": agent.mrtd,
                "attestation": {
                    "measurement_type": "agent_reference",
                    "node_size": "llm",
                    "rtmrs": {f"rtmr{i}": str(i) * 96 for i in range(4)},
                },
            },
        )

        resp = client.post(
            f"/api/v1/apps/{sample_app}/versions/1.0.0/deploy",
            json={"dry_run": True, "allowed_datacenters": ["gcp:us-central1-a"]},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["dry_run"] is True
        assert data["eligible"] is True
        assert data["selected_agent_id"] == agent.agent_id
