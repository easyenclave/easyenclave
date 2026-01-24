"""Tests for EasyEnclave SDK."""

from unittest.mock import MagicMock, patch

import pytest

from sdk.easyenclave.client import (
    EasyEnclaveClient,
    EasyEnclaveError,
    ServiceNotFoundError,
)


@pytest.fixture
def mock_httpx():
    """Mock httpx.Client for SDK tests."""
    with patch("sdk.easyenclave.client.httpx.Client") as mock:
        client_instance = MagicMock()
        mock.return_value = client_instance

        # Mock health check to pass by default
        health_response = MagicMock()
        health_response.json.return_value = {"status": "healthy"}
        health_response.raise_for_status = MagicMock()
        client_instance.get.return_value = health_response

        yield client_instance


class TestEasyEnclaveClient:
    def test_init_checks_health(self, mock_httpx):
        """Test that client checks health on init."""
        client = EasyEnclaveClient("http://localhost:8080", verify_attestation=False)
        mock_httpx.get.assert_called_with("http://localhost:8080/health")
        client.close()

    def test_init_fails_on_unhealthy(self, mock_httpx):
        """Test that client raises error on unhealthy service."""
        mock_httpx.get.return_value.json.return_value = {"status": "unhealthy"}
        with pytest.raises(EasyEnclaveError, match="unhealthy"):
            EasyEnclaveClient("http://localhost:8080", verify_attestation=False)

    def test_register(self, mock_httpx):
        """Test service registration."""
        register_response = MagicMock()
        register_response.json.return_value = {"service_id": "test-id"}
        register_response.raise_for_status = MagicMock()
        mock_httpx.post.return_value = register_response

        client = EasyEnclaveClient("http://localhost:8080", verify_attestation=False)
        service_id = client.register(
            name="test-service",
            endpoints={"prod": "https://test.example.com"},
            tags=["test"],
        )

        assert service_id == "test-id"
        mock_httpx.post.assert_called_once()
        call_args = mock_httpx.post.call_args
        assert "/api/v1/register" in call_args[0][0]
        client.close()

    def test_discover(self, mock_httpx):
        """Test service discovery."""
        discover_response = MagicMock()
        discover_response.json.return_value = {
            "services": [{"name": "service-1"}, {"name": "service-2"}]
        }
        discover_response.raise_for_status = MagicMock()

        # First call is health check, subsequent calls are discover
        mock_httpx.get.side_effect = [
            MagicMock(
                json=MagicMock(return_value={"status": "healthy"}),
                raise_for_status=MagicMock(),
            ),
            discover_response,
        ]

        client = EasyEnclaveClient("http://localhost:8080", verify_attestation=False)
        services = client.discover()

        assert len(services) == 2
        client.close()

    def test_discover_with_filters(self, mock_httpx):
        """Test service discovery with filters."""
        discover_response = MagicMock()
        discover_response.json.return_value = {"services": [{"name": "filtered"}]}
        discover_response.raise_for_status = MagicMock()

        mock_httpx.get.side_effect = [
            MagicMock(
                json=MagicMock(return_value={"status": "healthy"}),
                raise_for_status=MagicMock(),
            ),
            discover_response,
        ]

        client = EasyEnclaveClient("http://localhost:8080", verify_attestation=False)
        client.discover(name="test", tags=["api"], environment="prod")

        call_args = mock_httpx.get.call_args
        params = call_args[1]["params"]
        assert params["name"] == "test"
        assert params["tags"] == "api"
        assert params["environment"] == "prod"
        client.close()

    def test_get_service(self, mock_httpx):
        """Test getting a specific service."""
        get_response = MagicMock()
        get_response.json.return_value = {"service_id": "test-id", "name": "test"}
        get_response.raise_for_status = MagicMock()
        get_response.status_code = 200

        mock_httpx.get.side_effect = [
            MagicMock(
                json=MagicMock(return_value={"status": "healthy"}),
                raise_for_status=MagicMock(),
            ),
            get_response,
        ]

        client = EasyEnclaveClient("http://localhost:8080", verify_attestation=False)
        service = client.get_service("test-id")

        assert service["service_id"] == "test-id"
        client.close()

    def test_get_service_not_found(self, mock_httpx):
        """Test getting a non-existent service."""
        get_response = MagicMock()
        get_response.status_code = 404

        mock_httpx.get.side_effect = [
            MagicMock(
                json=MagicMock(return_value={"status": "healthy"}),
                raise_for_status=MagicMock(),
            ),
            get_response,
        ]

        client = EasyEnclaveClient("http://localhost:8080", verify_attestation=False)
        with pytest.raises(ServiceNotFoundError):
            client.get_service("nonexistent")
        client.close()

    def test_verify_service(self, mock_httpx):
        """Test verifying a service."""
        verify_response = MagicMock()
        verify_response.json.return_value = {"verified": True}
        verify_response.raise_for_status = MagicMock()
        verify_response.status_code = 200

        mock_httpx.get.side_effect = [
            MagicMock(
                json=MagicMock(return_value={"status": "healthy"}),
                raise_for_status=MagicMock(),
            ),
            verify_response,
        ]

        client = EasyEnclaveClient("http://localhost:8080", verify_attestation=False)
        result = client.verify_service("test-id")

        assert result["verified"] is True
        client.close()

    def test_deregister(self, mock_httpx):
        """Test deregistering a service."""
        delete_response = MagicMock()
        delete_response.json.return_value = {"status": "deleted"}
        delete_response.raise_for_status = MagicMock()
        delete_response.status_code = 200

        mock_httpx.delete.return_value = delete_response

        client = EasyEnclaveClient("http://localhost:8080", verify_attestation=False)
        result = client.deregister("test-id")

        assert result is True
        mock_httpx.delete.assert_called_once()
        client.close()

    def test_context_manager(self, mock_httpx):
        """Test using client as context manager."""
        with EasyEnclaveClient(
            "http://localhost:8080", verify_attestation=False
        ) as client:
            assert client is not None
        mock_httpx.close.assert_called_once()
