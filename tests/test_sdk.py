"""Tests for EasyEnclave SDK."""

from unittest.mock import MagicMock, patch

import pytest

from sdk.easyenclave.client import (
    EasyEnclaveClient,
    EasyEnclaveError,
    ServiceClient,
)


@pytest.fixture
def mock_httpx():
    """Mock httpx.Client for SDK tests."""
    with patch("sdk.easyenclave.client.httpx.Client") as mock:
        client_instance = MagicMock()
        mock.return_value = client_instance

        # Mock health check and proxy endpoint
        health_response = MagicMock()
        health_response.json.return_value = {"status": "healthy"}
        health_response.raise_for_status = MagicMock()

        proxy_response = MagicMock()
        proxy_response.json.return_value = {"proxy_url": "http://localhost:8080"}
        proxy_response.raise_for_status = MagicMock()

        # First call is health check, second is proxy endpoint
        def get_side_effect(url, **kwargs):
            if "/health" in url:
                return health_response
            elif "/api/v1/proxy" in url:
                return proxy_response
            else:
                # For other GET requests, return a default response
                return health_response

        client_instance.get.side_effect = get_side_effect

        yield client_instance


class TestEasyEnclaveClient:
    def test_init_checks_health(self, mock_httpx):
        """Test that client checks health on init."""
        client = EasyEnclaveClient("http://localhost:8080", verify=False)
        # Verify health was called
        calls = [str(call) for call in mock_httpx.get.call_args_list]
        assert any("/health" in c for c in calls)
        client.close()

    def test_init_fails_on_unhealthy(self, mock_httpx):
        """Test that client raises error on unhealthy service."""
        unhealthy_response = MagicMock()
        unhealthy_response.json.return_value = {"status": "unhealthy"}
        unhealthy_response.raise_for_status = MagicMock()
        mock_httpx.get.side_effect = lambda url, **kwargs: unhealthy_response

        with pytest.raises(EasyEnclaveError, match="unhealthy"):
            EasyEnclaveClient("http://localhost:8080", verify=False)

    def test_legacy_register_removed(self, mock_httpx):
        client = EasyEnclaveClient("http://localhost:8080", verify=False)
        with pytest.raises(EasyEnclaveError, match="Legacy service registry API was removed"):
            client.register(name="test-service", endpoints={"prod": "https://test.example.com"})
        client.close()

    def test_legacy_discover_removed(self, mock_httpx):
        client = EasyEnclaveClient("http://localhost:8080", verify=False)
        with pytest.raises(EasyEnclaveError, match="Legacy service discovery API was removed"):
            client.discover()
        client.close()

    def test_legacy_get_service_removed(self, mock_httpx):
        client = EasyEnclaveClient("http://localhost:8080", verify=False)
        with pytest.raises(EasyEnclaveError, match="Legacy service lookup API was removed"):
            client.get_service("test-id")
        client.close()

    def test_legacy_verify_service_removed(self, mock_httpx):
        client = EasyEnclaveClient("http://localhost:8080", verify=False)
        with pytest.raises(EasyEnclaveError, match="Legacy service verification API was removed"):
            client.verify_service("test-id")
        client.close()

    def test_legacy_deregister_removed(self, mock_httpx):
        client = EasyEnclaveClient("http://localhost:8080", verify=False)
        with pytest.raises(EasyEnclaveError, match="Legacy service deregistration API was removed"):
            client.deregister("test-id")
        client.close()

    def test_context_manager(self, mock_httpx):
        """Test using client as context manager."""
        with EasyEnclaveClient("http://localhost:8080", verify=False) as client:
            assert client is not None
        mock_httpx.close.assert_called_once()

    def test_service_client(self, mock_httpx):
        """Test ServiceClient for proxied requests."""
        client = EasyEnclaveClient("http://localhost:8080", verify=False)

        # Get service client
        svc = client.service("my-service")
        assert isinstance(svc, ServiceClient)
        assert svc.service_name == "my-service"
        assert "my-service" in svc.base_url

        client.close()
