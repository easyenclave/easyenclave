"""Tests for EasyEnclave SDK."""

from unittest.mock import MagicMock, patch

import pytest

from sdk.easyenclave.client import (
    EasyEnclaveClient,
    EasyEnclaveError,
    ServiceClient,
    ServiceNotFoundError,
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

    def test_register(self, mock_httpx):
        """Test service registration."""
        register_response = MagicMock()
        register_response.json.return_value = {"service_id": "test-id"}
        register_response.raise_for_status = MagicMock()
        mock_httpx.post.return_value = register_response

        client = EasyEnclaveClient("http://localhost:8080", verify=False)
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

        def get_side_effect(url, **kwargs):
            if "/health" in url:
                resp = MagicMock()
                resp.json.return_value = {"status": "healthy"}
                resp.raise_for_status = MagicMock()
                return resp
            elif "/api/v1/proxy" in url:
                resp = MagicMock()
                resp.json.return_value = {"proxy_url": "http://localhost:8080"}
                resp.raise_for_status = MagicMock()
                return resp
            elif "/api/v1/services" in url:
                return discover_response
            else:
                return discover_response

        mock_httpx.get.side_effect = get_side_effect

        client = EasyEnclaveClient("http://localhost:8080", verify=False)
        services = client.discover()

        assert len(services) == 2
        client.close()

    def test_discover_with_filters(self, mock_httpx):
        """Test service discovery with filters."""
        discover_response = MagicMock()
        discover_response.json.return_value = {"services": [{"name": "filtered"}]}
        discover_response.raise_for_status = MagicMock()

        calls = []

        def get_side_effect(url, **kwargs):
            calls.append((url, kwargs))
            if "/health" in url:
                resp = MagicMock()
                resp.json.return_value = {"status": "healthy"}
                resp.raise_for_status = MagicMock()
                return resp
            elif "/api/v1/proxy" in url:
                resp = MagicMock()
                resp.json.return_value = {"proxy_url": "http://localhost:8080"}
                resp.raise_for_status = MagicMock()
                return resp
            else:
                return discover_response

        mock_httpx.get.side_effect = get_side_effect

        client = EasyEnclaveClient("http://localhost:8080", verify=False)
        client.discover(name="test", tags=["api"], environment="prod")

        # Find the services call
        services_call = None
        for url, kwargs in calls:
            if "/api/v1/services" in url:
                services_call = (url, kwargs)
                break

        assert services_call is not None
        params = services_call[1].get("params", {})
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

        def get_side_effect(url, **kwargs):
            if "/health" in url:
                resp = MagicMock()
                resp.json.return_value = {"status": "healthy"}
                resp.raise_for_status = MagicMock()
                return resp
            elif "/api/v1/proxy" in url:
                resp = MagicMock()
                resp.json.return_value = {"proxy_url": "http://localhost:8080"}
                resp.raise_for_status = MagicMock()
                return resp
            else:
                return get_response

        mock_httpx.get.side_effect = get_side_effect

        client = EasyEnclaveClient("http://localhost:8080", verify=False)
        service = client.get_service("test-id")

        assert service["service_id"] == "test-id"
        client.close()

    def test_get_service_not_found(self, mock_httpx):
        """Test getting a non-existent service."""
        not_found_response = MagicMock()
        not_found_response.status_code = 404

        def get_side_effect(url, **kwargs):
            if "/health" in url:
                resp = MagicMock()
                resp.json.return_value = {"status": "healthy"}
                resp.raise_for_status = MagicMock()
                return resp
            elif "/api/v1/proxy" in url:
                resp = MagicMock()
                resp.json.return_value = {"proxy_url": "http://localhost:8080"}
                resp.raise_for_status = MagicMock()
                return resp
            else:
                return not_found_response

        mock_httpx.get.side_effect = get_side_effect

        client = EasyEnclaveClient("http://localhost:8080", verify=False)
        with pytest.raises(ServiceNotFoundError):
            client.get_service("nonexistent")
        client.close()

    def test_verify_service(self, mock_httpx):
        """Test verifying a service."""
        verify_response = MagicMock()
        verify_response.json.return_value = {"verified": True}
        verify_response.raise_for_status = MagicMock()
        verify_response.status_code = 200

        def get_side_effect(url, **kwargs):
            if "/health" in url:
                resp = MagicMock()
                resp.json.return_value = {"status": "healthy"}
                resp.raise_for_status = MagicMock()
                return resp
            elif "/api/v1/proxy" in url:
                resp = MagicMock()
                resp.json.return_value = {"proxy_url": "http://localhost:8080"}
                resp.raise_for_status = MagicMock()
                return resp
            else:
                return verify_response

        mock_httpx.get.side_effect = get_side_effect

        client = EasyEnclaveClient("http://localhost:8080", verify=False)
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

        client = EasyEnclaveClient("http://localhost:8080", verify=False)
        result = client.deregister("test-id")

        assert result is True
        mock_httpx.delete.assert_called_once()
        client.close()

    def test_context_manager(self, mock_httpx):
        """Test using client as context manager."""
        with EasyEnclaveClient(
            "http://localhost:8080", verify=False
        ) as client:
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
