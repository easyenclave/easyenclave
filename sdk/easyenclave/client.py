"""EasyEnclave SDK Client - Client library for the EasyEnclave discovery service.

Trust Model:
    Client --> Control Plane (verify attestation via /health) --> Proxy --> Service
"""

from __future__ import annotations

import httpx

from .verify import VerificationResult, verify_quote_local

DEFAULT_HEADERS = {
    # Avoid Cloudflare bot detection heuristics that sometimes block default
    # Python client user agents on the public tunnels/proxy.
    "user-agent": "EasyEnclave-SDK/0.1",
}


class EasyEnclaveError(Exception):
    """Base exception for EasyEnclave client errors."""

    pass


class ServiceNotFoundError(EasyEnclaveError):
    """Raised when a service is not found."""

    pass


class VerificationError(EasyEnclaveError):
    """Raised when attestation verification fails."""

    pass


class ControlPlaneNotVerifiedError(EasyEnclaveError):
    """Raised when control plane attestation cannot be verified."""

    pass


class ServiceClient:
    """Client for calling a specific service through the proxy.

    This client routes all requests through the attested control plane's
    proxy endpoint, which forwards to the service via Cloudflare tunnel.

    Example:
        client = EasyEnclaveClient("https://app.easyenclave.com")
        my_service = client.service("my-app")
        response = my_service.get("/api/data")
    """

    def __init__(
        self,
        proxy_url: str,
        service_name: str,
        timeout: float = 30.0,
    ):
        """Create a service client.

        Args:
            proxy_url: Base URL of the proxy (usually CP)
            service_name: Name of the target service
            timeout: Request timeout in seconds
        """
        self.base_url = f"{proxy_url.rstrip('/')}/proxy/{service_name}"
        self.service_name = service_name
        self.timeout = timeout
        self._client = httpx.Client(timeout=timeout, headers=DEFAULT_HEADERS)

    def get(self, path: str, **kwargs) -> httpx.Response:
        """Send GET request to service.

        Args:
            path: Path on the service (e.g., "/api/data")
            **kwargs: Additional httpx request arguments

        Returns:
            httpx.Response from the service
        """
        url = f"{self.base_url}{path}"
        return self._client.get(url, **kwargs)

    def post(self, path: str, **kwargs) -> httpx.Response:
        """Send POST request to service.

        Args:
            path: Path on the service
            **kwargs: Additional httpx request arguments (json=, data=, etc.)

        Returns:
            httpx.Response from the service
        """
        url = f"{self.base_url}{path}"
        return self._client.post(url, **kwargs)

    def put(self, path: str, **kwargs) -> httpx.Response:
        """Send PUT request to service."""
        url = f"{self.base_url}{path}"
        return self._client.put(url, **kwargs)

    def patch(self, path: str, **kwargs) -> httpx.Response:
        """Send PATCH request to service."""
        url = f"{self.base_url}{path}"
        return self._client.patch(url, **kwargs)

    def delete(self, path: str, **kwargs) -> httpx.Response:
        """Send DELETE request to service."""
        url = f"{self.base_url}{path}"
        return self._client.delete(url, **kwargs)

    def request(self, method: str, path: str, **kwargs) -> httpx.Response:
        """Send arbitrary HTTP request to service.

        Args:
            method: HTTP method (GET, POST, etc.)
            path: Path on the service
            **kwargs: Additional httpx request arguments

        Returns:
            httpx.Response from the service
        """
        url = f"{self.base_url}{path}"
        return self._client.request(method, url, **kwargs)

    def close(self) -> None:
        """Close the HTTP client."""
        self._client.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()


class EasyEnclaveClient:
    """Client for the EasyEnclave control plane.

    Connects to the control plane, optionally verifies its TDX attestation,
    and provides service discovery and proxying — all from a single /health call.

    Example:
        client = EasyEnclaveClient("https://app.easyenclave.com")
        response = client.service("my-app").get("/api/data")
    """

    def __init__(
        self,
        control_plane_url: str,
        verify: bool = True,
        expected_mrtd: str | None = None,
        timeout: float = 30.0,
    ):
        """Connect to EasyEnclave control plane.

        Args:
            control_plane_url: URL of the control plane
            verify: Whether to verify the control plane's TDX attestation
            expected_mrtd: Expected MRTD value (optional, for pinning)
            timeout: Request timeout in seconds

        Raises:
            EasyEnclaveError: If connection fails
            ControlPlaneNotVerifiedError: If verify=True and attestation fails
        """
        self.cp_url = control_plane_url.rstrip("/")
        self.timeout = timeout
        self._client = httpx.Client(timeout=timeout, headers=DEFAULT_HEADERS)
        self.verification_result: VerificationResult | None = None

        # Single call to /health gets status + attestation + proxy_url
        try:
            response = self._client.get(f"{self.cp_url}/health")
            response.raise_for_status()
            health = response.json()
        except httpx.HTTPError as e:
            raise EasyEnclaveError(f"Failed to connect to control plane: {e}") from e

        if health.get("status") != "healthy":
            raise EasyEnclaveError(f"Control plane unhealthy: {health.get('status')}")

        self.proxy_url = health.get("proxy_url", self.cp_url)

        if verify:
            attestation = health.get("attestation")
            if not attestation:
                raise ControlPlaneNotVerifiedError(
                    "Control plane did not return attestation (not running in TDX?)"
                )

            quote_b64 = attestation.get("quote_b64")
            if not quote_b64:
                raise ControlPlaneNotVerifiedError("No quote in attestation response")

            result = verify_quote_local(quote_b64, expected_mrtd=expected_mrtd)
            self.verification_result = result

            if not result.verified:
                raise ControlPlaneNotVerifiedError(
                    f"Attestation verification failed: {result.error}"
                )

    def service(self, service_name: str) -> ServiceClient:
        """Get a client for a specific service.

        The returned client routes all requests through the proxy
        to the named service.

        Args:
            service_name: Name of the target service

        Returns:
            ServiceClient for the service

        Example:
            my_service = client.service("my-app")
            response = my_service.get("/api/data")
        """
        return ServiceClient(self.proxy_url, service_name, self.timeout)

    def register(
        self,
        name: str,
        endpoints: dict[str, str],
        attestation_json: dict | None = None,
        source_repo: str | None = None,
        source_commit: str | None = None,
        compose_hash: str | None = None,
        mrtd: str | None = None,
        intel_ta_token: str | None = None,
        description: str = "",
        tags: list[str] | None = None,
    ) -> str:
        """Legacy API removed; use app catalog + version deploy endpoints."""
        raise EasyEnclaveError(
            "Legacy service registry API was removed. "
            "Use app catalog endpoints (/api/v1/apps, /versions, /deploy)."
        )

    def discover(
        self,
        name: str | None = None,
        tags: list[str] | None = None,
        environment: str | None = None,
        mrtd: str | None = None,
        health_status: str | None = None,
        query: str | None = None,
    ) -> list[dict]:
        """Legacy API removed; use app catalog + version deploy endpoints."""
        raise EasyEnclaveError(
            "Legacy service discovery API was removed. "
            "Use app catalog endpoints (/api/v1/apps, /versions, /deploy)."
        )

    def get_service(self, service_id: str) -> dict:
        """Legacy API removed; use app catalog + version deploy endpoints."""
        raise EasyEnclaveError(
            "Legacy service lookup API was removed. "
            "Use app catalog endpoints (/api/v1/apps, /versions, /deploy)."
        )

    def verify_service(self, service_id: str) -> dict:
        """Legacy API removed; use app catalog + version deploy endpoints."""
        raise EasyEnclaveError(
            "Legacy service verification API was removed. "
            "Use app catalog endpoints (/api/v1/apps, /versions, /deploy)."
        )

    def deregister(self, service_id: str) -> bool:
        """Legacy API removed; use app catalog + version deploy endpoints."""
        raise EasyEnclaveError(
            "Legacy service deregistration API was removed. "
            "Use app catalog endpoints (/api/v1/apps, /versions, /deploy)."
        )

    # App catalog methods

    def list_apps(
        self,
        name: str | None = None,
        tags: list[str] | None = None,
    ) -> list[dict]:
        """List apps in the catalog.

        Args:
            name: Filter by name (partial match)
            tags: Filter by tags

        Returns:
            List of app dictionaries
        """
        params = {}
        if name:
            params["name"] = name
        if tags:
            params["tags"] = ",".join(tags)

        try:
            response = self._client.get(
                f"{self.cp_url}/api/v1/apps",
                params=params,
            )
            response.raise_for_status()
            data = response.json()
            return data["apps"]
        except httpx.HTTPError as e:
            raise EasyEnclaveError(f"List apps request failed: {e}") from e

    def get_app(self, app_name: str) -> dict:
        """Get details for an app.

        Args:
            app_name: Name of the app

        Returns:
            App details dictionary
        """
        try:
            response = self._client.get(f"{self.cp_url}/api/v1/apps/{app_name}")
            if response.status_code == 404:
                raise ServiceNotFoundError(f"App not found: {app_name}")
            response.raise_for_status()
            return response.json()
        except httpx.HTTPError as e:
            raise EasyEnclaveError(f"Get app request failed: {e}") from e

    def get_app_version(self, app_name: str, version: str) -> dict:
        """Get details for a specific version of an app.

        Args:
            app_name: Name of the app
            version: Version string

        Returns:
            Version details dictionary
        """
        try:
            response = self._client.get(f"{self.cp_url}/api/v1/apps/{app_name}/versions/{version}")
            if response.status_code == 404:
                raise ServiceNotFoundError(f"Version not found: {app_name}@{version}")
            response.raise_for_status()
            return response.json()
        except httpx.HTTPError as e:
            raise EasyEnclaveError(f"Get version request failed: {e}") from e

    def close(self) -> None:
        """Close the HTTP client."""
        self._client.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
