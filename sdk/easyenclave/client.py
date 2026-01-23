"""EasyEnclave SDK Client - Client library for the EasyEnclave discovery service."""

from __future__ import annotations

from typing import Optional
import httpx


class EasyEnclaveError(Exception):
    """Base exception for EasyEnclave client errors."""

    pass


class ServiceNotFoundError(EasyEnclaveError):
    """Raised when a service is not found."""

    pass


class VerificationError(EasyEnclaveError):
    """Raised when attestation verification fails."""

    pass


class EasyEnclaveClient:
    """Client for interacting with the EasyEnclave discovery service."""

    def __init__(
        self,
        discovery_url: str,
        verify_attestation: bool = True,
        timeout: float = 30.0,
    ):
        """
        Connect to EasyEnclave service.

        Args:
            discovery_url: Base URL of the EasyEnclave service (e.g., "https://easyenclave.example.com")
            verify_attestation: Whether to verify the discovery service's own attestation on connect
            timeout: Request timeout in seconds
        """
        self.base_url = discovery_url.rstrip("/")
        self.timeout = timeout
        self._client = httpx.Client(timeout=timeout)

        # Verify discovery service health
        self._check_health()

        # Optionally verify the discovery service's attestation
        if verify_attestation:
            # TODO: Implement discovery service self-attestation verification
            pass

    def _check_health(self) -> None:
        """Check if the discovery service is healthy."""
        try:
            response = self._client.get(f"{self.base_url}/health")
            response.raise_for_status()
            data = response.json()
            if data.get("status") != "healthy":
                raise EasyEnclaveError(
                    f"Discovery service unhealthy: {data.get('status')}"
                )
        except httpx.HTTPError as e:
            raise EasyEnclaveError(f"Failed to connect to discovery service: {e}")

    def register(
        self,
        name: str,
        endpoints: dict[str, str],
        attestation_json: Optional[dict] = None,
        source_repo: Optional[str] = None,
        source_commit: Optional[str] = None,
        compose_hash: Optional[str] = None,
        mrtd: Optional[str] = None,
        intel_ta_token: Optional[str] = None,
        description: str = "",
        tags: Optional[list[str]] = None,
    ) -> str:
        """
        Register this service with EasyEnclave.

        Args:
            name: Human-readable service name
            endpoints: Dict mapping environment names to URLs (e.g., {"prod": "https://..."})
            attestation_json: Full attestation data from measure-tdx
            source_repo: GitHub repository URL
            source_commit: Git commit SHA
            compose_hash: SHA256 hash of docker-compose.yml
            mrtd: TDX measurement
            intel_ta_token: JWT from Intel Trust Authority
            description: Service description
            tags: Searchable tags

        Returns:
            service_id: Unique identifier for the registered service
        """
        payload = {
            "name": name,
            "description": description,
            "endpoints": endpoints,
            "tags": tags or [],
        }

        if source_repo:
            payload["source_repo"] = source_repo
        if source_commit:
            payload["source_commit"] = source_commit
        if compose_hash:
            payload["compose_hash"] = compose_hash
        if mrtd:
            payload["mrtd"] = mrtd
        if attestation_json:
            payload["attestation_json"] = attestation_json
        if intel_ta_token:
            payload["intel_ta_token"] = intel_ta_token

        try:
            response = self._client.post(
                f"{self.base_url}/api/v1/register",
                json=payload,
            )
            response.raise_for_status()
            data = response.json()
            return data["service_id"]
        except httpx.HTTPStatusError as e:
            raise EasyEnclaveError(f"Registration failed: {e.response.text}")
        except httpx.HTTPError as e:
            raise EasyEnclaveError(f"Registration request failed: {e}")

    def discover(
        self,
        name: Optional[str] = None,
        tags: Optional[list[str]] = None,
        environment: Optional[str] = None,
        mrtd: Optional[str] = None,
        health_status: Optional[str] = None,
        query: Optional[str] = None,
    ) -> list[dict]:
        """
        Find services matching criteria.

        Args:
            name: Filter by name (partial match)
            tags: Filter by tags (any match)
            environment: Filter by environment (must have endpoint for this env)
            mrtd: Filter by MRTD (exact match)
            health_status: Filter by health status
            query: Full-text search query

        Returns:
            List of service dictionaries matching the criteria
        """
        params = {}
        if name:
            params["name"] = name
        if tags:
            params["tags"] = ",".join(tags)
        if environment:
            params["environment"] = environment
        if mrtd:
            params["mrtd"] = mrtd
        if health_status:
            params["health_status"] = health_status
        if query:
            params["q"] = query

        try:
            response = self._client.get(
                f"{self.base_url}/api/v1/services",
                params=params,
            )
            response.raise_for_status()
            data = response.json()
            return data["services"]
        except httpx.HTTPError as e:
            raise EasyEnclaveError(f"Discovery request failed: {e}")

    def get_service(self, service_id: str) -> dict:
        """
        Get details for a specific service.

        Args:
            service_id: Unique identifier of the service

        Returns:
            Service details dictionary

        Raises:
            ServiceNotFoundError: If service not found
        """
        try:
            response = self._client.get(
                f"{self.base_url}/api/v1/services/{service_id}"
            )
            if response.status_code == 404:
                raise ServiceNotFoundError(f"Service not found: {service_id}")
            response.raise_for_status()
            return response.json()
        except httpx.HTTPError as e:
            raise EasyEnclaveError(f"Get service request failed: {e}")

    def verify_service(self, service_id: str) -> dict:
        """
        Verify a service's attestation via Intel Trust Authority.

        Args:
            service_id: Unique identifier of the service

        Returns:
            Verification result dictionary with keys:
            - verified: bool
            - verification_time: datetime string
            - details: dict (if verified)
            - error: str (if not verified)

        Raises:
            ServiceNotFoundError: If service not found
            VerificationError: If verification fails
        """
        try:
            response = self._client.get(
                f"{self.base_url}/api/v1/services/{service_id}/verify"
            )
            if response.status_code == 404:
                raise ServiceNotFoundError(f"Service not found: {service_id}")
            response.raise_for_status()
            return response.json()
        except httpx.HTTPError as e:
            raise EasyEnclaveError(f"Verification request failed: {e}")

    def deregister(self, service_id: str) -> bool:
        """
        Deregister a service.

        Args:
            service_id: Unique identifier of the service

        Returns:
            True if successfully deregistered

        Raises:
            ServiceNotFoundError: If service not found
        """
        try:
            response = self._client.delete(
                f"{self.base_url}/api/v1/services/{service_id}"
            )
            if response.status_code == 404:
                raise ServiceNotFoundError(f"Service not found: {service_id}")
            response.raise_for_status()
            return True
        except httpx.HTTPError as e:
            raise EasyEnclaveError(f"Deregister request failed: {e}")

    def close(self) -> None:
        """Close the HTTP client."""
        self._client.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
