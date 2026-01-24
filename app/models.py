"""Data models for EasyEnclave discovery service."""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, Field


class ServiceRegistrationRequest(BaseModel):
    """Request model for registering a new service."""

    name: str = Field(..., description="Human-readable service name")
    description: str = Field(default="", description="What this service does")

    # Source & Build Info
    source_repo: str | None = Field(default=None, description="GitHub repo URL")
    source_commit: str | None = Field(default=None, description="Git commit SHA")
    compose_hash: str | None = Field(
        default=None, description="SHA256 of docker-compose.yml"
    )

    # Endpoints (by environment)
    endpoints: dict[str, str] = Field(
        default_factory=dict,
        description='Endpoints by environment, e.g., {"prod": "https://..."}',
    )

    # Attestation
    mrtd: str | None = Field(default=None, description="TDX measurement")
    attestation_json: dict | None = Field(
        default=None, description="Full attestation from measure-tdx"
    )
    intel_ta_token: str | None = Field(
        default=None, description="JWT from Intel Trust Authority"
    )

    # Metadata
    tags: list[str] = Field(default_factory=list, description="Searchable tags")


class ServiceRegistration(BaseModel):
    """Full service registration model with server-generated fields."""

    service_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()), description="Unique identifier"
    )
    name: str = Field(..., description="Human-readable service name")
    description: str = Field(default="", description="What this service does")

    # Source & Build Info
    source_repo: str | None = Field(default=None, description="GitHub repo URL")
    source_commit: str | None = Field(default=None, description="Git commit SHA")
    compose_hash: str | None = Field(
        default=None, description="SHA256 of docker-compose.yml"
    )

    # Endpoints (by environment)
    endpoints: dict[str, str] = Field(
        default_factory=dict,
        description='Endpoints by environment, e.g., {"prod": "https://..."}',
    )

    # Attestation
    mrtd: str | None = Field(default=None, description="TDX measurement")
    attestation_json: dict | None = Field(
        default=None, description="Full attestation from measure-tdx"
    )
    intel_ta_token: str | None = Field(
        default=None, description="JWT from Intel Trust Authority"
    )

    # Metadata
    registered_at: datetime = Field(default_factory=datetime.utcnow)
    last_health_check: datetime | None = Field(default=None)
    health_status: str = Field(
        default="unknown", description="healthy, unhealthy, or unknown"
    )
    tags: list[str] = Field(default_factory=list, description="Searchable tags")

    @classmethod
    def from_request(cls, request: ServiceRegistrationRequest) -> ServiceRegistration:
        """Create a ServiceRegistration from a request."""
        return cls(
            name=request.name,
            description=request.description,
            source_repo=request.source_repo,
            source_commit=request.source_commit,
            compose_hash=request.compose_hash,
            endpoints=request.endpoints,
            mrtd=request.mrtd,
            attestation_json=request.attestation_json,
            intel_ta_token=request.intel_ta_token,
            tags=request.tags,
        )


class ServiceListResponse(BaseModel):
    """Response model for listing services."""

    services: list[ServiceRegistration]
    total: int


class VerificationResponse(BaseModel):
    """Response model for attestation verification."""

    service_id: str
    verified: bool
    verification_time: datetime
    details: dict | None = None
    error: str | None = None


class HealthResponse(BaseModel):
    """Response model for health check."""

    status: str
    timestamp: datetime
    version: str = "0.1.0"
