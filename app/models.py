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


# ==============================================================================
# Job Queue Models
# ==============================================================================


class Worker(BaseModel):
    """Model for a registered standby worker."""

    worker_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()), description="Unique worker identifier"
    )
    attestation: dict = Field(..., description="Initial VM attestation")
    capabilities: list[str] = Field(
        default_factory=lambda: ["docker"], description="Worker capabilities"
    )
    registered_at: datetime = Field(default_factory=datetime.utcnow)
    last_heartbeat: datetime = Field(default_factory=datetime.utcnow)
    status: str = Field(
        default="available", description="available, busy, or offline"
    )
    current_job_id: str | None = Field(default=None, description="Current job being processed")


class WorkerRegistrationRequest(BaseModel):
    """Request model for worker registration."""

    attestation: dict = Field(..., description="TDX attestation from VM")
    capabilities: list[str] = Field(
        default_factory=lambda: ["docker"], description="Worker capabilities"
    )


class WorkerRegistrationResponse(BaseModel):
    """Response model for worker registration."""

    worker_id: str
    poll_interval: int = Field(default=30, description="Seconds between poll requests")


class Job(BaseModel):
    """Model for a job in the queue."""

    job_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()), description="Unique job identifier"
    )
    compose: str = Field(..., description="Base64 encoded docker-compose.yml")
    build_context: dict[str, str] = Field(
        default_factory=dict, description="filename -> base64 content"
    )
    config: dict = Field(
        default_factory=dict,
        description="Job configuration (health_endpoint, service_name, etc.)",
    )
    status: str = Field(
        default="queued", description="queued, assigned, running, completed, failed"
    )
    worker_id: str | None = Field(default=None, description="Assigned worker ID")
    submitted_at: datetime = Field(default_factory=datetime.utcnow)
    started_at: datetime | None = Field(default=None)
    completed_at: datetime | None = Field(default=None)
    attestation: dict | None = Field(
        default=None, description="Workload attestation after completion"
    )
    service_id: str | None = Field(
        default=None, description="Service ID if registered with discovery"
    )
    error: str | None = Field(default=None, description="Error message if failed")


class JobSubmitRequest(BaseModel):
    """Request model for job submission."""

    compose: str = Field(..., description="Base64 encoded docker-compose.yml")
    build_context: dict[str, str] = Field(
        default_factory=dict, description="filename -> base64 content"
    )
    config: dict = Field(
        default_factory=dict,
        description="Job configuration (service_name, service_url, health_endpoint, etc.)",
    )


class JobSubmitResponse(BaseModel):
    """Response model for job submission."""

    job_id: str
    status: str = Field(default="queued")


class JobPollResponse(BaseModel):
    """Response model for job polling."""

    job_id: str | None = Field(default=None)
    compose: str | None = Field(default=None)
    build_context: dict[str, str] | None = Field(default=None)
    config: dict | None = Field(default=None)


class JobCompleteRequest(BaseModel):
    """Request model for job completion."""

    status: str = Field(..., description="completed or failed")
    attestation: dict | None = Field(default=None, description="Workload attestation")
    service_id: str | None = Field(default=None, description="Service ID if registered")
    error: str | None = Field(default=None, description="Error message if failed")


class JobStatusResponse(BaseModel):
    """Response model for job status."""

    job_id: str
    status: str
    submitted_at: datetime
    started_at: datetime | None = None
    completed_at: datetime | None = None
    attestation: dict | None = None
    service_id: str | None = None
    error: str | None = None


# ==============================================================================
# Launcher Agent Models
# ==============================================================================


class LauncherAgent(BaseModel):
    """A registered TDX VM launcher agent."""

    agent_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()), description="Unique agent identifier"
    )
    vm_name: str = Field(..., description="Libvirt domain name")
    status: str = Field(
        default="undeployed",
        description="Agent status: undeployed, deploying, deployed, error",
    )

    # Attestation
    attestation: dict = Field(..., description="Full TDX attestation from registration")
    mrtd: str = Field(default="", description="TDX measurement (extracted from attestation)")
    intel_ta_token: str | None = Field(default=None, description="JWT from Intel Trust Authority")

    # Deployment tracking
    current_deployment_id: str | None = Field(
        default=None, description="Active deployment ID"
    )
    service_url: str | None = Field(
        default=None, description="Service URL for health checks (from deployment config)"
    )
    health_endpoint: str = Field(
        default="/health", description="Health check endpoint path"
    )

    # Health tracking
    health_status: str = Field(
        default="unknown", description="Health status: healthy, unhealthy, unknown"
    )
    last_health_check: datetime | None = Field(
        default=None, description="Last health check timestamp"
    )
    unhealthy_since: datetime | None = Field(
        default=None, description="When the agent became unhealthy (for reassignment logic)"
    )

    # Lifecycle
    registered_at: datetime = Field(default_factory=datetime.utcnow)
    last_heartbeat: datetime = Field(default_factory=datetime.utcnow)
    version: str = Field(default="1.0.0", description="Launcher code version")

    # Trust verification
    verified: bool = Field(
        default=False,
        description="Whether the agent's MRTD is in the trusted list",
    )
    verification_error: str | None = Field(
        default=None,
        description="Error message if MRTD verification failed",
    )


class AgentRegistrationRequest(BaseModel):
    """Request model for agent registration."""

    attestation: dict = Field(..., description="TDX attestation from VM")
    vm_name: str = Field(..., description="Libvirt domain name")
    version: str = Field(default="1.0.0", description="Launcher version")


class AgentRegistrationResponse(BaseModel):
    """Response model for agent registration."""

    agent_id: str
    poll_interval: int = Field(default=30, description="Seconds between poll requests")


class AgentPollResponse(BaseModel):
    """Response model for agent polling."""

    deployment: dict | None = Field(
        default=None,
        description="Deployment config if available: {deployment_id, compose, build_context, config}",
    )
    update: dict | None = Field(
        default=None,
        description="Update instructions: {check_github: true}",
    )


class AgentStatusRequest(BaseModel):
    """Request model for agent status update."""

    status: str = Field(..., description="New status: deploying, deployed, error")
    deployment_id: str = Field(..., description="Deployment ID being updated")
    error: str | None = Field(default=None, description="Error message if status is error")


class AgentDeployedRequest(BaseModel):
    """Request model for deployment completion."""

    deployment_id: str = Field(..., description="Completed deployment ID")
    service_id: str = Field(..., description="Registered service ID")
    attestation: dict = Field(..., description="Workload attestation")


class AgentListResponse(BaseModel):
    """Response model for listing agents."""

    agents: list[LauncherAgent]
    total: int


# ==============================================================================
# Deployment Models
# ==============================================================================


class Deployment(BaseModel):
    """A deployment configuration for a launcher agent."""

    deployment_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()), description="Unique deployment identifier"
    )

    # What to deploy
    compose: str = Field(..., description="Base64 encoded docker-compose.yml")
    build_context: dict[str, str] = Field(
        default_factory=dict, description="filename -> base64 content"
    )
    config: dict = Field(
        default_factory=dict,
        description="Deployment config: service_name, service_url, health_endpoint, etc.",
    )

    # Assignment
    agent_id: str = Field(..., description="Assigned launcher agent ID")
    status: str = Field(
        default="pending",
        description="Deployment status: pending, assigned, running, completed, failed",
    )

    # Results
    service_id: str | None = Field(
        default=None, description="Registered service ID after successful deploy"
    )
    attestation: dict | None = Field(
        default=None, description="Workload attestation after deployment"
    )
    error: str | None = Field(default=None, description="Error message if failed")

    # Timestamps
    created_at: datetime = Field(default_factory=datetime.utcnow)
    started_at: datetime | None = Field(default=None)
    completed_at: datetime | None = Field(default=None)


class DeploymentCreateRequest(BaseModel):
    """Request model for creating a deployment."""

    compose: str = Field(..., description="Base64 encoded docker-compose.yml")
    build_context: dict[str, str] = Field(
        default_factory=dict, description="filename -> base64 content"
    )
    config: dict = Field(
        default_factory=dict,
        description="Deployment config: service_name, service_url, health_endpoint, intel_api_key, etc.",
    )
    agent_id: str = Field(..., description="Target agent ID (required)")


class DeploymentCreateResponse(BaseModel):
    """Response model for deployment creation."""

    deployment_id: str
    status: str = Field(default="pending")


class DeploymentListResponse(BaseModel):
    """Response model for listing deployments."""

    deployments: list[Deployment]
    total: int


# ==============================================================================
# Trusted MRTD Models - For verifying launcher agent measurements
# ==============================================================================


class TrustedMrtd(BaseModel):
    """A trusted MRTD measurement for launcher agents."""

    mrtd: str = Field(..., description="TDX MRTD measurement (hex string)")
    description: str = Field(default="", description="Human-readable description")
    image_version: str = Field(default="", description="Launcher image version")
    added_at: datetime = Field(default_factory=datetime.utcnow)
    added_by: str = Field(default="", description="Who added this trusted MRTD")
    active: bool = Field(default=True, description="Whether this MRTD is currently trusted")


class TrustedMrtdCreateRequest(BaseModel):
    """Request model for adding a trusted MRTD."""

    mrtd: str = Field(..., description="TDX MRTD measurement (hex string)")
    description: str = Field(default="", description="Human-readable description")
    image_version: str = Field(default="", description="Launcher image version")


class TrustedMrtdListResponse(BaseModel):
    """Response model for listing trusted MRTDs."""

    trusted_mrtds: list[TrustedMrtd]
    total: int
