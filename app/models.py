"""Data models for EasyEnclave discovery service."""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field


class ServiceRegistrationRequest(BaseModel):
    """Request model for registering a new service."""

    name: str = Field(..., description="Human-readable service name")
    description: str = Field(default="", description="What this service does")

    # Source & Build Info
    source_repo: str | None = Field(default=None, description="GitHub repo URL")
    source_commit: str | None = Field(default=None, description="Git commit SHA")
    compose_hash: str | None = Field(default=None, description="SHA256 of docker-compose.yml")

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
    intel_ta_token: str | None = Field(default=None, description="JWT from Intel Trust Authority")

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
    compose_hash: str | None = Field(default=None, description="SHA256 of docker-compose.yml")

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
    intel_ta_token: str | None = Field(default=None, description="JWT from Intel Trust Authority")

    # Metadata
    registered_at: datetime = Field(default_factory=datetime.utcnow)
    last_health_check: datetime | None = Field(default=None)
    health_status: str = Field(default="unknown", description="healthy, unhealthy, or unknown")
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
    status: str = Field(default="available", description="available, busy, or offline")
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

    # Cloudflare Tunnel
    tunnel_id: str | None = Field(default=None, description="Cloudflare Tunnel ID")
    hostname: str | None = Field(
        default=None, description="Public hostname (e.g., agent-abc123.easyenclave.com)"
    )

    # Deployment tracking
    current_deployment_id: str | None = Field(default=None, description="Active deployment ID")
    service_url: str | None = Field(
        default=None, description="Service URL for health checks (from deployment config)"
    )
    health_endpoint: str = Field(default="/health", description="Health check endpoint path")

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
    tunnel_error: str | None = Field(
        default=None,
        description="Error message if Cloudflare tunnel creation failed",
    )

    # Continuous attestation tracking
    last_attestation_check: datetime | None = Field(
        default=None,
        description="Last time attestation was verified",
    )
    attestation_valid: bool = Field(
        default=True,
        description="Whether the last attestation check passed",
    )
    attestation_error: str | None = Field(
        default=None,
        description="Error from last attestation check (if failed)",
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
    # Cloudflare Tunnel info (only returned on initial registration)
    tunnel_token: str | None = Field(
        default=None, description="Cloudflare tunnel token for cloudflared"
    )
    hostname: str | None = Field(
        default=None, description="Public hostname (e.g., agent-abc123.easyenclave.com)"
    )


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
    action: str | None = Field(
        default=None,
        description="Action for agent: 're_attest' if attestation failed",
    )
    message: str | None = Field(
        default=None,
        description="Human-readable message for the action",
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


class MrtdType(str, Enum):
    """Type of trusted MRTD - agent launcher vs app workload."""

    AGENT = "agent"  # Trusted launcher agent image (system, locked)
    PROXY = "proxy"  # Trusted cloudflared proxy image (system, locked)
    APP = "app"  # Trusted app workload image (dynamic, from app store)


class TrustedMrtd(BaseModel):
    """A trusted MRTD measurement for launcher agents or app workloads.

    Each trusted MRTD should be linked to a specific, auditable build.
    Agent MRTDs authorize VMs to register as launcher agents.
    App MRTDs authorize specific app workload images for deployment.
    """

    mrtd: str = Field(..., description="TDX MRTD measurement (hex string)")
    type: MrtdType = Field(
        default=MrtdType.AGENT,
        description="Type: 'agent' for launcher images, 'proxy' for cloudflared, 'app' for workloads",
    )
    locked: bool = Field(
        default=False, description="System MRTDs (agent/proxy) cannot be modified via API"
    )
    description: str = Field(default="", description="Human-readable description")
    image_version: str = Field(default="", description="Image version")

    # GitHub attestation - links MRTD to auditable source code
    source_repo: str | None = Field(
        default=None, description="GitHub repo URL (e.g., github.com/easyenclave/easyenclave)"
    )
    source_commit: str | None = Field(
        default=None, description="Git commit SHA that produced this MRTD"
    )
    source_tag: str | None = Field(default=None, description="Git tag (e.g., v1.0.0)")
    build_workflow: str | None = Field(
        default=None, description="GitHub Actions workflow URL that built the image"
    )
    image_digest: str | None = Field(default=None, description="Docker image digest (sha256:...)")

    # Metadata
    added_at: datetime = Field(default_factory=datetime.utcnow)
    added_by: str = Field(default="", description="Who added this trusted MRTD")
    active: bool = Field(default=True, description="Whether this MRTD is currently trusted")


class TrustedMrtdCreateRequest(BaseModel):
    """Request model for adding a trusted MRTD.

    Should include GitHub attestation fields to link the MRTD to auditable source.
    """

    mrtd: str = Field(..., description="TDX MRTD measurement (hex string)")
    type: MrtdType = Field(
        default=MrtdType.AGENT, description="Type: 'agent' for launcher images, 'app' for workloads"
    )
    description: str = Field(default="", description="Human-readable description")
    image_version: str = Field(default="", description="Image version")

    # GitHub attestation - links MRTD to auditable source code
    source_repo: str | None = Field(
        default=None, description="GitHub repo URL (e.g., github.com/easyenclave/easyenclave)"
    )
    source_commit: str | None = Field(
        default=None, description="Git commit SHA that produced this MRTD"
    )
    source_tag: str | None = Field(default=None, description="Git tag (e.g., v1.0.0)")
    build_workflow: str | None = Field(
        default=None, description="GitHub Actions workflow URL that built the image"
    )
    image_digest: str | None = Field(default=None, description="Docker image digest (sha256:...)")


class TrustedMrtdListResponse(BaseModel):
    """Response model for listing trusted MRTDs."""

    trusted_mrtds: list[TrustedMrtd]
    total: int


# ==============================================================================
# App Catalog Models - For app registration, publishing, and deployment
# ==============================================================================


class App(BaseModel):
    """An app in the catalog."""

    app_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()), description="Unique app identifier"
    )
    name: str = Field(..., description="Unique app name")
    description: str = Field(default="", description="What this app does")
    source_repo: str | None = Field(default=None, description="GitHub repo (e.g., 'org/repo')")
    maintainers: list[str] = Field(
        default_factory=list, description="Email addresses of maintainers"
    )
    tags: list[str] = Field(default_factory=list, description="Searchable tags")
    created_at: datetime = Field(default_factory=datetime.utcnow)


class AppCreateRequest(BaseModel):
    """Request model for registering an app."""

    name: str = Field(..., description="Unique app name")
    description: str = Field(default="", description="What this app does")
    source_repo: str | None = Field(default=None, description="GitHub repo (e.g., 'org/repo')")
    maintainers: list[str] = Field(
        default_factory=list, description="Email addresses of maintainers"
    )
    tags: list[str] = Field(default_factory=list, description="Searchable tags")


class AppListResponse(BaseModel):
    """Response model for listing apps."""

    apps: list[App]
    total: int


class AppVersion(BaseModel):
    """A published, attested version of an app."""

    version_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()), description="Unique version identifier"
    )
    app_name: str = Field(..., description="Name of the parent app")
    version: str = Field(..., description="Semver version string (e.g., '1.0.0')")
    compose: str = Field(..., description="Base64 encoded docker-compose.yml")
    image_digest: str | None = Field(default=None, description="Docker image digest (sha256:...)")
    source_commit: str | None = Field(default=None, description="Git commit SHA")
    source_tag: str | None = Field(default=None, description="Git tag (e.g., 'v1.0.0')")

    # Attestation results
    mrtd: str | None = Field(default=None, description="TDX measurement from attestation")
    attestation: dict | None = Field(default=None, description="Full attestation details")

    # Status: pending, attesting, attested, rejected, failed
    status: str = Field(
        default="pending",
        description="Version status: pending, attesting, attested, rejected, failed",
    )
    rejection_reason: str | None = Field(
        default=None, description="Reason for rejection (if status is rejected)"
    )

    published_at: datetime = Field(default_factory=datetime.utcnow)


class AppVersionCreateRequest(BaseModel):
    """Request model for publishing an app version."""

    version: str = Field(..., description="Semver version string (e.g., '1.0.0')")
    compose: str = Field(..., description="Base64 encoded docker-compose.yml")
    image_digest: str | None = Field(default=None, description="Docker image digest (sha256:...)")
    source_commit: str | None = Field(default=None, description="Git commit SHA")
    source_tag: str | None = Field(default=None, description="Git tag (e.g., 'v1.0.0')")


class AppVersionResponse(BaseModel):
    """Response model for a published app version."""

    version_id: str
    app_name: str
    version: str
    mrtd: str | None = None
    attestation: dict | None = None
    status: str
    rejection_reason: str | None = None
    published_at: datetime


class AppVersionListResponse(BaseModel):
    """Response model for listing app versions."""

    versions: list[AppVersion]
    total: int


class DeployFromVersionRequest(BaseModel):
    """Request model for deploying from an app version."""

    agent_id: str = Field(..., description="Target agent ID")
    config: dict | None = Field(
        default=None,
        description="Override config: service_url, health_endpoint, etc.",
    )


# ==============================================================================
# Agent and Workload Logging Models
# ==============================================================================


class LogLevel(str, Enum):
    """Log level for filtering."""

    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"


class LogSource(str, Enum):
    """Source of the log entry."""

    AGENT = "agent"  # Launcher agent logs
    CONTAINER = "container"  # Docker container logs


class LogEntry(BaseModel):
    """A single log entry from an agent or container."""

    log_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()), description="Unique log identifier"
    )
    agent_id: str = Field(..., description="Agent that generated/collected this log")
    source: LogSource = Field(..., description="Source: 'agent' or 'container'")
    container_name: str | None = Field(
        default=None, description="Container name (if source is container)"
    )
    level: LogLevel = Field(default=LogLevel.INFO, description="Log level")
    message: str = Field(..., description="Log message")
    timestamp: datetime = Field(
        default_factory=datetime.utcnow, description="When the log was generated"
    )
    received_at: datetime = Field(
        default_factory=datetime.utcnow, description="When the control plane received it"
    )
    metadata: dict = Field(default_factory=dict, description="Additional metadata")


class LogBatchRequest(BaseModel):
    """Request model for submitting a batch of logs."""

    logs: list[dict] = Field(..., description="List of log entries")
    min_level: LogLevel = Field(
        default=LogLevel.INFO,
        description="Minimum log level to include (client-side filtering)",
    )


class LogBatchResponse(BaseModel):
    """Response model for log batch submission."""

    received: int = Field(..., description="Number of logs received")
    stored: int = Field(..., description="Number of logs stored")


class LogQueryParams(BaseModel):
    """Query parameters for fetching logs."""

    agent_id: str | None = Field(default=None, description="Filter by agent ID")
    source: LogSource | None = Field(default=None, description="Filter by source")
    container_name: str | None = Field(default=None, description="Filter by container name")
    min_level: LogLevel = Field(default=LogLevel.INFO, description="Minimum log level")
    since: datetime | None = Field(default=None, description="Logs since this time")
    until: datetime | None = Field(default=None, description="Logs until this time")
    limit: int = Field(default=100, description="Maximum number of logs to return")


class LogListResponse(BaseModel):
    """Response model for listing logs."""

    logs: list[LogEntry]
    total: int
