"""Request/Response DTOs for EasyEnclave API.

Data models are in db_models.py (SQLModel classes that serve as both ORM and Pydantic models).
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

# Re-export data models from db_models for backwards compatibility
from .db_models import (  # noqa: F401
    Account,
    Agent,
    App,
    AppVersion,
    Deployment,
    Service,
    Transaction,
)

# Aliases for backward compatibility
ServiceRegistration = Service


# =============================================================================
# Service API
# =============================================================================


class ServiceRegistrationRequest(BaseModel):
    """Request for registering a service."""

    name: str
    description: str = ""
    source_repo: str | None = None
    source_commit: str | None = None
    compose_hash: str | None = None
    endpoints: dict[str, str] = Field(default_factory=dict)
    mrtd: str | None = None
    attestation_json: dict | None = None
    intel_ta_token: str | None = None
    tags: list[str] = Field(default_factory=list)


class ServiceListResponse(BaseModel):
    """Response for listing services."""

    services: list[Service]
    total: int


class VerificationResponse(BaseModel):
    """Response for attestation verification."""

    service_id: str
    verified: bool
    verification_time: datetime
    details: dict | None = None
    error: str | None = None


class HealthResponse(BaseModel):
    """Response for health check."""

    status: str
    timestamp: datetime
    version: str = "0.1.0"
    boot_id: str | None = None
    git_sha: str | None = None
    attestation: dict | None = None
    proxy_url: str | None = None
    # High-level feature flags (do not expose secrets).
    gcp_project_configured: bool = False
    gcp_service_account_key_configured: bool = False
    gcp_capacity_fulfiller_enabled: bool = False


# =============================================================================
# Agent API
# =============================================================================


class AgentRegistrationRequest(BaseModel):
    """Request for agent registration."""

    attestation: dict
    vm_name: str
    version: str = "1.0.0"
    node_size: str = ""
    datacenter: str = ""


class AgentRegistrationResponse(BaseModel):
    """Response for agent registration."""

    agent_id: str
    poll_interval: int = 30
    tunnel_token: str | None = None
    hostname: str | None = None


class AgentChallengeResponse(BaseModel):
    """Response for nonce challenge request."""

    nonce: str
    ttl_seconds: int
    issued_at: str


class AgentStatusRequest(BaseModel):
    """Request for agent status update."""

    status: str
    deployment_id: str
    error: str | None = None


class AgentHeartbeatRequest(BaseModel):
    """Agent heartbeat + fresh attestation push."""

    vm_name: str
    attestation: dict
    status: str | None = None
    deployment_id: str | None = None


class AgentDeployedRequest(BaseModel):
    """Request for deployment completion."""

    deployment_id: str
    service_id: str
    attestation: dict


class AgentListResponse(BaseModel):
    """Response for listing agents."""

    agents: list[Agent]
    total: int


class AgentCapacityTarget(BaseModel):
    """Desired minimum capacity for a datacenter/node-size pool."""

    datacenter: str
    node_size: str = ""
    min_count: int = Field(default=1, ge=0)


class AgentCapacityReconcileRequest(BaseModel):
    """Request for control-plane agent capacity reconciliation."""

    targets: list[AgentCapacityTarget] = Field(default_factory=list)
    require_verified: bool = True
    require_healthy: bool = True
    require_hostname: bool = True
    allowed_statuses: list[str] = Field(
        default_factory=lambda: ["undeployed", "deployed", "deploying"]
    )
    dispatch: bool = False
    reason: str = ""
    account_id: str | None = None


class AgentCapacityTargetResult(BaseModel):
    """Observed capacity and shortfall for one datacenter/node-size pool."""

    datacenter: str
    node_size: str = ""
    min_count: int
    eligible_count: int
    shortfall: int
    eligible_agent_ids: list[str] = Field(default_factory=list)


class AgentCapacityDispatchResult(BaseModel):
    """Result of dispatching an external provisioning request."""

    datacenter: str
    node_size: str = ""
    requested_count: int
    dispatched: bool
    status_code: int | None = None
    detail: str | None = None


class AgentCapacityReconcileResponse(BaseModel):
    """Response for agent capacity reconciliation."""

    eligible: bool
    total_shortfall: int
    targets: list[AgentCapacityTargetResult]
    dispatches: list[AgentCapacityDispatchResult] = Field(default_factory=list)


class CapacityPurchaseRequest(BaseModel):
    """Request paid warm capacity for a datacenter/node-size pool."""

    datacenter: str
    node_size: str = "tiny"
    min_warm_count: int = Field(default=1, ge=1)
    months: int = Field(default=1, ge=1)
    reason: str = "capacity-purchase"


class CapacityPoolTargetUpsertRequest(BaseModel):
    """Create or update a warm-capacity target for one pool."""

    datacenter: str
    node_size: str = ""
    min_warm_count: int = Field(default=0, ge=0)
    enabled: bool = True
    require_verified: bool = True
    require_healthy: bool = True
    require_hostname: bool = True
    dispatch: bool = False
    reason: str = "capacity-pool-controller"


class CapacityPoolTargetView(BaseModel):
    """Warm-capacity target plus current reservation state."""

    datacenter: str
    node_size: str = ""
    min_warm_count: int
    enabled: bool
    require_verified: bool
    require_healthy: bool
    require_hostname: bool
    dispatch: bool
    reason: str
    eligible_agents: int = 0
    open_reservations: int = 0
    shortfall: int = 0


class CapacityPoolTargetListResponse(BaseModel):
    """Admin response for warm-capacity pool targets."""

    targets: list[CapacityPoolTargetView] = Field(default_factory=list)
    total: int = 0


class CapacityReservationView(BaseModel):
    """Admin view for one capacity reservation."""

    reservation_id: str
    agent_id: str
    datacenter: str
    node_size: str = ""
    status: str
    deployment_id: str | None = None
    note: str = ""
    created_at: datetime
    updated_at: datetime


class CapacityReservationListResponse(BaseModel):
    """Admin response for capacity reservations."""

    reservations: list[CapacityReservationView] = Field(default_factory=list)
    total: int = 0


class CapacityPurchaseResponse(BaseModel):
    """Response for a billing-backed capacity purchase request."""

    request_id: str
    account_id: str
    datacenter: str
    node_size: str
    min_warm_count: int
    months: int
    simulated_payment: bool
    charged_amount_usd: float
    transaction_id: str
    balance_after: float
    target: CapacityPoolTargetView
    capacity: AgentCapacityReconcileResponse


class CapacityLaunchOrderView(BaseModel):
    """View model for one capacity launch order."""

    order_id: str
    datacenter: str
    node_size: str = ""
    status: str
    reason: str
    requested_count: int = 1
    account_id: str | None = None
    claimed_by_account_id: str | None = None
    claim_expires_at: datetime | None = None
    claimed_at: datetime | None = None
    fulfilled_at: datetime | None = None
    vm_name: str | None = None
    error: str | None = None
    created_at: datetime
    updated_at: datetime


class CapacityLaunchOrderListResponse(BaseModel):
    """Response for listing capacity launch orders."""

    orders: list[CapacityLaunchOrderView] = Field(default_factory=list)
    total: int = 0


class CapacityLaunchOrderClaimRequest(BaseModel):
    """Launcher request for claiming next order."""

    datacenter: str = ""
    node_size: str = ""


class CapacityLaunchOrderClaimResponse(BaseModel):
    """Launcher response after attempting to claim next order."""

    claimed: bool
    order: CapacityLaunchOrderView | None = None
    # Plaintext one-time token (only returned at claim time).
    bootstrap_token: str | None = None


class CapacityLaunchOrderUpdateRequest(BaseModel):
    """Launcher update for an already-claimed order."""

    status: str  # claimed|provisioning|fulfilled|failed
    vm_name: str | None = None
    error: str | None = None


class CloudResourceAgent(BaseModel):
    """Observed cloud resource represented by a registered agent."""

    agent_id: str
    vm_name: str
    cloud: str
    datacenter: str
    availability_zone: str = ""
    region: str = ""
    node_size: str = ""
    status: str
    health_status: str = ""
    verified: bool
    deployed_app: str | None = None
    hostname: str | None = None


class CloudResourceCloudSummary(BaseModel):
    """Per-cloud aggregate counts for observed resources."""

    cloud: str
    total_agents: int
    healthy_agents: int
    verified_agents: int
    undeployed_agents: int
    deployed_agents: int
    deploying_agents: int
    node_size_counts: dict[str, int] = Field(default_factory=dict)
    datacenters: list[str] = Field(default_factory=list)


class CloudResourceInventoryResponse(BaseModel):
    """Admin response for cloud resource inventory."""

    generated_at: datetime
    total_agents: int
    total_deployments: int
    active_deployments: int
    clouds: list[CloudResourceCloudSummary] = Field(default_factory=list)
    agents: list[CloudResourceAgent] = Field(default_factory=list)


class ExternalCloudResource(BaseModel):
    """One cloud resource returned by the external provisioner inventory."""

    provider: str
    cloud: str
    resource_id: str
    resource_type: str = ""
    name: str = ""
    datacenter: str = ""
    availability_zone: str = ""
    region: str = ""
    status: str = ""
    labels: dict[str, str] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)
    tracked: bool = False
    orphaned: bool = False
    linked_agent_id: str | None = None
    linked_vm_name: str | None = None


class ExternalCloudInventoryResponse(BaseModel):
    """Admin response for external Azure/GCP cloud inventory."""

    configured: bool
    generated_at: datetime
    total_resources: int = 0
    tracked_count: int = 0
    orphaned_count: int = 0
    detail: str | None = None
    resources: list[ExternalCloudResource] = Field(default_factory=list)


class ExternalCloudCleanupRequest(BaseModel):
    """Request to clean up external cloud resources via provisioner."""

    dry_run: bool = True
    only_orphaned: bool = True
    providers: list[str] = Field(default_factory=list)
    resource_ids: list[str] = Field(default_factory=list)
    reason: str = "admin-cloud-cleanup"


class ExternalCloudCleanupResponse(BaseModel):
    """Response from external cloud cleanup dispatch."""

    configured: bool
    dispatched: bool
    dry_run: bool
    requested_count: int = 0
    status_code: int | None = None
    detail: str | None = None


# =============================================================================
# Admin: Unified Cleanup
# =============================================================================


class CloudflareCleanupRequest(BaseModel):
    """Request to cleanup Cloudflare resources."""

    dry_run: bool = False


class CloudflareCleanupResponse(BaseModel):
    """Response for Cloudflare orphan cleanup."""

    dry_run: bool = False
    tunnels_deleted: int = 0
    dns_deleted: int = 0
    tunnels_candidates: int = 0
    dns_candidates: int = 0
    tunnels_failed: int = 0
    dns_failed: int = 0


class UnifiedOrphanCleanupRequest(BaseModel):
    """Run orphan cleanup across multiple systems (Cloudflare + external provisioner)."""

    dry_run: bool = True
    cloudflare: bool = True
    external_cloud: bool = True
    reason: str = "admin-unified-orphan-cleanup"


class UnifiedOrphanCleanupResponse(BaseModel):
    """Response for unified orphan cleanup."""

    dry_run: bool
    cloudflare_configured: bool
    external_cloud_configured: bool
    cloudflare: CloudflareCleanupResponse | None = None
    external_cloud: ExternalCloudCleanupResponse | None = None
    detail: str | None = None


class AdminAgentCleanupRequest(BaseModel):
    """Delete an agent and also attempt to delete linked external cloud resources."""

    dry_run: bool = True
    reason: str = "admin-agent-cleanup"


class AdminAgentCleanupResponse(BaseModel):
    """Response for admin agent cleanup."""

    dry_run: bool
    agent_id: str
    vm_name: str | None = None
    cloudflare_deleted: bool = False
    agent_deleted: bool = False
    external_cloud: ExternalCloudCleanupResponse | None = None
    external_candidates: int = 0
    detail: str | None = None


class AdminStaleAgentCleanupRequest(BaseModel):
    """Bulk-delete agents that are stale (no heartbeat for N hours)."""

    stale_hours: float | None = None
    include_deployed: bool = False
    dry_run: bool = True


class AdminStaleAgentCleanupResponse(BaseModel):
    """Response for bulk stale-agent cleanup."""

    dry_run: bool
    stale_hours: float
    candidates: int = 0
    deleted_agents: list[dict] = Field(default_factory=list)
    skipped_agents: list[dict] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)


# =============================================================================
# Deployment API
# =============================================================================


class DeploymentCreateResponse(BaseModel):
    """Response for deployment creation."""

    deployment_id: str
    agent_id: str
    status: str = "pending"


class DeploymentPreflightIssue(BaseModel):
    """Structured validation issue for deployment preflight."""

    code: str
    message: str
    agent_id: str | None = None
    node_size: str | None = None
    datacenter: str | None = None


class DeploymentPreflightResponse(BaseModel):
    """Response for deployment preflight checks."""

    dry_run: bool = True
    eligible: bool
    selected_agent_id: str | None = None
    selected_node_size: str | None = None
    selected_datacenter: str | None = None
    selected_cloud: str | None = None
    issues: list[DeploymentPreflightIssue] = Field(default_factory=list)


class DeploymentListResponse(BaseModel):
    """Response for listing deployments."""

    deployments: list[Deployment]
    total: int


# =============================================================================
# App Catalog API
# =============================================================================


class AppCreateRequest(BaseModel):
    """Request for registering an app."""

    name: str
    description: str = ""
    source_repo: str | None = None
    maintainers: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)


class AppListResponse(BaseModel):
    """Response for listing apps."""

    apps: list[App]
    total: int


class AppVersionCreateRequest(BaseModel):
    """Request for publishing an app version."""

    version: str
    compose: str
    node_size: str = ""
    image_digest: str | None = None
    source_commit: str | None = None
    source_tag: str | None = None
    ingress: list[dict] | None = None  # [{"path": "/*", "port": 8080}]


class AppVersionResponse(BaseModel):
    """Response for a published app version."""

    version_id: str
    app_name: str
    version: str
    node_size: str = ""
    ingress: list[dict] | None = None
    mrtd: str | None = None
    attestation: dict | None = None
    status: str
    rejection_reason: str | None = None
    published_at: datetime


class AppVersionListResponse(BaseModel):
    """Response for listing app versions."""

    versions: list[AppVersion]
    total: int


class DeployFromVersionRequest(BaseModel):
    """Request for deploying from an app version."""

    agent_id: str | None = None
    config: dict | None = None
    node_size: str = ""  # Required agent node_size (e.g., "tiny", "standard", "llm"). Empty = any.
    dry_run: bool = False
    allowed_datacenters: list[str] = Field(default_factory=list)
    denied_datacenters: list[str] = Field(default_factory=list)
    allowed_clouds: list[str] = Field(default_factory=list)
    denied_clouds: list[str] = Field(default_factory=list)
    allow_measuring_enclave_fallback: bool = False
    # Billing fields
    account_id: str | None = None  # Optional for backward compatibility
    sla_class: str = "adhoc"  # adhoc|three_nines|four_nines|five_nines
    machine_size: str = "default"  # default|h100
    cpu_vcpus: float = 2.0  # For cost calculation
    memory_gb: float = 4.0
    gpu_count: int = 0
    # GitHub ownership
    github_owner: str | None = None


class SetAgentOwnerRequest(BaseModel):
    """Request for setting or clearing GitHub owner on an agent."""

    github_owner: str | None = None


class MeasurementCallbackRequest(BaseModel):
    """Callback from measuring enclave with results."""

    version_id: str
    status: str  # "success" or "failed"
    error: str | None = None
    measurement: dict | None = None  # {compose_hash, resolved_images}


class ManualAttestRequest(BaseModel):
    """Optional metadata for admin bootstrap attestation."""

    mrtd: str | None = None
    attestation: dict | None = None


# =============================================================================
# Billing API
# =============================================================================


class AccountCreateRequest(BaseModel):
    """Request for creating a billing account."""

    name: str
    description: str = ""
    account_type: str  # "deployer" | "agent" | "contributor" | "launcher"


class AccountLinkIdentityRequest(BaseModel):
    """Request to link an account with contributor identity metadata."""

    github_login: str | None = None
    github_org: str | None = None


class AccountResponse(BaseModel):
    """Response for a billing account (includes computed balance)."""

    account_id: str
    name: str
    description: str
    account_type: str
    github_login: str | None = None
    github_org: str | None = None
    balance: float
    created_at: datetime


class AccountListResponse(BaseModel):
    """Response for listing accounts."""

    accounts: list[AccountResponse]
    total: int


class DepositRequest(BaseModel):
    """Request for depositing funds into an account."""

    amount: float = Field(gt=0)
    description: str = ""


class CreatePaymentIntentRequest(BaseModel):
    """Request for creating a Stripe payment intent."""

    amount: float = Field(gt=0)


class ApiKeyRotateResponse(BaseModel):
    """Response after rotating an account API key."""

    account_id: str
    api_key: str
    rotated_at: datetime
    warning: str


class AdminLoginRequest(BaseModel):
    """Request for admin login."""

    password: str


class AdminLoginResponse(BaseModel):
    """Response for admin login."""

    token: str
    expires_at: datetime


class TransactionResponse(BaseModel):
    """Response for a single transaction."""

    transaction_id: str
    account_id: str
    amount: float
    balance_after: float
    tx_type: str
    description: str
    reference_id: str | None = None
    created_at: datetime


class TransactionListResponse(BaseModel):
    """Response for listing transactions."""

    transactions: list[TransactionResponse]
    total: int


class RateCardResponse(BaseModel):
    """Response for the billing rate card."""

    rates: dict[str, float]
    currency: str = "USD"


class AppRevenueShareCreateRequest(BaseModel):
    """Request to add a contributor share rule for an app."""

    account_id: str
    share_bps: int = Field(ge=1, le=10000)
    label: str = ""


class AppRevenueShareResponse(BaseModel):
    """Contributor share rule for an app."""

    share_id: str
    app_name: str
    account_id: str
    account_name: str | None = None
    github_login: str | None = None
    share_bps: int
    share_percent: float
    label: str
    created_at: datetime


class AppRevenueShareListResponse(BaseModel):
    """List of contributor share rules for one app."""

    app_name: str
    total_bps: int
    total_percent: float
    shares: list[AppRevenueShareResponse]
