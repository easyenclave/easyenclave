"""SQLModel database models for EasyEnclave storage.

These models serve as both SQLAlchemy ORM models AND Pydantic models,
eliminating the need for separate data classes.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from sqlmodel import JSON, Column, Field, SQLModel


def generate_uuid() -> str:
    return str(uuid.uuid4())


def utcnow() -> datetime:
    """Return current UTC time (timezone-aware)."""
    return datetime.now(timezone.utc)


class Service(SQLModel, table=True):
    """Service registration."""

    __tablename__ = "services"

    service_id: str = Field(default_factory=generate_uuid, primary_key=True)
    name: str = Field(unique=True, index=True)
    description: str = Field(default="")
    source_repo: str | None = None
    source_commit: str | None = None
    compose_hash: str | None = None
    endpoints: dict[str, str] = Field(default_factory=dict, sa_column=Column(JSON))
    mrtd: str | None = None
    attestation_json: dict | None = Field(default=None, sa_column=Column(JSON))
    intel_ta_token: str | None = None
    registered_at: datetime = Field(default_factory=utcnow)
    last_health_check: datetime | None = None
    health_status: str = Field(default="unknown", index=True)
    tags: list[str] = Field(default_factory=list, sa_column=Column(JSON))


class Agent(SQLModel, table=True):
    """Launcher agent."""

    __tablename__ = "agents"

    agent_id: str = Field(default_factory=generate_uuid, primary_key=True)
    vm_name: str = Field(unique=True, index=True)
    status: str = Field(default="undeployed", index=True)
    attestation: dict[str, Any] = Field(sa_column=Column(JSON))
    mrtd: str = Field(default="")
    rtmrs: dict[str, str] | None = Field(default=None, sa_column=Column(JSON))
    intel_ta_token: str | None = None
    tunnel_id: str | None = None
    hostname: str | None = None
    tunnel_token: str | None = None
    current_deployment_id: str | None = None
    service_url: str | None = None
    health_endpoint: str = Field(default="/health")
    health_status: str = Field(default="unknown")
    last_health_check: datetime | None = None
    unhealthy_since: datetime | None = None
    stats: dict | None = Field(default=None, sa_column=Column(JSON))
    registered_at: datetime = Field(default_factory=utcnow)
    last_heartbeat: datetime = Field(default_factory=utcnow)
    version: str = Field(default="1.0.0")
    verified: bool = Field(default=False, index=True)
    verification_error: str | None = None
    tunnel_error: str | None = None
    last_attestation_check: datetime | None = None
    attestation_valid: bool = Field(default=True)
    attestation_error: str | None = None
    # Billing fields
    account_id: str | None = Field(default=None, index=True)  # For earnings
    sla_tiers: list[str] = Field(
        default_factory=list, sa_column=Column(JSON)
    )  # Which tiers they support
    machine_sizes: list[str] = Field(
        default_factory=list, sa_column=Column(JSON)
    )  # Which sizes they support
    # TCB (Trusted Computing Base) status
    tcb_status: str | None = Field(default=None, index=True)
    tcb_verified_at: datetime | None = None


class Deployment(SQLModel, table=True):
    """Deployment record."""

    __tablename__ = "deployments"

    deployment_id: str = Field(default_factory=generate_uuid, primary_key=True)
    compose: str
    build_context: dict[str, str] = Field(default_factory=dict, sa_column=Column(JSON))
    config: dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON))
    agent_id: str = Field(index=True)
    status: str = Field(default="pending", index=True)
    service_id: str | None = None
    attestation: dict | None = Field(default=None, sa_column=Column(JSON))
    error: str | None = None
    created_at: datetime = Field(default_factory=utcnow)
    started_at: datetime | None = None
    completed_at: datetime | None = None
    # Billing fields
    account_id: str | None = Field(default=None, index=True)
    sla_class: str = Field(default="adhoc")  # adhoc|three_nines|four_nines|five_nines
    machine_size: str = Field(default="default")  # default|h100
    cpu_vcpus: float = Field(default=2.0)
    memory_gb: float = Field(default=4.0)
    gpu_count: int = Field(default=0)
    last_charge_time: datetime | None = None
    total_charged: float = Field(default=0.0)


class App(SQLModel, table=True):
    """App in the catalog."""

    __tablename__ = "apps"

    app_id: str = Field(default_factory=generate_uuid, primary_key=True)
    name: str = Field(unique=True, index=True)
    description: str = Field(default="")
    source_repo: str | None = None
    maintainers: list[str] = Field(default_factory=list, sa_column=Column(JSON))
    tags: list[str] = Field(default_factory=list, sa_column=Column(JSON))
    created_at: datetime = Field(default_factory=utcnow)


class AppVersion(SQLModel, table=True):
    """Published app version."""

    __tablename__ = "app_versions"

    version_id: str = Field(default_factory=generate_uuid, primary_key=True)
    app_name: str = Field(index=True)
    version: str
    compose: str
    image_digest: str | None = None
    source_commit: str | None = None
    source_tag: str | None = None
    mrtd: str | None = None
    attestation: dict | None = Field(default=None, sa_column=Column(JSON))
    ingress: list[dict] | None = Field(default=None, sa_column=Column(JSON))
    status: str = Field(default="pending", index=True)
    rejection_reason: str | None = None
    published_at: datetime = Field(default_factory=utcnow)


class Account(SQLModel, table=True):
    """Billing account holding a USD credit balance."""

    __tablename__ = "accounts"

    account_id: str = Field(default_factory=generate_uuid, primary_key=True)
    name: str = Field(unique=True, index=True)
    description: str = Field(default="")
    account_type: str = Field(index=True)  # "deployer" | "agent"
    created_at: datetime = Field(default_factory=utcnow)
    # API key authentication fields
    api_key_hash: str | None = None  # bcrypt hash
    api_key_prefix: str | None = Field(default=None, index=True)  # "ee_live_xxxx" for fast lookup
    # GitHub OAuth linking (for future auto-provisioning)
    github_id: int | None = Field(default=None, index=True)
    github_login: str | None = None
    github_org: str | None = None
    linked_at: datetime | None = None


class Transaction(SQLModel, table=True):
    """Immutable ledger entry for an account."""

    __tablename__ = "transactions"

    transaction_id: str = Field(default_factory=generate_uuid, primary_key=True)
    account_id: str = Field(index=True)
    amount: float
    balance_after: float
    tx_type: str = Field(index=True)  # "deposit", "withdrawal", "charge", "earning"
    description: str = Field(default="")
    reference_id: str | None = None
    created_at: datetime = Field(default_factory=utcnow)


class Setting(SQLModel, table=True):
    """Key-value settings stored in DB, overriding env vars."""

    __tablename__ = "settings"

    key: str = Field(primary_key=True)
    value: str = Field(default="")
    is_secret: bool = Field(default=False)
    updated_at: datetime = Field(default_factory=utcnow)


class AdminSession(SQLModel, table=True):
    """Admin authentication session."""

    __tablename__ = "admin_sessions"

    session_id: str = Field(default_factory=generate_uuid, primary_key=True)
    token_hash: str  # bcrypt hash
    token_prefix: str = Field(index=True)  # First 12 chars for fast lookup
    created_at: datetime = Field(default_factory=utcnow)
    expires_at: datetime
    last_used: datetime = Field(default_factory=utcnow)
    ip_address: str | None = None
    # GitHub OAuth fields
    github_id: int | None = None
    github_login: str | None = None
    github_email: str | None = None
    github_avatar_url: str | None = None
    auth_method: str = Field(default="password")  # "password" | "github_oauth"
