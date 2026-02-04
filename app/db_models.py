"""SQLModel database models for EasyEnclave storage."""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum
from typing import Any

from sqlmodel import JSON, Column, Field, SQLModel


def generate_uuid() -> str:
    """Generate a new UUID string."""
    return str(uuid.uuid4())


def utcnow() -> datetime:
    """Get current UTC time."""
    return datetime.utcnow()


class MrtdType(str, Enum):
    """Type of trusted MRTD - agent launcher vs app workload."""

    AGENT = "agent"
    PROXY = "proxy"
    APP = "app"


# =============================================================================
# Database Tables (SQLModel with table=True)
# =============================================================================


class ServiceDB(SQLModel, table=True):
    """Database model for service registrations."""

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


class WorkerDB(SQLModel, table=True):
    """Database model for standby workers."""

    __tablename__ = "workers"

    worker_id: str = Field(default_factory=generate_uuid, primary_key=True)
    attestation: dict[str, Any] = Field(sa_column=Column(JSON))
    capabilities: list[str] = Field(default_factory=lambda: ["docker"], sa_column=Column(JSON))
    registered_at: datetime = Field(default_factory=utcnow)
    last_heartbeat: datetime = Field(default_factory=utcnow)
    status: str = Field(default="available")
    current_job_id: str | None = None


class JobDB(SQLModel, table=True):
    """Database model for jobs."""

    __tablename__ = "jobs"

    job_id: str = Field(default_factory=generate_uuid, primary_key=True)
    compose: str
    build_context: dict[str, str] = Field(default_factory=dict, sa_column=Column(JSON))
    config: dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON))
    status: str = Field(default="queued", index=True)
    worker_id: str | None = None
    submitted_at: datetime = Field(default_factory=utcnow)
    started_at: datetime | None = None
    completed_at: datetime | None = None
    attestation: dict | None = Field(default=None, sa_column=Column(JSON))
    service_id: str | None = None
    error: str | None = None
    queue_order: int | None = Field(default=None, index=True)


class AgentDB(SQLModel, table=True):
    """Database model for launcher agents."""

    __tablename__ = "agents"

    agent_id: str = Field(default_factory=generate_uuid, primary_key=True)
    vm_name: str = Field(unique=True, index=True)
    status: str = Field(default="undeployed", index=True)
    attestation: dict[str, Any] = Field(sa_column=Column(JSON))
    mrtd: str = Field(default="")
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


class DeploymentDB(SQLModel, table=True):
    """Database model for deployments."""

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


class TrustedMrtdDB(SQLModel, table=True):
    """Database model for trusted MRTD measurements."""

    __tablename__ = "trusted_mrtds"

    mrtd: str = Field(primary_key=True)
    type: str = Field(default="agent")
    locked: bool = Field(default=False)
    description: str = Field(default="")
    image_version: str = Field(default="")
    source_repo: str | None = None
    source_commit: str | None = None
    source_tag: str | None = None
    build_workflow: str | None = None
    image_digest: str | None = None
    attestation_url: str | None = None
    added_at: datetime = Field(default_factory=utcnow)
    added_by: str = Field(default="")
    active: bool = Field(default=True)


class AppDB(SQLModel, table=True):
    """Database model for apps."""

    __tablename__ = "apps"

    app_id: str = Field(default_factory=generate_uuid, primary_key=True)
    name: str = Field(unique=True, index=True)
    description: str = Field(default="")
    source_repo: str | None = None
    maintainers: list[str] = Field(default_factory=list, sa_column=Column(JSON))
    tags: list[str] = Field(default_factory=list, sa_column=Column(JSON))
    created_at: datetime = Field(default_factory=utcnow)


class AppVersionDB(SQLModel, table=True):
    """Database model for app versions."""

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
    status: str = Field(default="pending", index=True)
    rejection_reason: str | None = None
    published_at: datetime = Field(default_factory=utcnow)

    class Config:
        """SQLModel config."""

        # Unique constraint on (app_name, version) is handled by Alembic migration
