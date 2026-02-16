"""SQLModel-backed storage for EasyEnclave."""

from __future__ import annotations

import logging
import os
import re
from datetime import datetime, timedelta, timezone

from sqlmodel import select

from .database import get_db
from .db_models import (
    Account,
    AdminSession,
    Agent,
    App,
    AppRevenueShare,
    AppVersion,
    CapacityPoolTarget,
    CapacityReservation,
    Deployment,
    Service,
    Transaction,
    TrustedMrtd,
)

logger = logging.getLogger(__name__)

UNHEALTHY_TIMEOUT = timedelta(hours=1)
AGENT_OFFLINE_TIMEOUT = timedelta(minutes=5)


def _aware(dt: datetime) -> datetime:
    """Ensure a datetime is timezone-aware (assume UTC if naive)."""
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def _normalize_pool_value(value: str | None) -> str:
    return (value or "").strip().lower()


class ServiceStore:
    """Storage for service registrations."""

    def get(self, service_id: str) -> Service | None:
        with get_db() as session:
            return session.get(Service, service_id)

    def get_by_name(self, name: str) -> Service | None:
        with get_db() as session:
            return session.exec(select(Service).where(Service.name == name)).first()

    def upsert(self, service: Service) -> tuple[str, bool]:
        """Register or update by name. Returns (service_id, is_new)."""
        with get_db() as session:
            existing = session.exec(select(Service).where(Service.name == service.name)).first()
            if existing:
                for field in [
                    "description",
                    "source_repo",
                    "source_commit",
                    "compose_hash",
                    "endpoints",
                    "mrtd",
                    "attestation_json",
                    "intel_ta_token",
                    "last_health_check",
                    "health_status",
                    "tags",
                ]:
                    setattr(existing, field, getattr(service, field))
                session.add(existing)
                return existing.service_id, False
            session.add(service)
            return service.service_id, True

    def _is_timed_out(self, service: Service) -> bool:
        if service.health_status == "healthy" or service.last_health_check is None:
            return False
        return datetime.now(timezone.utc) - _aware(service.last_health_check) > UNHEALTHY_TIMEOUT

    def list(self, filters: dict | None = None, include_down: bool = False) -> list[Service]:
        with get_db() as session:
            services = list(session.exec(select(Service)).all())

        if not include_down:
            services = [s for s in services if not self._is_timed_out(s)]

        if filters:
            if filters.get("name"):
                services = [s for s in services if filters["name"].lower() in s.name.lower()]
            if filters.get("tags"):
                filter_tags = set(filters["tags"])
                services = [s for s in services if filter_tags & set(s.tags or [])]
            if filters.get("environment"):
                services = [s for s in services if filters["environment"] in (s.endpoints or {})]
            if filters.get("mrtd"):
                services = [s for s in services if s.mrtd == filters["mrtd"]]
            if filters.get("health_status"):
                services = [s for s in services if s.health_status == filters["health_status"]]

        return services

    def delete(self, service_id: str) -> bool:
        with get_db() as session:
            service = session.get(Service, service_id)
            if service:
                session.delete(service)
                return True
            return False

    def get_all_for_health_check(self) -> list[Service]:
        with get_db() as session:
            return list(session.exec(select(Service)).all())

    def update(self, service_id: str, **updates) -> Service | None:
        with get_db() as session:
            service = session.get(Service, service_id)
            if not service:
                return None
            for key, value in updates.items():
                if hasattr(service, key):
                    setattr(service, key, value)
            session.add(service)
            session.commit()
            session.refresh(service)
            return service

    def search(self, query: str) -> list[Service]:
        q = query.lower()
        with get_db() as session:
            results = []
            for s in session.exec(select(Service)).all():
                if (
                    q in s.name.lower()
                    or q in s.description.lower()
                    or any(q in t.lower() for t in (s.tags or []))
                    or (s.source_repo and q in s.source_repo.lower())
                ):
                    results.append(s)
            return results

    def clear(self) -> None:
        with get_db() as session:
            for s in session.exec(select(Service)).all():
                session.delete(s)


class AgentStore:
    """Storage for launcher agents."""

    def register(self, agent: Agent) -> str:
        with get_db() as session:
            existing = session.exec(select(Agent).where(Agent.vm_name == agent.vm_name)).first()
            if existing:
                session.delete(existing)
                session.commit()
            session.add(agent)
        return agent.agent_id

    def get(self, agent_id: str) -> Agent | None:
        with get_db() as session:
            return session.get(Agent, agent_id)

    def get_by_vm_name(self, vm_name: str) -> Agent | None:
        with get_db() as session:
            return session.exec(select(Agent).where(Agent.vm_name == vm_name)).first()

    def heartbeat(self, agent_id: str) -> bool:
        with get_db() as session:
            agent = session.get(Agent, agent_id)
            if not agent:
                return False
            agent.last_heartbeat = datetime.now(timezone.utc)
            session.add(agent)
            return True

    def update_status(
        self, agent_id: str, status: str, deployment_id: str | None = None, error: str | None = None
    ) -> bool:
        with get_db() as session:
            agent = session.get(Agent, agent_id)
            if not agent:
                return False
            agent.status = status
            if deployment_id is not None:
                agent.current_deployment_id = deployment_id
            agent.last_heartbeat = datetime.now(timezone.utc)
            session.add(agent)
            return True

    def list(self, filters: dict | None = None) -> list[Agent]:
        with get_db() as session:
            agents = list(session.exec(select(Agent)).all())
        if filters:
            if filters.get("status"):
                agents = [a for a in agents if a.status == filters["status"]]
            if filters.get("vm_name"):
                agents = [a for a in agents if filters["vm_name"].lower() in a.vm_name.lower()]
        return agents

    def delete(self, agent_id: str) -> bool:
        with get_db() as session:
            agent = session.get(Agent, agent_id)
            if agent:
                session.delete(agent)
                return True
            return False

    def get_available(self, require_verified: bool = True) -> Agent | None:
        agents = self.list({"status": "undeployed"})
        now = datetime.now(timezone.utc)
        for agent in agents:
            if now - _aware(agent.last_heartbeat) < AGENT_OFFLINE_TIMEOUT:
                if require_verified and not agent.verified:
                    continue
                return agent
        return None

    def update_health(
        self,
        agent_id: str,
        health_status: str,
        service_url: str | None = None,
        health_endpoint: str | None = None,
    ) -> bool:
        with get_db() as session:
            agent = session.get(Agent, agent_id)
            if not agent:
                return False
            if health_status == "unhealthy" and agent.health_status != "unhealthy":
                agent.unhealthy_since = datetime.now(timezone.utc)
            elif health_status != "unhealthy":
                agent.unhealthy_since = None
            agent.health_status = health_status
            agent.last_health_check = datetime.now(timezone.utc)
            if service_url is not None:
                agent.service_url = service_url
            if health_endpoint is not None:
                agent.health_endpoint = health_endpoint
            session.add(agent)
            return True

    def update_tunnel_info(
        self, agent_id: str, tunnel_id: str, hostname: str, tunnel_token: str | None = None
    ) -> bool:
        with get_db() as session:
            agent = session.get(Agent, agent_id)
            if not agent:
                return False
            agent.tunnel_id = tunnel_id
            agent.hostname = hostname
            if tunnel_token:
                agent.tunnel_token = tunnel_token
            agent.tunnel_error = None
            session.add(agent)
            return True

    def get_unhealthy_agents(self, unhealthy_timeout: timedelta) -> list[Agent]:
        with get_db() as session:
            agents = session.exec(
                select(Agent).where(Agent.status == "deployed", Agent.unhealthy_since.isnot(None))
            ).all()
            now = datetime.now(timezone.utc)
            return [
                a
                for a in agents
                if a.unhealthy_since and now - _aware(a.unhealthy_since) > unhealthy_timeout
            ]

    def get_stale_agents(self, stale_timeout: timedelta) -> list[Agent]:
        """Get agents whose last heartbeat is older than stale_timeout."""
        with get_db() as session:
            cutoff = datetime.now(timezone.utc) - stale_timeout
            return list(session.exec(select(Agent).where(Agent.last_heartbeat < cutoff)).all())

    def reset_for_reassignment(self, agent_id: str) -> bool:
        with get_db() as session:
            agent = session.get(Agent, agent_id)
            if not agent:
                return False
            agent.status = "undeployed"
            agent.current_deployment_id = None
            agent.deployed_app = None
            agent.service_url = None
            agent.health_status = "unknown"
            agent.last_health_check = None
            agent.unhealthy_since = None
            session.add(agent)
            return True

    def update_attestation_status(
        self,
        agent_id: str,
        attestation_valid: bool,
        error: str | None = None,
        intel_ta_token: str | None = None,
    ) -> bool:
        with get_db() as session:
            agent = session.get(Agent, agent_id)
            if not agent:
                return False
            agent.last_attestation_check = datetime.now(timezone.utc)
            agent.attestation_valid = attestation_valid
            agent.attestation_error = error
            if intel_ta_token is not None:
                agent.intel_ta_token = intel_ta_token
            session.add(agent)
            return True

    def update_rtmrs(self, agent_id: str, rtmrs: dict[str, str]) -> bool:
        """Update stored RTMRs for an agent (backfill or refresh)."""
        with get_db() as session:
            agent = session.get(Agent, agent_id)
            if not agent:
                return False
            agent.rtmrs = rtmrs
            session.add(agent)
            return True

    def update_attestation(
        self, agent_id: str, intel_ta_token: str, verified: bool, error: str | None = None
    ) -> bool:
        with get_db() as session:
            agent = session.get(Agent, agent_id)
            if not agent:
                return False
            agent.intel_ta_token = intel_ta_token
            agent.verified = verified
            agent.last_attestation_check = datetime.now(timezone.utc)
            agent.attestation_valid = verified
            agent.attestation_error = error
            session.add(agent)
            return True

    def update_attestation_blob(self, agent_id: str, attestation: dict) -> bool:
        """Store latest attestation JSON blob for debugging/attestation chain."""
        with get_db() as session:
            agent = session.get(Agent, agent_id)
            if not agent:
                return False
            agent.attestation = attestation
            agent.last_heartbeat = datetime.now(timezone.utc)
            session.add(agent)
            return True

    def clear_tunnel_info(self, agent_id: str) -> bool:
        """Clear tunnel fields after external tunnel deletion."""
        with get_db() as session:
            agent = session.get(Agent, agent_id)
            if not agent:
                return False
            agent.tunnel_id = None
            agent.hostname = None
            agent.tunnel_token = None
            session.add(agent)
            return True

    def list_by_owners(self, owners: list[str]) -> list[Agent]:
        """List agents whose github_owner is in the given list."""
        if not owners:
            return []
        with get_db() as session:
            return list(session.exec(select(Agent).where(Agent.github_owner.in_(owners))).all())

    def set_deployed_app(self, agent_id: str, deployed_app: str | None) -> bool:
        """Set or clear the deployed_app field on an agent."""
        with get_db() as session:
            agent = session.get(Agent, agent_id)
            if not agent:
                return False
            agent.deployed_app = deployed_app
            session.add(agent)
            return True

    def set_github_owner(self, agent_id: str, github_owner: str | None) -> bool:
        """Set or clear the github_owner field on an agent."""
        with get_db() as session:
            agent = session.get(Agent, agent_id)
            if not agent:
                return False
            agent.github_owner = github_owner
            session.add(agent)
            return True

    def update_tcb_status(self, agent_id: str, tcb_status: str) -> bool:
        """Update TCB status during attestation refresh."""
        with get_db() as session:
            agent = session.get(Agent, agent_id)
            if not agent:
                return False
            agent.tcb_status = tcb_status
            agent.tcb_verified_at = datetime.now(timezone.utc)
            session.add(agent)
            return True

    def clear(self) -> None:
        with get_db() as session:
            for a in session.exec(select(Agent)).all():
                session.delete(a)


class CapacityPoolTargetStore:
    """Storage for desired warm-capacity targets per datacenter/node-size."""

    def list(self, enabled_only: bool = False) -> list[CapacityPoolTarget]:
        with get_db() as session:
            stmt = select(CapacityPoolTarget)
            if enabled_only:
                stmt = stmt.where(CapacityPoolTarget.enabled)
            return list(
                session.exec(
                    stmt.order_by(CapacityPoolTarget.datacenter, CapacityPoolTarget.node_size)
                ).all()
            )

    def has_enabled_targets(self) -> bool:
        with get_db() as session:
            row = session.exec(
                select(CapacityPoolTarget.target_id).where(CapacityPoolTarget.enabled).limit(1)
            ).first()
        return row is not None

    def upsert(
        self,
        *,
        datacenter: str,
        node_size: str,
        min_warm_count: int,
        enabled: bool = True,
        require_verified: bool = True,
        require_healthy: bool = True,
        require_hostname: bool = True,
        dispatch: bool = False,
        reason: str = "capacity-pool-controller",
    ) -> CapacityPoolTarget:
        normalized_datacenter = _normalize_pool_value(datacenter)
        normalized_node_size = _normalize_pool_value(node_size)
        if not normalized_datacenter:
            raise ValueError("datacenter is required")
        if min_warm_count < 0:
            raise ValueError("min_warm_count must be >= 0")
        now = datetime.now(timezone.utc)
        with get_db() as session:
            existing = session.exec(
                select(CapacityPoolTarget).where(
                    CapacityPoolTarget.datacenter == normalized_datacenter,
                    CapacityPoolTarget.node_size == normalized_node_size,
                )
            ).first()
            if existing:
                existing.min_warm_count = min_warm_count
                existing.enabled = enabled
                existing.require_verified = require_verified
                existing.require_healthy = require_healthy
                existing.require_hostname = require_hostname
                existing.dispatch = dispatch
                existing.reason = reason.strip() or "capacity-pool-controller"
                existing.updated_at = now
                session.add(existing)
                return existing
            obj = CapacityPoolTarget(
                datacenter=normalized_datacenter,
                node_size=normalized_node_size,
                min_warm_count=min_warm_count,
                enabled=enabled,
                require_verified=require_verified,
                require_healthy=require_healthy,
                require_hostname=require_hostname,
                dispatch=dispatch,
                reason=reason.strip() or "capacity-pool-controller",
                created_at=now,
                updated_at=now,
            )
            session.add(obj)
            return obj

    def delete_pool(self, datacenter: str, node_size: str = "") -> bool:
        normalized_datacenter = _normalize_pool_value(datacenter)
        normalized_node_size = _normalize_pool_value(node_size)
        with get_db() as session:
            obj = session.exec(
                select(CapacityPoolTarget).where(
                    CapacityPoolTarget.datacenter == normalized_datacenter,
                    CapacityPoolTarget.node_size == normalized_node_size,
                )
            ).first()
            if not obj:
                return False
            session.delete(obj)
            return True

    def clear(self) -> None:
        with get_db() as session:
            for row in session.exec(select(CapacityPoolTarget)).all():
                session.delete(row)


class CapacityReservationStore:
    """Storage for warm-capacity reservations."""

    def list(self, status: str | None = None) -> list[CapacityReservation]:
        normalized_status = _normalize_pool_value(status)
        with get_db() as session:
            stmt = select(CapacityReservation)
            if normalized_status:
                stmt = stmt.where(CapacityReservation.status == normalized_status)
            return list(
                session.exec(
                    stmt.order_by(
                        CapacityReservation.created_at, CapacityReservation.reservation_id
                    )
                ).all()
            )

    def list_open_by_pool(self, datacenter: str, node_size: str = "") -> list[CapacityReservation]:
        normalized_datacenter = _normalize_pool_value(datacenter)
        normalized_node_size = _normalize_pool_value(node_size)
        with get_db() as session:
            return list(
                session.exec(
                    select(CapacityReservation)
                    .where(
                        CapacityReservation.status == "open",
                        CapacityReservation.datacenter == normalized_datacenter,
                        CapacityReservation.node_size == normalized_node_size,
                    )
                    .order_by(CapacityReservation.created_at, CapacityReservation.reservation_id)
                ).all()
            )

    def list_open_by_agent_ids(self, agent_ids: list[str]) -> dict[str, CapacityReservation]:
        if not agent_ids:
            return {}
        with get_db() as session:
            rows = list(
                session.exec(
                    select(CapacityReservation)
                    .where(
                        CapacityReservation.status == "open",
                        CapacityReservation.agent_id.in_(agent_ids),
                    )
                    .order_by(CapacityReservation.created_at, CapacityReservation.reservation_id)
                ).all()
            )
        by_agent: dict[str, CapacityReservation] = {}
        for row in rows:
            if row.agent_id not in by_agent:
                by_agent[row.agent_id] = row
        return by_agent

    def has_open_for_agent(self, agent_id: str) -> bool:
        with get_db() as session:
            row = session.exec(
                select(CapacityReservation.reservation_id)
                .where(
                    CapacityReservation.status == "open",
                    CapacityReservation.agent_id == agent_id,
                )
                .limit(1)
            ).first()
        return row is not None

    def create_open(
        self,
        *,
        agent_id: str,
        datacenter: str,
        node_size: str = "",
        note: str = "",
    ) -> CapacityReservation:
        normalized_datacenter = _normalize_pool_value(datacenter)
        normalized_node_size = _normalize_pool_value(node_size)
        now = datetime.now(timezone.utc)
        with get_db() as session:
            existing = session.exec(
                select(CapacityReservation).where(
                    CapacityReservation.status == "open",
                    CapacityReservation.agent_id == agent_id,
                )
            ).first()
            if existing:
                existing.datacenter = normalized_datacenter
                existing.node_size = normalized_node_size
                existing.note = note
                existing.updated_at = now
                session.add(existing)
                return existing

            obj = CapacityReservation(
                agent_id=agent_id,
                datacenter=normalized_datacenter,
                node_size=normalized_node_size,
                status="open",
                deployment_id=None,
                note=note,
                created_at=now,
                updated_at=now,
            )
            session.add(obj)
            return obj

    def consume(self, reservation_id: str, deployment_id: str) -> bool:
        now = datetime.now(timezone.utc)
        with get_db() as session:
            row = session.get(CapacityReservation, reservation_id)
            if not row or row.status != "open":
                return False
            row.status = "consumed"
            row.deployment_id = deployment_id
            row.updated_at = now
            session.add(row)
            return True

    def expire_open_for_pool_except(
        self, *, datacenter: str, node_size: str = "", keep_agent_ids: set[str]
    ) -> int:
        normalized_datacenter = _normalize_pool_value(datacenter)
        normalized_node_size = _normalize_pool_value(node_size)
        now = datetime.now(timezone.utc)
        expired = 0
        with get_db() as session:
            rows = list(
                session.exec(
                    select(CapacityReservation).where(
                        CapacityReservation.status == "open",
                        CapacityReservation.datacenter == normalized_datacenter,
                        CapacityReservation.node_size == normalized_node_size,
                    )
                ).all()
            )
            for row in rows:
                if row.agent_id in keep_agent_ids:
                    continue
                row.status = "expired"
                row.updated_at = now
                session.add(row)
                expired += 1
        return expired

    def expire_open_for_agent(self, agent_id: str) -> int:
        now = datetime.now(timezone.utc)
        expired = 0
        with get_db() as session:
            rows = list(
                session.exec(
                    select(CapacityReservation).where(
                        CapacityReservation.status == "open",
                        CapacityReservation.agent_id == agent_id,
                    )
                ).all()
            )
            for row in rows:
                row.status = "expired"
                row.updated_at = now
                session.add(row)
                expired += 1
        return expired

    def clear(self) -> None:
        with get_db() as session:
            for row in session.exec(select(CapacityReservation)).all():
                session.delete(row)


class DeploymentStore:
    """Storage for deployments."""

    def create(self, deployment: Deployment) -> str:
        with get_db() as session:
            session.add(deployment)
        return deployment.deployment_id

    def get(self, deployment_id: str) -> Deployment | None:
        with get_db() as session:
            return session.get(Deployment, deployment_id)

    def update_status(self, deployment_id: str, status: str, error: str | None = None) -> bool:
        with get_db() as session:
            d = session.get(Deployment, deployment_id)
            if not d:
                return False
            d.status = status
            if error:
                d.error = error
            session.add(d)
            return True

    def update(self, deployment_id: str, updates: dict) -> bool:
        """Update arbitrary fields on a deployment."""
        with get_db() as session:
            d = session.get(Deployment, deployment_id)
            if not d:
                return False
            for key, value in updates.items():
                if hasattr(d, key):
                    setattr(d, key, value)
            session.add(d)
            return True

    def complete(
        self,
        deployment_id: str,
        status: str,
        service_id: str | None = None,
        attestation: dict | None = None,
        error: str | None = None,
    ) -> bool:
        with get_db() as session:
            d = session.get(Deployment, deployment_id)
            if not d:
                return False
            d.status = status
            d.completed_at = datetime.now(timezone.utc)
            if service_id:
                d.service_id = service_id
            if attestation:
                d.attestation = attestation
            if error:
                d.error = error
            session.add(d)
            return True

    def list(self, filters: dict | None = None) -> list[Deployment]:
        with get_db() as session:
            deployments = list(session.exec(select(Deployment)).all())
        if filters:
            if filters.get("status"):
                deployments = [d for d in deployments if d.status == filters["status"]]
            if filters.get("agent_id"):
                deployments = [d for d in deployments if d.agent_id == filters["agent_id"]]
        return deployments

    def reassign(self, deployment_id: str, new_agent_id: str) -> bool:
        with get_db() as session:
            d = session.get(Deployment, deployment_id)
            if not d:
                return False
            d.agent_id = new_agent_id
            d.status = "pending"
            d.started_at = None
            d.completed_at = None
            d.error = None
            session.add(d)
            return True

    def mark_for_reassignment(self, deployment_id: str) -> bool:
        with get_db() as session:
            d = session.get(Deployment, deployment_id)
            if not d:
                return False
            d.status = "reassigning"
            d.error = "Agent unhealthy - pending reassignment"
            session.add(d)
            return True

    def get_for_reassignment(self) -> list[Deployment]:
        with get_db() as session:
            return list(
                session.exec(select(Deployment).where(Deployment.status == "reassigning")).all()
            )

    def clear(self) -> None:
        with get_db() as session:
            for d in session.exec(select(Deployment)).all():
                session.delete(d)


# ==============================================================================
# Trusted MRTD lookup (env vars + DB)
# ==============================================================================

_trusted_mrtds: dict[str, str] = {}  # mrtd_hash -> type ("agent" or "proxy")
_MRTD_RE = re.compile(r"^[0-9a-f]{96}$")


def _normalize_mrtd(value: str) -> str:
    return (value or "").strip().lower()


def _validate_mrtd(mrtd: str) -> None:
    if not mrtd:
        raise ValueError("mrtd is required")
    if not _MRTD_RE.fullmatch(mrtd):
        raise ValueError("mrtd must be a 96-character hex string")


def load_trusted_mrtds():
    """Load trusted MRTDs from environment variables and DB.

    Env vars remain supported for bootstrapping, but DB entries allow adding
    new baselines without restarting the control plane.
    """
    global _trusted_mrtds
    _trusted_mrtds = {}
    for env_var, mrtd_type in [
        ("TRUSTED_AGENT_MRTDS", "agent"),
        ("TRUSTED_PROXY_MRTDS", "proxy"),
        # Backward compat with old single-value env vars
        ("SYSTEM_AGENT_MRTD", "agent"),
        ("SYSTEM_PROXY_MRTD", "proxy"),
    ]:
        val = os.environ.get(env_var, "")
        for mrtd in val.split(","):
            mrtd = _normalize_mrtd(mrtd)
            if mrtd:
                _trusted_mrtds[mrtd] = mrtd_type

    # DB-backed entries (override/augment env var list).
    try:
        with get_db() as session:
            rows = list(session.exec(select(TrustedMrtd)).all())
        for row in rows:
            mrtd = _normalize_mrtd(row.mrtd or "")
            mrtd_type = (row.mrtd_type or "").strip() or "agent"
            if mrtd:
                _trusted_mrtds[mrtd] = mrtd_type
    except Exception as e:
        logger.warning(f"Failed to load trusted MRTDs from DB: {e}")
    if _trusted_mrtds:
        for mrtd_hash, mrtd_type in _trusted_mrtds.items():
            logger.info(f"Loaded trusted {mrtd_type} MRTD: {mrtd_hash[:16]}...")


def get_trusted_mrtd(mrtd: str) -> str | None:
    """Return type if trusted, None if not."""
    return _trusted_mrtds.get(_normalize_mrtd(mrtd))


def list_trusted_mrtds() -> dict[str, str]:
    """Return all trusted MRTDs as {mrtd_hash: type}."""
    return dict(_trusted_mrtds)


class TrustedMrtdStore:
    """DB-backed trusted MRTD baselines."""

    def list(self) -> list[TrustedMrtd]:
        with get_db() as session:
            return list(session.exec(select(TrustedMrtd).order_by(TrustedMrtd.added_at)).all())

    def upsert(self, mrtd: str, mrtd_type: str = "agent", note: str = "") -> TrustedMrtd:
        mrtd = _normalize_mrtd(mrtd)
        _validate_mrtd(mrtd)
        mrtd_type = (mrtd_type or "agent").strip().lower()
        if mrtd_type not in {"agent", "proxy"}:
            raise ValueError("mrtd_type must be 'agent' or 'proxy'")
        with get_db() as session:
            existing = session.get(TrustedMrtd, mrtd)
            if existing:
                existing.mrtd_type = mrtd_type
                if note:
                    existing.note = note
                session.add(existing)
                obj = existing
            else:
                obj = TrustedMrtd(mrtd=mrtd, mrtd_type=mrtd_type, note=note)
                session.add(obj)
        # Refresh in-memory cache for fast-path checks.
        load_trusted_mrtds()
        return obj

    def delete(self, mrtd: str) -> bool:
        mrtd = _normalize_mrtd(mrtd)
        if not mrtd:
            return False
        with get_db() as session:
            obj = session.get(TrustedMrtd, mrtd)
            if not obj:
                return False
            session.delete(obj)
        load_trusted_mrtds()
        return True

    def clear(self) -> None:
        with get_db() as session:
            for row in session.exec(select(TrustedMrtd)).all():
                session.delete(row)
        load_trusted_mrtds()


# ==============================================================================
# Trusted RTMR lookup (env-var-only, no DB)
# ==============================================================================

_trusted_rtmrs: dict[str, dict[str, str]] = {}  # type ("agent"/"proxy") -> {rtmr0: ..., rtmr3: ...}
_trusted_rtmrs_by_size: dict[str, dict[str, dict[str, str]]] = {}
_RTMR_KEYS = tuple(f"rtmr{i}" for i in range(4))


def _is_valid_rtmr_profile(value: object) -> bool:
    return isinstance(value, dict) and all(k in value for k in _RTMR_KEYS)


def load_trusted_rtmrs():
    """Load trusted RTMRs from environment variables.

    Expected format: JSON object with rtmr0-3 keys, e.g.
    TRUSTED_AGENT_RTMRS='{"rtmr0":"abc...","rtmr1":"def...","rtmr2":"ghi...","rtmr3":"jkl..."}'
    """
    global _trusted_rtmrs, _trusted_rtmrs_by_size
    _trusted_rtmrs = {}
    _trusted_rtmrs_by_size = {}
    import json

    for env_var, mrtd_type in [
        ("TRUSTED_AGENT_RTMRS", "agent"),
        ("TRUSTED_PROXY_RTMRS", "proxy"),
    ]:
        val = os.environ.get(env_var, "").strip()
        if not val:
            continue
        try:
            rtmrs = json.loads(val)
            if _is_valid_rtmr_profile(rtmrs):
                _trusted_rtmrs[mrtd_type] = rtmrs
                logger.info(
                    f"Loaded trusted {mrtd_type} RTMRs: "
                    f"RTMR0={rtmrs['rtmr0'][:16]}... "
                    f"RTMR1={rtmrs['rtmr1'][:16]}... "
                    f"RTMR2={rtmrs['rtmr2'][:16]}... "
                    f"RTMR3={rtmrs['rtmr3'][:16]}..."
                )
            else:
                logger.warning(f"Invalid {env_var}: must be JSON with rtmr0-rtmr3 keys")
        except Exception as e:
            logger.warning(f"Could not parse {env_var}: {e}")

    for env_var, mrtd_type in [
        ("TRUSTED_AGENT_RTMRS_BY_SIZE", "agent"),
        ("TRUSTED_PROXY_RTMRS_BY_SIZE", "proxy"),
    ]:
        val = os.environ.get(env_var, "").strip()
        if not val:
            continue
        try:
            parsed = json.loads(val)
            if not isinstance(parsed, dict):
                logger.warning(
                    f"Invalid {env_var}: expected JSON object mapping node_size -> RTMR profile"
                )
                continue

            loaded: dict[str, dict[str, str]] = {}
            for node_size, profile in parsed.items():
                if not isinstance(node_size, str) or not node_size:
                    logger.warning(f"Invalid {env_var} entry key: {node_size!r}")
                    continue
                if not _is_valid_rtmr_profile(profile):
                    logger.warning(
                        f"Invalid {env_var} entry for '{node_size}': must include rtmr0-rtmr3"
                    )
                    continue
                loaded[node_size] = profile
                logger.info(
                    f"Loaded trusted {mrtd_type} RTMRs for node_size='{node_size}': "
                    f"RTMR0={profile['rtmr0'][:16]}... "
                    f"RTMR1={profile['rtmr1'][:16]}... "
                    f"RTMR2={profile['rtmr2'][:16]}... "
                    f"RTMR3={profile['rtmr3'][:16]}..."
                )

            if loaded:
                _trusted_rtmrs_by_size[mrtd_type] = loaded
        except Exception as e:
            logger.warning(f"Could not parse {env_var}: {e}")


def get_trusted_rtmrs(mrtd_type: str, node_size: str = "") -> dict[str, str] | None:
    """Return trusted RTMRs for type/node_size, falling back to type-only baseline."""
    if node_size:
        by_size = _trusted_rtmrs_by_size.get(mrtd_type, {})
        if node_size in by_size:
            return by_size[node_size]
    return _trusted_rtmrs.get(mrtd_type)


class AppStore:
    """Storage for apps."""

    def register(self, app: App) -> str:
        with get_db() as session:
            session.add(app)
        return app.app_id

    def get_by_name(self, name: str) -> App | None:
        with get_db() as session:
            return session.exec(select(App).where(App.name == name)).first()

    def list(self, filters: dict | None = None) -> list[App]:
        with get_db() as session:
            apps = list(session.exec(select(App)).all())
        if filters:
            if filters.get("name"):
                apps = [a for a in apps if filters["name"].lower() in a.name.lower()]
            if filters.get("tags"):
                filter_tags = set(filters["tags"])
                apps = [a for a in apps if filter_tags & set(a.tags or [])]
        return apps

    def delete(self, app_id: str) -> bool:
        with get_db() as session:
            app = session.get(App, app_id)
            if app:
                session.delete(app)
                return True
            return False

    def clear(self) -> None:
        with get_db() as session:
            for a in session.exec(select(App)).all():
                session.delete(a)


class AppVersionStore:
    """Storage for app versions."""

    def create(self, version: AppVersion) -> str:
        with get_db() as session:
            session.add(version)
        return version.version_id

    def get(self, version_id: str) -> AppVersion | None:
        with get_db() as session:
            return session.get(AppVersion, version_id)

    def get_by_version(self, app_name: str, version: str, node_size: str = "") -> AppVersion | None:
        with get_db() as session:
            return session.exec(
                select(AppVersion).where(
                    AppVersion.app_name == app_name,
                    AppVersion.version == version,
                    AppVersion.node_size == node_size,
                )
            ).first()

    def list_for_app(self, app_name: str) -> list[AppVersion]:
        with get_db() as session:
            return list(
                session.exec(
                    select(AppVersion)
                    .where(AppVersion.app_name == app_name)
                    .order_by(AppVersion.published_at.desc())
                ).all()
            )

    def update_status(
        self,
        version_id: str,
        status: str,
        mrtd: str | None = None,
        attestation: dict | None = None,
        rejection_reason: str | None = None,
    ) -> bool:
        with get_db() as session:
            v = session.get(AppVersion, version_id)
            if not v:
                return False
            v.status = status
            if mrtd is not None:
                v.mrtd = mrtd
            if attestation is not None:
                v.attestation = attestation
            if rejection_reason is not None:
                v.rejection_reason = rejection_reason
            session.add(v)
            return True

    def list_by_status(self, status: str) -> list[AppVersion]:
        with get_db() as session:
            return list(
                session.exec(
                    select(AppVersion)
                    .where(AppVersion.status == status)
                    .order_by(AppVersion.published_at)
                ).all()
            )

    def clear(self) -> None:
        with get_db() as session:
            for v in session.exec(select(AppVersion)).all():
                session.delete(v)


class AccountStore:
    """Storage for billing accounts."""

    def create(self, account: Account) -> str:
        with get_db() as session:
            session.add(account)
        return account.account_id

    def get(self, account_id: str) -> Account | None:
        with get_db() as session:
            return session.get(Account, account_id)

    def get_by_name(self, name: str) -> Account | None:
        with get_db() as session:
            return session.exec(select(Account).where(Account.name == name)).first()

    def list(self, filters: dict | None = None) -> list[Account]:
        with get_db() as session:
            accounts = list(session.exec(select(Account)).all())
        if filters:
            if filters.get("name"):
                accounts = [a for a in accounts if filters["name"].lower() in a.name.lower()]
            if filters.get("account_type"):
                accounts = [a for a in accounts if a.account_type == filters["account_type"]]
        return accounts

    def delete(self, account_id: str) -> bool:
        with get_db() as session:
            account = session.get(Account, account_id)
            if account:
                session.delete(account)
                return True
            return False

    def update_identity(
        self,
        account_id: str,
        github_login: str | None = None,
        github_org: str | None = None,
        linked_at: datetime | None = None,
    ) -> Account | None:
        with get_db() as session:
            account = session.get(Account, account_id)
            if not account:
                return None
            account.github_login = github_login
            account.github_org = github_org
            account.linked_at = linked_at or datetime.now(timezone.utc)
            session.add(account)
            session.commit()
            session.refresh(account)
            return account

    def update_api_credentials(
        self,
        account_id: str,
        api_key_hash: str,
        api_key_prefix: str,
    ) -> Account | None:
        with get_db() as session:
            account = session.get(Account, account_id)
            if not account:
                return None
            account.api_key_hash = api_key_hash
            account.api_key_prefix = api_key_prefix
            session.add(account)
            session.commit()
            session.refresh(account)
            return account

    def get_balance(self, account_id: str) -> float:
        """Get current balance from the most recent transaction."""
        with get_db() as session:
            latest = session.exec(
                select(Transaction)
                .where(Transaction.account_id == account_id)
                .order_by(Transaction.created_at.desc())
            ).first()
            return latest.balance_after if latest else 0.0

    def get_by_api_key_prefix(self, prefix: str) -> Account | None:
        """Fast lookup of account by API key prefix."""
        with get_db() as session:
            return session.exec(select(Account).where(Account.api_key_prefix == prefix)).first()

    def get_by_github_login(self, github_login: str) -> Account | None:
        """Look up account by linked GitHub login."""
        with get_db() as session:
            return session.exec(select(Account).where(Account.github_login == github_login)).first()

    def clear(self) -> None:
        with get_db() as session:
            for a in session.exec(select(Account)).all():
                session.delete(a)


class TransactionStore:
    """Storage for billing transactions (append-only ledger)."""

    def create(self, transaction: Transaction) -> str:
        with get_db() as session:
            session.add(transaction)
        return transaction.transaction_id

    def list_for_account(
        self, account_id: str, limit: int = 50, offset: int = 0
    ) -> list[Transaction]:
        with get_db() as session:
            return list(
                session.exec(
                    select(Transaction)
                    .where(Transaction.account_id == account_id)
                    .order_by(Transaction.created_at.desc())
                    .offset(offset)
                    .limit(limit)
                ).all()
            )

    def count_for_account(self, account_id: str) -> int:
        with get_db() as session:
            return len(
                list(
                    session.exec(
                        select(Transaction).where(Transaction.account_id == account_id)
                    ).all()
                )
            )

    def clear(self) -> None:
        with get_db() as session:
            for t in session.exec(select(Transaction)).all():
                session.delete(t)


class AppRevenueShareStore:
    """Storage for app contributor revenue share rules."""

    def create(self, share: AppRevenueShare) -> str:
        with get_db() as session:
            session.add(share)
        return share.share_id

    def get(self, share_id: str) -> AppRevenueShare | None:
        with get_db() as session:
            return session.get(AppRevenueShare, share_id)

    def list_for_app(self, app_name: str) -> list[AppRevenueShare]:
        with get_db() as session:
            return list(
                session.exec(
                    select(AppRevenueShare)
                    .where(AppRevenueShare.app_name == app_name)
                    .order_by(AppRevenueShare.created_at.asc())
                ).all()
            )

    def total_bps_for_app(self, app_name: str) -> int:
        return sum(share.share_bps for share in self.list_for_app(app_name))

    def delete(self, share_id: str) -> bool:
        with get_db() as session:
            share = session.get(AppRevenueShare, share_id)
            if not share:
                return False
            session.delete(share)
            return True

    def clear_for_app(self, app_name: str) -> None:
        with get_db() as session:
            shares = session.exec(
                select(AppRevenueShare).where(AppRevenueShare.app_name == app_name)
            )
            for share in shares:
                session.delete(share)

    def clear(self) -> None:
        with get_db() as session:
            for share in session.exec(select(AppRevenueShare)).all():
                session.delete(share)


class AdminSessionStore:
    """Storage for admin authentication sessions."""

    def create(self, session_obj: AdminSession) -> str:
        with get_db() as session:
            session.add(session_obj)
        return session_obj.session_id

    def get(self, session_id: str) -> AdminSession | None:
        with get_db() as session:
            return session.get(AdminSession, session_id)

    def get_by_prefix(self, prefix: str) -> AdminSession | None:
        """Fast lookup of session by token prefix."""
        with get_db() as session:
            return session.exec(
                select(AdminSession).where(AdminSession.token_prefix == prefix)
            ).first()

    def delete(self, session_id: str) -> bool:
        with get_db() as session:
            session_obj = session.get(AdminSession, session_id)
            if session_obj:
                session.delete(session_obj)
                return True
            return False

    def delete_expired(self) -> int:
        """Delete all expired sessions. Returns count of deleted sessions."""
        with get_db() as session:
            now = datetime.now(timezone.utc)
            expired = session.exec(select(AdminSession).where(AdminSession.expires_at < now)).all()
            count = 0
            for s in expired:
                session.delete(s)
                count += 1
            return count

    def touch(self, session_id: str) -> None:
        """Update last_used timestamp."""
        with get_db() as session:
            session_obj = session.get(AdminSession, session_id)
            if session_obj:
                session_obj.last_used = datetime.now(timezone.utc)
                session.add(session_obj)

    def clear(self) -> None:
        with get_db() as session:
            for s in session.exec(select(AdminSession)).all():
                session.delete(s)


# Global store instances
store = ServiceStore()
agent_store = AgentStore()
capacity_pool_target_store = CapacityPoolTargetStore()
capacity_reservation_store = CapacityReservationStore()
deployment_store = DeploymentStore()
app_store = AppStore()
app_version_store = AppVersionStore()
account_store = AccountStore()
transaction_store = TransactionStore()
app_revenue_share_store = AppRevenueShareStore()
admin_session_store = AdminSessionStore()
trusted_mrtd_store = TrustedMrtdStore()

# Load trusted MRTDs and RTMRs from env vars at import time
load_trusted_mrtds()
load_trusted_rtmrs()
