"""SQLModel-backed storage for EasyEnclave."""

from __future__ import annotations

import logging
import os
from datetime import datetime, timedelta

from sqlmodel import func, select

from .database import get_db, init_db
from .db_models import (
    Agent,
    App,
    AppVersion,
    Deployment,
    MrtdType,
    Service,
    TrustedMrtd,
)

logger = logging.getLogger(__name__)

UNHEALTHY_TIMEOUT = timedelta(hours=1)
AGENT_OFFLINE_TIMEOUT = timedelta(minutes=5)


class ServiceStore:
    """Storage for service registrations."""

    def register(self, service: Service) -> str:
        with get_db() as session:
            session.add(service)
        return service.service_id

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
        return datetime.utcnow() - service.last_health_check > UNHEALTHY_TIMEOUT

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

    def count(self) -> int:
        with get_db() as session:
            return session.exec(select(func.count()).select_from(Service)).one()

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
            agent.last_heartbeat = datetime.utcnow()
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
            agent.last_heartbeat = datetime.utcnow()
            session.add(agent)
            return True

    def set_deployment(self, agent_id: str, deployment_id: str | None) -> bool:
        with get_db() as session:
            agent = session.get(Agent, agent_id)
            if not agent:
                return False
            agent.current_deployment_id = deployment_id
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
        now = datetime.utcnow()
        for agent in agents:
            if now - agent.last_heartbeat < AGENT_OFFLINE_TIMEOUT:
                if require_verified and not agent.verified:
                    continue
                return agent
        return None

    def set_verified(self, agent_id: str, verified: bool, error: str | None = None) -> bool:
        with get_db() as session:
            agent = session.get(Agent, agent_id)
            if not agent:
                return False
            agent.verified = verified
            agent.verification_error = error
            session.add(agent)
            return True

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
                agent.unhealthy_since = datetime.utcnow()
            elif health_status != "unhealthy":
                agent.unhealthy_since = None
            agent.health_status = health_status
            agent.last_health_check = datetime.utcnow()
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

    def update_tunnel_error(self, agent_id: str, error: str) -> bool:
        with get_db() as session:
            agent = session.get(Agent, agent_id)
            if not agent:
                return False
            agent.tunnel_error = error
            session.add(agent)
            return True

    def get_unhealthy_agents(self, unhealthy_timeout: timedelta) -> list[Agent]:
        with get_db() as session:
            agents = session.exec(
                select(Agent).where(Agent.status == "deployed", Agent.unhealthy_since.isnot(None))
            ).all()
            now = datetime.utcnow()
            return [
                a
                for a in agents
                if a.unhealthy_since and now - a.unhealthy_since > unhealthy_timeout
            ]

    def reset_for_reassignment(self, agent_id: str) -> bool:
        with get_db() as session:
            agent = session.get(Agent, agent_id)
            if not agent:
                return False
            agent.status = "undeployed"
            agent.current_deployment_id = None
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
            agent.last_attestation_check = datetime.utcnow()
            agent.attestation_valid = attestation_valid
            agent.attestation_error = error
            if intel_ta_token is not None:
                agent.intel_ta_token = intel_ta_token
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
            agent.last_attestation_check = datetime.utcnow()
            agent.attestation_valid = verified
            agent.attestation_error = error
            session.add(agent)
            return True

    def update_stats(self, agent_id: str, stats: dict) -> bool:
        with get_db() as session:
            agent = session.get(Agent, agent_id)
            if not agent:
                return False
            agent.stats = stats
            session.add(agent)
            return True

    def mark_attestation_failed(self, agent_id: str, error: str, clear_tunnel: bool = True) -> bool:
        with get_db() as session:
            agent = session.get(Agent, agent_id)
            if not agent:
                return False
            agent.status = "attestation_failed"
            agent.attestation_valid = False
            agent.attestation_error = error
            agent.last_attestation_check = datetime.utcnow()
            if clear_tunnel:
                agent.tunnel_id = None
                agent.hostname = None
            session.add(agent)
            return True

    def clear(self) -> None:
        with get_db() as session:
            for a in session.exec(select(Agent)).all():
                session.delete(a)


class DeploymentStore:
    """Storage for deployments."""

    def create(self, deployment: Deployment) -> str:
        with get_db() as session:
            session.add(deployment)
        return deployment.deployment_id

    def get(self, deployment_id: str) -> Deployment | None:
        with get_db() as session:
            return session.get(Deployment, deployment_id)

    def get_pending_for_agent(self, agent_id: str) -> Deployment | None:
        with get_db() as session:
            return session.exec(
                select(Deployment)
                .where(Deployment.agent_id == agent_id, Deployment.status == "pending")
                .order_by(Deployment.created_at.asc())
                .limit(1)
            ).first()

    def assign(self, deployment_id: str, agent_id: str) -> bool:
        with get_db() as session:
            d = session.get(Deployment, deployment_id)
            if not d:
                return False
            d.status = "assigned"
            d.agent_id = agent_id
            d.started_at = datetime.utcnow()
            session.add(d)
            return True

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
            d.completed_at = datetime.utcnow()
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

    def delete(self, deployment_id: str) -> bool:
        with get_db() as session:
            d = session.get(Deployment, deployment_id)
            if d:
                session.delete(d)
                return True
            return False

    def clear(self) -> None:
        with get_db() as session:
            for d in session.exec(select(Deployment)).all():
                session.delete(d)


class TrustedMrtdStore:
    """Storage for trusted MRTD measurements."""

    def __init__(self):
        self._load_system_mrtds()

    def _load_system_mrtds(self):
        try:
            init_db()
        except Exception:
            pass

        for env_var, mrtd_type, desc in [
            ("SYSTEM_AGENT_MRTD", MrtdType.AGENT, "System agent launcher image"),
            ("SYSTEM_PROXY_MRTD", MrtdType.PROXY, "System cloudflared proxy image"),
        ]:
            mrtd = os.environ.get(env_var)
            if mrtd:
                self._upsert_system_mrtd(
                    TrustedMrtd(mrtd=mrtd, type=mrtd_type.value, locked=True, description=desc)
                )
                logger.info(f"Loaded system {mrtd_type.value} MRTD: {mrtd[:16]}...")

    def _upsert_system_mrtd(self, trusted: TrustedMrtd) -> None:
        with get_db() as session:
            existing = session.get(TrustedMrtd, trusted.mrtd)
            if existing:
                existing.type = trusted.type
                existing.locked = trusted.locked
                existing.description = trusted.description
                existing.active = trusted.active
                session.add(existing)
            else:
                session.add(trusted)

    def add(self, trusted: TrustedMrtd) -> str:
        with get_db() as session:
            session.add(trusted)
        return trusted.mrtd

    def get(self, mrtd: str) -> TrustedMrtd | None:
        with get_db() as session:
            return session.get(TrustedMrtd, mrtd)

    def is_trusted(self, mrtd: str) -> bool:
        trusted = self.get(mrtd)
        return trusted is not None and trusted.active

    def list(self, include_inactive: bool = False) -> list[TrustedMrtd]:
        with get_db() as session:
            stmt = select(TrustedMrtd)
            if not include_inactive:
                stmt = stmt.where(TrustedMrtd.active == True)  # noqa: E712
            return list(session.exec(stmt).all())

    def deactivate(self, mrtd: str) -> tuple[bool, str | None]:
        trusted = self.get(mrtd)
        if not trusted:
            return False, None
        if trusted.locked:
            return False, "Cannot deactivate system MRTD"
        with get_db() as session:
            t = session.get(TrustedMrtd, mrtd)
            if t:
                t.active = False
                session.add(t)
        return True, None

    def activate(self, mrtd: str) -> bool:
        with get_db() as session:
            t = session.get(TrustedMrtd, mrtd)
            if not t:
                return False
            t.active = True
            session.add(t)
            return True

    def delete(self, mrtd: str) -> tuple[bool, str | None]:
        trusted = self.get(mrtd)
        if not trusted:
            return False, None
        if trusted.locked:
            return False, "Cannot delete system MRTD"
        with get_db() as session:
            t = session.get(TrustedMrtd, mrtd)
            if t:
                session.delete(t)
        return True, None

    def clear(self) -> None:
        with get_db() as session:
            for t in session.exec(select(TrustedMrtd)).all():
                session.delete(t)


class AppStore:
    """Storage for apps."""

    def register(self, app: App) -> str:
        with get_db() as session:
            session.add(app)
        return app.app_id

    def get(self, app_id: str) -> App | None:
        with get_db() as session:
            return session.get(App, app_id)

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

    def update(self, app_id: str, **updates) -> App | None:
        with get_db() as session:
            app = session.get(App, app_id)
            if not app:
                return None
            for key, value in updates.items():
                if hasattr(app, key):
                    setattr(app, key, value)
            session.add(app)
            session.commit()
            session.refresh(app)
            return app

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

    def get_by_version(self, app_name: str, version: str) -> AppVersion | None:
        with get_db() as session:
            return session.exec(
                select(AppVersion).where(
                    AppVersion.app_name == app_name, AppVersion.version == version
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

    def update(self, version_id: str, **updates) -> AppVersion | None:
        with get_db() as session:
            v = session.get(AppVersion, version_id)
            if not v:
                return None
            for key, value in updates.items():
                if hasattr(v, key):
                    setattr(v, key, value)
            session.add(v)
            session.commit()
            session.refresh(v)
            return v

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

    def delete(self, version_id: str) -> bool:
        with get_db() as session:
            v = session.get(AppVersion, version_id)
            if v:
                session.delete(v)
                return True
            return False

    def clear(self) -> None:
        with get_db() as session:
            for v in session.exec(select(AppVersion)).all():
                session.delete(v)


# Global store instances
store = ServiceStore()
agent_store = AgentStore()
deployment_store = DeploymentStore()
trusted_mrtd_store = TrustedMrtdStore()
app_store = AppStore()
app_version_store = AppVersionStore()
