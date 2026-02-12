"""SQLModel-backed storage for EasyEnclave."""

from __future__ import annotations

import logging
import os
from datetime import datetime, timedelta, timezone

from sqlmodel import select

from .database import get_db
from .db_models import (
    Account,
    AdminSession,
    Agent,
    App,
    AppVersion,
    Deployment,
    Service,
    Transaction,
)

logger = logging.getLogger(__name__)

UNHEALTHY_TIMEOUT = timedelta(hours=1)
AGENT_OFFLINE_TIMEOUT = timedelta(minutes=5)


def _aware(dt: datetime) -> datetime:
    """Ensure a datetime is timezone-aware (assume UTC if naive)."""
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


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
# Trusted MRTD lookup (env-var-only, no DB)
# ==============================================================================

_trusted_mrtds: dict[str, str] = {}  # mrtd_hash -> type ("agent" or "proxy")


def load_trusted_mrtds():
    """Load trusted MRTDs from environment variables."""
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
            mrtd = mrtd.strip()
            if mrtd:
                _trusted_mrtds[mrtd] = mrtd_type
    if _trusted_mrtds:
        for mrtd_hash, mrtd_type in _trusted_mrtds.items():
            logger.info(f"Loaded trusted {mrtd_type} MRTD: {mrtd_hash[:16]}...")


def get_trusted_mrtd(mrtd: str) -> str | None:
    """Return type if trusted, None if not."""
    return _trusted_mrtds.get(mrtd)


def list_trusted_mrtds() -> dict[str, str]:
    """Return all trusted MRTDs as {mrtd_hash: type}."""
    return dict(_trusted_mrtds)


# ==============================================================================
# Trusted RTMR lookup (env-var-only, no DB)
# ==============================================================================

_trusted_rtmrs: dict[str, dict[str, str]] = {}  # type ("agent"/"proxy") -> {rtmr0: ..., rtmr3: ...}


def load_trusted_rtmrs():
    """Load trusted RTMRs from environment variables.

    Expected format: JSON object with rtmr0-3 keys, e.g.
    TRUSTED_AGENT_RTMRS='{"rtmr0":"abc...","rtmr1":"def...","rtmr2":"ghi...","rtmr3":"jkl..."}'
    """
    global _trusted_rtmrs
    _trusted_rtmrs = {}
    for env_var, mrtd_type in [
        ("TRUSTED_AGENT_RTMRS", "agent"),
        ("TRUSTED_PROXY_RTMRS", "proxy"),
    ]:
        val = os.environ.get(env_var, "").strip()
        if not val:
            continue
        try:
            import json

            rtmrs = json.loads(val)
            if isinstance(rtmrs, dict) and all(f"rtmr{i}" in rtmrs for i in range(4)):
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


def get_trusted_rtmrs(mrtd_type: str) -> dict[str, str] | None:
    """Return trusted RTMRs for a given type, or None if not configured."""
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
deployment_store = DeploymentStore()
app_store = AppStore()
app_version_store = AppVersionStore()
account_store = AccountStore()
transaction_store = TransactionStore()
admin_session_store = AdminSessionStore()

# Load trusted MRTDs and RTMRs from env vars at import time
load_trusted_mrtds()
load_trusted_rtmrs()
