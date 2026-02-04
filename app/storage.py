"""SQLModel-backed storage for EasyEnclave discovery service."""

from __future__ import annotations

import logging
import os
from datetime import datetime, timedelta

from sqlmodel import func, select

from .database import get_db, init_db
from .db_models import (
    AgentDB,
    AppDB,
    AppVersionDB,
    DeploymentDB,
    JobDB,
    MrtdType,
    ServiceDB,
    TrustedMrtdDB,
    WorkerDB,
)
from .models import (
    App,
    AppVersion,
    Deployment,
    Job,
    LauncherAgent,
    ServiceRegistration,
    TrustedMrtd,
    Worker,
)

logger = logging.getLogger(__name__)

# How long a service can be unhealthy before being marked as "down"
UNHEALTHY_TIMEOUT = timedelta(hours=1)


def _db_to_pydantic_service(db: ServiceDB) -> ServiceRegistration:
    """Convert database model to Pydantic model."""
    return ServiceRegistration(
        service_id=db.service_id,
        name=db.name,
        description=db.description,
        source_repo=db.source_repo,
        source_commit=db.source_commit,
        compose_hash=db.compose_hash,
        endpoints=db.endpoints or {},
        mrtd=db.mrtd,
        attestation_json=db.attestation_json,
        intel_ta_token=db.intel_ta_token,
        registered_at=db.registered_at,
        last_health_check=db.last_health_check,
        health_status=db.health_status,
        tags=db.tags or [],
    )


def _pydantic_to_db_service(service: ServiceRegistration) -> ServiceDB:
    """Convert Pydantic model to database model."""
    return ServiceDB(
        service_id=service.service_id,
        name=service.name,
        description=service.description,
        source_repo=service.source_repo,
        source_commit=service.source_commit,
        compose_hash=service.compose_hash,
        endpoints=service.endpoints,
        mrtd=service.mrtd,
        attestation_json=service.attestation_json,
        intel_ta_token=service.intel_ta_token,
        registered_at=service.registered_at,
        last_health_check=service.last_health_check,
        health_status=service.health_status,
        tags=service.tags,
    )


class InMemoryStore:
    """SQLModel-backed storage for service registrations."""

    def register(self, service: ServiceRegistration) -> str:
        """Register a new service. Returns the service_id."""
        with get_db() as session:
            db_service = _pydantic_to_db_service(service)
            session.add(db_service)
        return service.service_id

    def get_by_name(self, name: str) -> ServiceRegistration | None:
        """Get a service by name. Returns None if not found."""
        with get_db() as session:
            statement = select(ServiceDB).where(ServiceDB.name == name)
            db_service = session.exec(statement).first()
            return _db_to_pydantic_service(db_service) if db_service else None

    def upsert(self, service: ServiceRegistration) -> tuple[str, bool]:
        """Register or update a service by name.

        Returns (service_id, is_new) where is_new is True if created, False if updated.
        """
        with get_db() as session:
            statement = select(ServiceDB).where(ServiceDB.name == service.name)
            existing = session.exec(statement).first()
            if existing:
                # Update existing - preserve service_id and registered_at
                existing.description = service.description
                existing.source_repo = service.source_repo
                existing.source_commit = service.source_commit
                existing.compose_hash = service.compose_hash
                existing.endpoints = service.endpoints
                existing.mrtd = service.mrtd
                existing.attestation_json = service.attestation_json
                existing.intel_ta_token = service.intel_ta_token
                existing.last_health_check = service.last_health_check
                existing.health_status = service.health_status
                existing.tags = service.tags
                session.add(existing)
                return existing.service_id, False
            else:
                # Create new
                db_service = _pydantic_to_db_service(service)
                session.add(db_service)
                return service.service_id, True

    def get(self, service_id: str) -> ServiceRegistration | None:
        """Get a service by ID. Returns None if not found."""
        with get_db() as session:
            db_service = session.get(ServiceDB, service_id)
            return _db_to_pydantic_service(db_service) if db_service else None

    def _is_timed_out(self, service: ServiceRegistration) -> bool:
        """Check if a service has been unhealthy long enough to be considered down."""
        if service.health_status == "healthy":
            return False
        if service.last_health_check is None:
            return False
        return datetime.utcnow() - service.last_health_check > UNHEALTHY_TIMEOUT

    def list(
        self, filters: dict | None = None, include_down: bool = False
    ) -> list[ServiceRegistration]:
        """List all services, optionally filtered."""
        with get_db() as session:
            statement = select(ServiceDB)
            db_services = session.exec(statement).all()
            services = [_db_to_pydantic_service(s) for s in db_services]

        # Filter out timed-out services by default
        if not include_down:
            services = [s for s in services if not self._is_timed_out(s)]

        if not filters:
            return services

        result = services

        if filters.get("name"):
            name_filter = filters["name"].lower()
            result = [s for s in result if name_filter in s.name.lower()]

        if filters.get("tags"):
            filter_tags = set(filters["tags"])
            result = [s for s in result if filter_tags & set(s.tags)]

        if filters.get("environment"):
            env = filters["environment"]
            result = [s for s in result if env in s.endpoints]

        if filters.get("mrtd"):
            mrtd = filters["mrtd"]
            result = [s for s in result if s.mrtd == mrtd]

        if filters.get("health_status"):
            status = filters["health_status"]
            result = [s for s in result if s.health_status == status]

        return result

    def delete(self, service_id: str) -> bool:
        """Delete a service by ID. Returns True if deleted, False if not found."""
        with get_db() as session:
            db_service = session.get(ServiceDB, service_id)
            if db_service:
                session.delete(db_service)
                return True
            return False

    def get_all_for_health_check(self) -> list[ServiceRegistration]:
        """Get all services for health checking (includes timed-out services)."""
        with get_db() as session:
            statement = select(ServiceDB)
            db_services = session.exec(statement).all()
            return [_db_to_pydantic_service(s) for s in db_services]

    def update(self, service_id: str, **updates) -> ServiceRegistration | None:
        """Update a service's fields. Returns updated service or None if not found."""
        with get_db() as session:
            db_service = session.get(ServiceDB, service_id)
            if db_service is None:
                return None

            for key, value in updates.items():
                if hasattr(db_service, key):
                    setattr(db_service, key, value)

            session.add(db_service)
            session.commit()
            session.refresh(db_service)
            return _db_to_pydantic_service(db_service)

    def search(self, query: str) -> list[ServiceRegistration]:
        """Search services by query string (matches name, description, tags)."""
        query_lower = query.lower()
        with get_db() as session:
            statement = select(ServiceDB)
            db_services = session.exec(statement).all()
            results = []
            for db_service in db_services:
                service = _db_to_pydantic_service(db_service)
                if query_lower in service.name.lower():
                    results.append(service)
                    continue
                if query_lower in service.description.lower():
                    results.append(service)
                    continue
                if any(query_lower in tag.lower() for tag in service.tags):
                    results.append(service)
                    continue
                if service.source_repo and query_lower in service.source_repo.lower():
                    results.append(service)
                    continue
            return results

    def count(self) -> int:
        """Return the total number of registered services."""
        with get_db() as session:
            statement = select(func.count()).select_from(ServiceDB)
            return session.exec(statement).one()

    def clear(self) -> None:
        """Clear all services (useful for testing)."""
        with get_db() as session:
            statement = select(ServiceDB)
            for db_service in session.exec(statement).all():
                session.delete(db_service)


# Global store instance
store = InMemoryStore()


# How long before a worker is considered offline
WORKER_OFFLINE_TIMEOUT = timedelta(minutes=2)


def _db_to_pydantic_worker(db: WorkerDB) -> Worker:
    """Convert database model to Pydantic model."""
    return Worker(
        worker_id=db.worker_id,
        attestation=db.attestation,
        capabilities=db.capabilities or ["docker"],
        registered_at=db.registered_at,
        last_heartbeat=db.last_heartbeat,
        status=db.status,
        current_job_id=db.current_job_id,
    )


class WorkerStore:
    """SQLModel-backed storage for standby workers."""

    def register(self, worker: Worker) -> str:
        """Register a new worker. Returns the worker_id."""
        with get_db() as session:
            db_worker = WorkerDB(
                worker_id=worker.worker_id,
                attestation=worker.attestation,
                capabilities=worker.capabilities,
                registered_at=worker.registered_at,
                last_heartbeat=worker.last_heartbeat,
                status=worker.status,
                current_job_id=worker.current_job_id,
            )
            session.add(db_worker)
        return worker.worker_id

    def get(self, worker_id: str) -> Worker | None:
        """Get a worker by ID. Returns None if not found."""
        with get_db() as session:
            db_worker = session.get(WorkerDB, worker_id)
            return _db_to_pydantic_worker(db_worker) if db_worker else None

    def heartbeat(self, worker_id: str) -> bool:
        """Update worker's last heartbeat. Returns False if not found."""
        with get_db() as session:
            db_worker = session.get(WorkerDB, worker_id)
            if db_worker is None:
                return False
            db_worker.last_heartbeat = datetime.utcnow()
            session.add(db_worker)
            return True

    def mark_busy(self, worker_id: str, job_id: str) -> bool:
        """Mark a worker as busy with a job. Returns False if not found."""
        with get_db() as session:
            db_worker = session.get(WorkerDB, worker_id)
            if db_worker is None:
                return False
            db_worker.status = "busy"
            db_worker.current_job_id = job_id
            session.add(db_worker)
            return True

    def mark_available(self, worker_id: str) -> bool:
        """Mark a worker as available. Returns False if not found."""
        with get_db() as session:
            db_worker = session.get(WorkerDB, worker_id)
            if db_worker is None:
                return False
            db_worker.status = "available"
            db_worker.current_job_id = None
            session.add(db_worker)
            return True

    def list(self) -> list[Worker]:
        """List all workers."""
        with get_db() as session:
            statement = select(WorkerDB)
            db_workers = session.exec(statement).all()
            return [_db_to_pydantic_worker(w) for w in db_workers]

    def delete(self, worker_id: str) -> bool:
        """Delete a worker. Returns True if deleted, False if not found."""
        with get_db() as session:
            db_worker = session.get(WorkerDB, worker_id)
            if db_worker:
                session.delete(db_worker)
                return True
            return False

    def clear(self) -> None:
        """Clear all workers (useful for testing)."""
        with get_db() as session:
            statement = select(WorkerDB)
            for db_worker in session.exec(statement).all():
                session.delete(db_worker)


def _db_to_pydantic_job(db: JobDB) -> Job:
    """Convert database model to Pydantic model."""
    return Job(
        job_id=db.job_id,
        compose=db.compose,
        build_context=db.build_context or {},
        config=db.config or {},
        status=db.status,
        worker_id=db.worker_id,
        submitted_at=db.submitted_at,
        started_at=db.started_at,
        completed_at=db.completed_at,
        attestation=db.attestation,
        service_id=db.service_id,
        error=db.error,
    )


class JobStore:
    """SQLModel-backed storage for jobs."""

    def submit(self, job: Job) -> str:
        """Submit a new job to the queue. Returns the job_id."""
        with get_db() as session:
            # Get next queue order
            statement = select(func.coalesce(func.max(JobDB.queue_order), 0) + 1)
            queue_order = session.exec(statement).one()

            db_job = JobDB(
                job_id=job.job_id,
                compose=job.compose,
                build_context=job.build_context,
                config=job.config,
                status=job.status,
                worker_id=job.worker_id,
                submitted_at=job.submitted_at,
                started_at=job.started_at,
                completed_at=job.completed_at,
                attestation=job.attestation,
                service_id=job.service_id,
                error=job.error,
                queue_order=queue_order,
            )
            session.add(db_job)
        return job.job_id

    def get(self, job_id: str) -> Job | None:
        """Get a job by ID. Returns None if not found."""
        with get_db() as session:
            db_job = session.get(JobDB, job_id)
            return _db_to_pydantic_job(db_job) if db_job else None

    def get_next_job(self) -> Job | None:
        """Get the next queued job. Returns None if queue is empty."""
        with get_db() as session:
            statement = (
                select(JobDB)
                .where(JobDB.status == "queued")
                .order_by(JobDB.queue_order.asc())
                .limit(1)
            )
            db_job = session.exec(statement).first()
            return _db_to_pydantic_job(db_job) if db_job else None

    def assign_job(self, job_id: str, worker_id: str) -> bool:
        """Assign a job to a worker. Returns False if job not found."""
        with get_db() as session:
            db_job = session.get(JobDB, job_id)
            if db_job is None:
                return False
            db_job.status = "assigned"
            db_job.worker_id = worker_id
            db_job.started_at = datetime.utcnow()
            session.add(db_job)
            return True

    def update_status(self, job_id: str, status: str) -> bool:
        """Update a job's status. Returns False if job not found."""
        with get_db() as session:
            db_job = session.get(JobDB, job_id)
            if db_job is None:
                return False
            db_job.status = status
            session.add(db_job)
            return True

    def complete_job(
        self,
        job_id: str,
        status: str,
        attestation: dict | None = None,
        service_id: str | None = None,
        error: str | None = None,
    ) -> bool:
        """Complete a job. Returns False if job not found."""
        with get_db() as session:
            db_job = session.get(JobDB, job_id)
            if db_job is None:
                return False
            db_job.status = status
            db_job.completed_at = datetime.utcnow()
            db_job.attestation = attestation
            db_job.service_id = service_id
            db_job.error = error
            session.add(db_job)
            return True

    def list(self, status: str | None = None) -> list[Job]:
        """List all jobs, optionally filtered by status."""
        with get_db() as session:
            statement = select(JobDB)
            if status:
                statement = statement.where(JobDB.status == status)
            db_jobs = session.exec(statement).all()
            return [_db_to_pydantic_job(j) for j in db_jobs]

    def delete(self, job_id: str) -> bool:
        """Delete a job. Returns True if deleted, False if not found."""
        with get_db() as session:
            db_job = session.get(JobDB, job_id)
            if db_job:
                session.delete(db_job)
                return True
            return False

    def clear(self) -> None:
        """Clear all jobs (useful for testing)."""
        with get_db() as session:
            statement = select(JobDB)
            for db_job in session.exec(statement).all():
                session.delete(db_job)


# Global store instances
worker_store = WorkerStore()
job_store = JobStore()


# How long before an agent is considered offline
AGENT_OFFLINE_TIMEOUT = timedelta(minutes=5)


def _db_to_pydantic_agent(db: AgentDB) -> LauncherAgent:
    """Convert database model to Pydantic model."""
    return LauncherAgent(
        agent_id=db.agent_id,
        vm_name=db.vm_name,
        status=db.status,
        attestation=db.attestation,
        mrtd=db.mrtd,
        intel_ta_token=db.intel_ta_token,
        tunnel_id=db.tunnel_id,
        hostname=db.hostname,
        tunnel_token=db.tunnel_token,
        current_deployment_id=db.current_deployment_id,
        service_url=db.service_url,
        health_endpoint=db.health_endpoint,
        health_status=db.health_status,
        last_health_check=db.last_health_check,
        unhealthy_since=db.unhealthy_since,
        stats=db.stats,
        registered_at=db.registered_at,
        last_heartbeat=db.last_heartbeat,
        version=db.version,
        verified=db.verified,
        verification_error=db.verification_error,
        tunnel_error=db.tunnel_error,
        last_attestation_check=db.last_attestation_check,
        attestation_valid=db.attestation_valid,
        attestation_error=db.attestation_error,
    )


class AgentStore:
    """SQLModel-backed storage for launcher agents."""

    def register(self, agent: LauncherAgent) -> str:
        """Register a new agent. Returns the agent_id."""
        with get_db() as session:
            # Delete existing agent with same vm_name if exists (for re-registration)
            statement = select(AgentDB).where(AgentDB.vm_name == agent.vm_name)
            existing = session.exec(statement).first()
            if existing:
                session.delete(existing)
                session.commit()

            db_agent = AgentDB(
                agent_id=agent.agent_id,
                vm_name=agent.vm_name,
                status=agent.status,
                attestation=agent.attestation,
                mrtd=agent.mrtd,
                intel_ta_token=agent.intel_ta_token,
                tunnel_id=agent.tunnel_id,
                hostname=agent.hostname,
                tunnel_token=agent.tunnel_token,
                current_deployment_id=agent.current_deployment_id,
                service_url=agent.service_url,
                health_endpoint=agent.health_endpoint,
                health_status=agent.health_status,
                last_health_check=agent.last_health_check,
                unhealthy_since=agent.unhealthy_since,
                stats=agent.stats,
                registered_at=agent.registered_at,
                last_heartbeat=agent.last_heartbeat,
                version=agent.version,
                verified=agent.verified,
                verification_error=agent.verification_error,
                tunnel_error=agent.tunnel_error,
                last_attestation_check=agent.last_attestation_check,
                attestation_valid=agent.attestation_valid,
                attestation_error=agent.attestation_error,
            )
            session.add(db_agent)
        return agent.agent_id

    def get(self, agent_id: str) -> LauncherAgent | None:
        """Get an agent by ID. Returns None if not found."""
        with get_db() as session:
            db_agent = session.get(AgentDB, agent_id)
            return _db_to_pydantic_agent(db_agent) if db_agent else None

    def get_by_vm_name(self, vm_name: str) -> LauncherAgent | None:
        """Get an agent by VM name. Returns None if not found."""
        with get_db() as session:
            statement = select(AgentDB).where(AgentDB.vm_name == vm_name)
            db_agent = session.exec(statement).first()
            return _db_to_pydantic_agent(db_agent) if db_agent else None

    def heartbeat(self, agent_id: str) -> bool:
        """Update agent's last heartbeat. Returns False if not found."""
        with get_db() as session:
            db_agent = session.get(AgentDB, agent_id)
            if db_agent is None:
                return False
            db_agent.last_heartbeat = datetime.utcnow()
            session.add(db_agent)
            return True

    def update_status(
        self,
        agent_id: str,
        status: str,
        deployment_id: str | None = None,
        error: str | None = None,
    ) -> bool:
        """Update agent's status. Returns False if not found."""
        with get_db() as session:
            db_agent = session.get(AgentDB, agent_id)
            if db_agent is None:
                return False
            db_agent.status = status
            if deployment_id is not None:
                db_agent.current_deployment_id = deployment_id
            db_agent.last_heartbeat = datetime.utcnow()
            session.add(db_agent)
            return True

    def set_deployment(self, agent_id: str, deployment_id: str | None) -> bool:
        """Set or clear the agent's current deployment. Returns False if not found."""
        with get_db() as session:
            db_agent = session.get(AgentDB, agent_id)
            if db_agent is None:
                return False
            db_agent.current_deployment_id = deployment_id
            session.add(db_agent)
            return True

    def list(self, filters: dict | None = None) -> list[LauncherAgent]:
        """List all agents, optionally filtered."""
        with get_db() as session:
            statement = select(AgentDB)
            db_agents = session.exec(statement).all()
            agents = [_db_to_pydantic_agent(a) for a in db_agents]

        if not filters:
            return agents

        result = agents

        if filters.get("status"):
            result = [a for a in result if a.status == filters["status"]]

        if filters.get("vm_name"):
            vm_name_filter = filters["vm_name"].lower()
            result = [a for a in result if vm_name_filter in a.vm_name.lower()]

        return result

    def delete(self, agent_id: str) -> bool:
        """Delete an agent. Returns True if deleted, False if not found."""
        with get_db() as session:
            db_agent = session.get(AgentDB, agent_id)
            if db_agent:
                session.delete(db_agent)
                return True
            return False

    def get_available(self, require_verified: bool = True) -> LauncherAgent | None:
        """Get an available (undeployed, verified) agent. Returns None if none available."""
        agents = self.list({"status": "undeployed"})
        now = datetime.utcnow()
        for agent in agents:
            if now - agent.last_heartbeat < AGENT_OFFLINE_TIMEOUT:
                if require_verified and not agent.verified:
                    continue
                return agent
        return None

    def set_verified(
        self,
        agent_id: str,
        verified: bool,
        error: str | None = None,
    ) -> bool:
        """Set agent's verification status. Returns False if not found."""
        with get_db() as session:
            db_agent = session.get(AgentDB, agent_id)
            if db_agent is None:
                return False
            db_agent.verified = verified
            db_agent.verification_error = error
            session.add(db_agent)
            return True

    def update_health(
        self,
        agent_id: str,
        health_status: str,
        service_url: str | None = None,
        health_endpoint: str | None = None,
    ) -> bool:
        """Update agent's health status. Returns False if not found."""
        with get_db() as session:
            db_agent = session.get(AgentDB, agent_id)
            if db_agent is None:
                return False

            # Determine unhealthy_since
            if health_status == "unhealthy":
                if db_agent.health_status != "unhealthy":
                    db_agent.unhealthy_since = datetime.utcnow()
            else:
                db_agent.unhealthy_since = None

            db_agent.health_status = health_status
            db_agent.last_health_check = datetime.utcnow()
            if service_url is not None:
                db_agent.service_url = service_url
            if health_endpoint is not None:
                db_agent.health_endpoint = health_endpoint

            session.add(db_agent)
            return True

    def update_tunnel_info(
        self,
        agent_id: str,
        tunnel_id: str,
        hostname: str,
        tunnel_token: str | None = None,
    ) -> bool:
        """Update agent's Cloudflare tunnel info. Returns False if not found."""
        with get_db() as session:
            db_agent = session.get(AgentDB, agent_id)
            if db_agent is None:
                return False
            db_agent.tunnel_id = tunnel_id
            db_agent.hostname = hostname
            if tunnel_token:
                db_agent.tunnel_token = tunnel_token
            db_agent.tunnel_error = None
            session.add(db_agent)
            return True

    def update_tunnel_error(self, agent_id: str, error: str) -> bool:
        """Store tunnel creation error on agent. Returns False if not found."""
        with get_db() as session:
            db_agent = session.get(AgentDB, agent_id)
            if db_agent is None:
                return False
            db_agent.tunnel_error = error
            session.add(db_agent)
            return True

    def get_unhealthy_agents(self, unhealthy_timeout: timedelta) -> list[LauncherAgent]:
        """Get agents that have been unhealthy longer than the timeout."""
        with get_db() as session:
            statement = select(AgentDB).where(
                AgentDB.status == "deployed", AgentDB.unhealthy_since.isnot(None)
            )
            db_agents = session.exec(statement).all()
            now = datetime.utcnow()
            unhealthy = []
            for db_agent in db_agents:
                if db_agent.unhealthy_since and now - db_agent.unhealthy_since > unhealthy_timeout:
                    unhealthy.append(_db_to_pydantic_agent(db_agent))
            return unhealthy

    def reset_for_reassignment(self, agent_id: str) -> bool:
        """Reset an agent to undeployed state for reassignment. Returns False if not found."""
        with get_db() as session:
            db_agent = session.get(AgentDB, agent_id)
            if db_agent is None:
                return False
            db_agent.status = "undeployed"
            db_agent.current_deployment_id = None
            db_agent.service_url = None
            db_agent.health_status = "unknown"
            db_agent.last_health_check = None
            db_agent.unhealthy_since = None
            session.add(db_agent)
            return True

    def update_attestation_status(
        self,
        agent_id: str,
        attestation_valid: bool,
        error: str | None = None,
        intel_ta_token: str | None = None,
    ) -> bool:
        """Update agent's attestation status. Returns False if not found."""
        with get_db() as session:
            db_agent = session.get(AgentDB, agent_id)
            if db_agent is None:
                return False
            db_agent.last_attestation_check = datetime.utcnow()
            db_agent.attestation_valid = attestation_valid
            db_agent.attestation_error = error
            if intel_ta_token is not None:
                db_agent.intel_ta_token = intel_ta_token
            session.add(db_agent)
            return True

    def update_attestation(
        self,
        agent_id: str,
        intel_ta_token: str,
        verified: bool,
        error: str | None = None,
    ) -> bool:
        """Update agent's attestation from poll. Returns False if not found."""
        with get_db() as session:
            db_agent = session.get(AgentDB, agent_id)
            if db_agent is None:
                return False
            db_agent.intel_ta_token = intel_ta_token
            db_agent.verified = verified
            db_agent.last_attestation_check = datetime.utcnow()
            db_agent.attestation_valid = verified
            db_agent.attestation_error = error
            session.add(db_agent)
            return True

    def update_stats(self, agent_id: str, stats: dict) -> bool:
        """Update agent's system stats. Returns False if not found."""
        with get_db() as session:
            db_agent = session.get(AgentDB, agent_id)
            if db_agent is None:
                return False
            db_agent.stats = stats
            session.add(db_agent)
            return True

    def mark_attestation_failed(
        self,
        agent_id: str,
        error: str,
        clear_tunnel: bool = True,
    ) -> bool:
        """Mark agent as attestation failed. Returns False if not found."""
        with get_db() as session:
            db_agent = session.get(AgentDB, agent_id)
            if db_agent is None:
                return False
            db_agent.status = "attestation_failed"
            db_agent.attestation_valid = False
            db_agent.attestation_error = error
            db_agent.last_attestation_check = datetime.utcnow()
            if clear_tunnel:
                db_agent.tunnel_id = None
                db_agent.hostname = None
            session.add(db_agent)
            return True

    def clear(self) -> None:
        """Clear all agents (useful for testing)."""
        with get_db() as session:
            statement = select(AgentDB)
            for db_agent in session.exec(statement).all():
                session.delete(db_agent)


def _db_to_pydantic_deployment(db: DeploymentDB) -> Deployment:
    """Convert database model to Pydantic model."""
    return Deployment(
        deployment_id=db.deployment_id,
        compose=db.compose,
        build_context=db.build_context or {},
        config=db.config or {},
        agent_id=db.agent_id,
        status=db.status,
        service_id=db.service_id,
        attestation=db.attestation,
        error=db.error,
        created_at=db.created_at,
        started_at=db.started_at,
        completed_at=db.completed_at,
    )


class DeploymentStore:
    """SQLModel-backed storage for deployments."""

    def create(self, deployment: Deployment) -> str:
        """Create a new deployment. Returns the deployment_id."""
        with get_db() as session:
            db_deployment = DeploymentDB(
                deployment_id=deployment.deployment_id,
                compose=deployment.compose,
                build_context=deployment.build_context,
                config=deployment.config,
                agent_id=deployment.agent_id,
                status=deployment.status,
                service_id=deployment.service_id,
                attestation=deployment.attestation,
                error=deployment.error,
                created_at=deployment.created_at,
                started_at=deployment.started_at,
                completed_at=deployment.completed_at,
            )
            session.add(db_deployment)
        return deployment.deployment_id

    def get(self, deployment_id: str) -> Deployment | None:
        """Get a deployment by ID. Returns None if not found."""
        with get_db() as session:
            db_deployment = session.get(DeploymentDB, deployment_id)
            return _db_to_pydantic_deployment(db_deployment) if db_deployment else None

    def get_pending_for_agent(self, agent_id: str) -> Deployment | None:
        """Get the next pending deployment for an agent. Returns None if none pending."""
        with get_db() as session:
            statement = (
                select(DeploymentDB)
                .where(DeploymentDB.agent_id == agent_id, DeploymentDB.status == "pending")
                .order_by(DeploymentDB.created_at.asc())
                .limit(1)
            )
            db_deployment = session.exec(statement).first()
            return _db_to_pydantic_deployment(db_deployment) if db_deployment else None

    def assign(self, deployment_id: str, agent_id: str) -> bool:
        """Mark a deployment as assigned to an agent. Returns False if not found."""
        with get_db() as session:
            db_deployment = session.get(DeploymentDB, deployment_id)
            if db_deployment is None:
                return False
            db_deployment.status = "assigned"
            db_deployment.agent_id = agent_id
            db_deployment.started_at = datetime.utcnow()
            session.add(db_deployment)
            return True

    def update_status(
        self,
        deployment_id: str,
        status: str,
        error: str | None = None,
    ) -> bool:
        """Update a deployment's status. Returns False if not found."""
        with get_db() as session:
            db_deployment = session.get(DeploymentDB, deployment_id)
            if db_deployment is None:
                return False
            db_deployment.status = status
            if error:
                db_deployment.error = error
            session.add(db_deployment)
            return True

    def complete(
        self,
        deployment_id: str,
        status: str,
        service_id: str | None = None,
        attestation: dict | None = None,
        error: str | None = None,
    ) -> bool:
        """Complete a deployment. Returns False if not found."""
        with get_db() as session:
            db_deployment = session.get(DeploymentDB, deployment_id)
            if db_deployment is None:
                return False
            db_deployment.status = status
            db_deployment.completed_at = datetime.utcnow()
            if service_id:
                db_deployment.service_id = service_id
            if attestation:
                db_deployment.attestation = attestation
            if error:
                db_deployment.error = error
            session.add(db_deployment)
            return True

    def list(self, filters: dict | None = None) -> list[Deployment]:
        """List all deployments, optionally filtered."""
        with get_db() as session:
            statement = select(DeploymentDB)
            db_deployments = session.exec(statement).all()
            deployments = [_db_to_pydantic_deployment(d) for d in db_deployments]

        if not filters:
            return deployments

        result = deployments

        if filters.get("status"):
            result = [d for d in result if d.status == filters["status"]]

        if filters.get("agent_id"):
            result = [d for d in result if d.agent_id == filters["agent_id"]]

        return result

    def reassign(self, deployment_id: str, new_agent_id: str) -> bool:
        """Reassign a deployment to a different agent. Returns False if not found."""
        with get_db() as session:
            db_deployment = session.get(DeploymentDB, deployment_id)
            if db_deployment is None:
                return False
            db_deployment.agent_id = new_agent_id
            db_deployment.status = "pending"
            db_deployment.started_at = None
            db_deployment.completed_at = None
            db_deployment.error = None
            session.add(db_deployment)
            return True

    def mark_for_reassignment(self, deployment_id: str) -> bool:
        """Mark a deployment as needing reassignment. Returns False if not found."""
        with get_db() as session:
            db_deployment = session.get(DeploymentDB, deployment_id)
            if db_deployment is None:
                return False
            db_deployment.status = "reassigning"
            db_deployment.error = "Agent unhealthy - pending reassignment"
            session.add(db_deployment)
            return True

    def get_for_reassignment(self) -> list[Deployment]:
        """Get all deployments marked for reassignment."""
        with get_db() as session:
            statement = select(DeploymentDB).where(DeploymentDB.status == "reassigning")
            db_deployments = session.exec(statement).all()
            return [_db_to_pydantic_deployment(d) for d in db_deployments]

    def delete(self, deployment_id: str) -> bool:
        """Delete a deployment. Returns True if deleted, False if not found."""
        with get_db() as session:
            db_deployment = session.get(DeploymentDB, deployment_id)
            if db_deployment:
                session.delete(db_deployment)
                return True
            return False

    def clear(self) -> None:
        """Clear all deployments (useful for testing)."""
        with get_db() as session:
            statement = select(DeploymentDB)
            for db_deployment in session.exec(statement).all():
                session.delete(db_deployment)


def _db_to_pydantic_trusted_mrtd(db: TrustedMrtdDB) -> TrustedMrtd:
    """Convert database model to Pydantic model."""
    from .models import MrtdType as PydanticMrtdType

    return TrustedMrtd(
        mrtd=db.mrtd,
        type=PydanticMrtdType(db.type) if db.type else PydanticMrtdType.AGENT,
        locked=db.locked,
        description=db.description,
        image_version=db.image_version,
        source_repo=db.source_repo,
        source_commit=db.source_commit,
        source_tag=db.source_tag,
        build_workflow=db.build_workflow,
        image_digest=db.image_digest,
        attestation_url=db.attestation_url,
        added_at=db.added_at,
        added_by=db.added_by,
        active=db.active,
    )


class TrustedMrtdStore:
    """SQLModel-backed storage for trusted MRTD measurements."""

    def __init__(self):
        self._load_system_mrtds()

    def _load_system_mrtds(self):
        """Load hardcoded system MRTDs from environment variables."""
        try:
            init_db()
        except Exception:
            pass

        agent_mrtd = os.environ.get("SYSTEM_AGENT_MRTD")
        if agent_mrtd:
            trusted = TrustedMrtd(
                mrtd=agent_mrtd,
                type=MrtdType.AGENT,
                locked=True,
                description="System agent launcher image",
            )
            self._upsert_system_mrtd(trusted)
            logger.info(f"Loaded system agent MRTD: {agent_mrtd[:16]}...")

        proxy_mrtd = os.environ.get("SYSTEM_PROXY_MRTD")
        if proxy_mrtd:
            trusted = TrustedMrtd(
                mrtd=proxy_mrtd,
                type=MrtdType.PROXY,
                locked=True,
                description="System cloudflared proxy image",
            )
            self._upsert_system_mrtd(trusted)
            logger.info(f"Loaded system proxy MRTD: {proxy_mrtd[:16]}...")

    def _upsert_system_mrtd(self, trusted_mrtd: TrustedMrtd) -> None:
        """Insert or update a system MRTD."""
        with get_db() as session:
            existing = session.get(TrustedMrtdDB, trusted_mrtd.mrtd)
            if existing:
                existing.type = trusted_mrtd.type.value
                existing.locked = trusted_mrtd.locked
                existing.description = trusted_mrtd.description
                existing.active = trusted_mrtd.active
                session.add(existing)
            else:
                db_mrtd = TrustedMrtdDB(
                    mrtd=trusted_mrtd.mrtd,
                    type=trusted_mrtd.type.value,
                    locked=trusted_mrtd.locked,
                    description=trusted_mrtd.description,
                    image_version=trusted_mrtd.image_version,
                    source_repo=trusted_mrtd.source_repo,
                    source_commit=trusted_mrtd.source_commit,
                    source_tag=trusted_mrtd.source_tag,
                    build_workflow=trusted_mrtd.build_workflow,
                    image_digest=trusted_mrtd.image_digest,
                    attestation_url=trusted_mrtd.attestation_url,
                    added_at=trusted_mrtd.added_at,
                    added_by=trusted_mrtd.added_by,
                    active=trusted_mrtd.active,
                )
                session.add(db_mrtd)

    def add(self, trusted_mrtd: TrustedMrtd) -> str:
        """Add a trusted MRTD. Returns the MRTD value."""
        with get_db() as session:
            db_mrtd = TrustedMrtdDB(
                mrtd=trusted_mrtd.mrtd,
                type=trusted_mrtd.type.value,
                locked=trusted_mrtd.locked,
                description=trusted_mrtd.description,
                image_version=trusted_mrtd.image_version,
                source_repo=trusted_mrtd.source_repo,
                source_commit=trusted_mrtd.source_commit,
                source_tag=trusted_mrtd.source_tag,
                build_workflow=trusted_mrtd.build_workflow,
                image_digest=trusted_mrtd.image_digest,
                attestation_url=trusted_mrtd.attestation_url,
                added_at=trusted_mrtd.added_at,
                added_by=trusted_mrtd.added_by,
                active=trusted_mrtd.active,
            )
            session.add(db_mrtd)
        return trusted_mrtd.mrtd

    def get(self, mrtd: str) -> TrustedMrtd | None:
        """Get a trusted MRTD by value. Returns None if not found."""
        with get_db() as session:
            db_mrtd = session.get(TrustedMrtdDB, mrtd)
            return _db_to_pydantic_trusted_mrtd(db_mrtd) if db_mrtd else None

    def is_trusted(self, mrtd: str) -> bool:
        """Check if an MRTD is in the trusted list and active."""
        trusted = self.get(mrtd)
        return trusted is not None and trusted.active

    def list(self, include_inactive: bool = False) -> list[TrustedMrtd]:
        """List all trusted MRTDs."""
        with get_db() as session:
            statement = select(TrustedMrtdDB)
            if not include_inactive:
                statement = statement.where(TrustedMrtdDB.active == True)  # noqa: E712
            db_mrtds = session.exec(statement).all()
            return [_db_to_pydantic_trusted_mrtd(m) for m in db_mrtds]

    def deactivate(self, mrtd: str) -> tuple[bool, str | None]:
        """Deactivate a trusted MRTD."""
        trusted = self.get(mrtd)
        if trusted is None:
            return False, None
        if trusted.locked:
            return False, "Cannot deactivate system MRTD"

        with get_db() as session:
            db_mrtd = session.get(TrustedMrtdDB, mrtd)
            if db_mrtd:
                db_mrtd.active = False
                session.add(db_mrtd)
        return True, None

    def activate(self, mrtd: str) -> bool:
        """Activate a trusted MRTD. Returns False if not found."""
        with get_db() as session:
            db_mrtd = session.get(TrustedMrtdDB, mrtd)
            if db_mrtd is None:
                return False
            db_mrtd.active = True
            session.add(db_mrtd)
            return True

    def delete(self, mrtd: str) -> tuple[bool, str | None]:
        """Delete a trusted MRTD."""
        trusted = self.get(mrtd)
        if trusted is None:
            return False, None
        if trusted.locked:
            return False, "Cannot delete system MRTD"

        with get_db() as session:
            db_mrtd = session.get(TrustedMrtdDB, mrtd)
            if db_mrtd:
                session.delete(db_mrtd)
        return True, None

    def clear(self) -> None:
        """Clear all trusted MRTDs (useful for testing)."""
        with get_db() as session:
            statement = select(TrustedMrtdDB)
            for db_mrtd in session.exec(statement).all():
                session.delete(db_mrtd)


# Global store instances
agent_store = AgentStore()
deployment_store = DeploymentStore()
trusted_mrtd_store = TrustedMrtdStore()


# =============================================================================
# App Catalog Storage
# =============================================================================


def _db_to_pydantic_app(db: AppDB) -> App:
    """Convert database model to Pydantic model."""
    return App(
        app_id=db.app_id,
        name=db.name,
        description=db.description,
        source_repo=db.source_repo,
        maintainers=db.maintainers or [],
        tags=db.tags or [],
        created_at=db.created_at,
    )


class AppStore:
    """SQLModel-backed storage for apps."""

    def register(self, app: App) -> str:
        """Register a new app. Returns the app_id."""
        with get_db() as session:
            db_app = AppDB(
                app_id=app.app_id,
                name=app.name,
                description=app.description,
                source_repo=app.source_repo,
                maintainers=app.maintainers,
                tags=app.tags,
                created_at=app.created_at,
            )
            session.add(db_app)
        return app.app_id

    def get(self, app_id: str) -> App | None:
        """Get an app by ID. Returns None if not found."""
        with get_db() as session:
            db_app = session.get(AppDB, app_id)
            return _db_to_pydantic_app(db_app) if db_app else None

    def get_by_name(self, name: str) -> App | None:
        """Get an app by name. Returns None if not found."""
        with get_db() as session:
            statement = select(AppDB).where(AppDB.name == name)
            db_app = session.exec(statement).first()
            return _db_to_pydantic_app(db_app) if db_app else None

    def list(self, filters: dict | None = None) -> list[App]:
        """List all apps, optionally filtered."""
        with get_db() as session:
            statement = select(AppDB)
            db_apps = session.exec(statement).all()
            apps = [_db_to_pydantic_app(a) for a in db_apps]

        if not filters:
            return apps

        result = apps

        if filters.get("name"):
            name_filter = filters["name"].lower()
            result = [a for a in result if name_filter in a.name.lower()]

        if filters.get("tags"):
            filter_tags = set(filters["tags"])
            result = [a for a in result if filter_tags & set(a.tags)]

        return result

    def update(self, app_id: str, **updates) -> App | None:
        """Update an app's fields. Returns updated app or None if not found."""
        with get_db() as session:
            db_app = session.get(AppDB, app_id)
            if db_app is None:
                return None

            for key, value in updates.items():
                if hasattr(db_app, key):
                    setattr(db_app, key, value)

            session.add(db_app)
            session.commit()
            session.refresh(db_app)
            return _db_to_pydantic_app(db_app)

    def delete(self, app_id: str) -> bool:
        """Delete an app. Returns True if deleted, False if not found."""
        with get_db() as session:
            db_app = session.get(AppDB, app_id)
            if db_app:
                session.delete(db_app)
                return True
            return False

    def clear(self) -> None:
        """Clear all apps (useful for testing)."""
        with get_db() as session:
            statement = select(AppDB)
            for db_app in session.exec(statement).all():
                session.delete(db_app)


def _db_to_pydantic_app_version(db: AppVersionDB) -> AppVersion:
    """Convert database model to Pydantic model."""
    return AppVersion(
        version_id=db.version_id,
        app_name=db.app_name,
        version=db.version,
        compose=db.compose,
        image_digest=db.image_digest,
        source_commit=db.source_commit,
        source_tag=db.source_tag,
        mrtd=db.mrtd,
        attestation=db.attestation,
        status=db.status,
        rejection_reason=db.rejection_reason,
        published_at=db.published_at,
    )


class AppVersionStore:
    """SQLModel-backed storage for app versions."""

    def create(self, version: AppVersion) -> str:
        """Create a new app version. Returns the version_id."""
        with get_db() as session:
            db_version = AppVersionDB(
                version_id=version.version_id,
                app_name=version.app_name,
                version=version.version,
                compose=version.compose,
                image_digest=version.image_digest,
                source_commit=version.source_commit,
                source_tag=version.source_tag,
                mrtd=version.mrtd,
                attestation=version.attestation,
                status=version.status,
                rejection_reason=version.rejection_reason,
                published_at=version.published_at,
            )
            session.add(db_version)
        return version.version_id

    def get(self, version_id: str) -> AppVersion | None:
        """Get a version by ID. Returns None if not found."""
        with get_db() as session:
            db_version = session.get(AppVersionDB, version_id)
            return _db_to_pydantic_app_version(db_version) if db_version else None

    def get_by_version(self, app_name: str, version: str) -> AppVersion | None:
        """Get a specific version of an app. Returns None if not found."""
        with get_db() as session:
            statement = select(AppVersionDB).where(
                AppVersionDB.app_name == app_name, AppVersionDB.version == version
            )
            db_version = session.exec(statement).first()
            return _db_to_pydantic_app_version(db_version) if db_version else None

    def list_for_app(self, app_name: str) -> list[AppVersion]:
        """List all versions for an app, ordered by published_at (newest first)."""
        with get_db() as session:
            statement = (
                select(AppVersionDB)
                .where(AppVersionDB.app_name == app_name)
                .order_by(AppVersionDB.published_at.desc())
            )
            db_versions = session.exec(statement).all()
            return [_db_to_pydantic_app_version(v) for v in db_versions]

    def update(self, version_id: str, **updates) -> AppVersion | None:
        """Update a version's fields. Returns updated version or None if not found."""
        with get_db() as session:
            db_version = session.get(AppVersionDB, version_id)
            if db_version is None:
                return None

            for key, value in updates.items():
                if hasattr(db_version, key):
                    setattr(db_version, key, value)

            session.add(db_version)
            session.commit()
            session.refresh(db_version)
            return _db_to_pydantic_app_version(db_version)

    def update_status(
        self,
        version_id: str,
        status: str,
        mrtd: str | None = None,
        attestation: dict | None = None,
        rejection_reason: str | None = None,
    ) -> bool:
        """Update version status and attestation. Returns False if not found."""
        with get_db() as session:
            db_version = session.get(AppVersionDB, version_id)
            if db_version is None:
                return False
            db_version.status = status
            if mrtd is not None:
                db_version.mrtd = mrtd
            if attestation is not None:
                db_version.attestation = attestation
            if rejection_reason is not None:
                db_version.rejection_reason = rejection_reason
            session.add(db_version)
            return True

    def delete(self, version_id: str) -> bool:
        """Delete a version. Returns True if deleted, False if not found."""
        with get_db() as session:
            db_version = session.get(AppVersionDB, version_id)
            if db_version:
                session.delete(db_version)
                return True
            return False

    def clear(self) -> None:
        """Clear all versions (useful for testing)."""
        with get_db() as session:
            statement = select(AppVersionDB)
            for db_version in session.exec(statement).all():
                session.delete(db_version)


# Global app store instances
app_store = AppStore()
app_version_store = AppVersionStore()
