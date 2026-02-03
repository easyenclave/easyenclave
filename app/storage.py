"""In-memory storage for EasyEnclave discovery service."""

from __future__ import annotations

import logging
import os
import threading
from datetime import datetime, timedelta

from .models import (
    App,
    AppVersion,
    Deployment,
    Job,
    LauncherAgent,
    LogEntry,
    LogLevel,
    LogSource,
    MrtdType,
    ServiceRegistration,
    TrustedMrtd,
    Worker,
)

logger = logging.getLogger(__name__)

# How long a service can be unhealthy before being marked as "down"
UNHEALTHY_TIMEOUT = timedelta(hours=1)


class InMemoryStore:
    """Thread-safe in-memory storage for service registrations."""

    def __init__(self):
        self._services: dict[str, ServiceRegistration] = {}
        self._name_index: dict[str, str] = {}  # name -> service_id
        self._lock = threading.RLock()

    def register(self, service: ServiceRegistration) -> str:
        """Register a new service. Returns the service_id."""
        with self._lock:
            self._services[service.service_id] = service
            self._name_index[service.name] = service.service_id
            return service.service_id

    def get_by_name(self, name: str) -> ServiceRegistration | None:
        """Get a service by name. Returns None if not found."""
        with self._lock:
            service_id = self._name_index.get(name)
            if service_id:
                return self._services.get(service_id)
            return None

    def upsert(self, service: ServiceRegistration) -> tuple[str, bool]:
        """Register or update a service by name.

        Returns (service_id, is_new) where is_new is True if created, False if updated.
        """
        with self._lock:
            existing_id = self._name_index.get(service.name)
            if existing_id:
                # Update existing - preserve service_id and registered_at
                existing = self._services[existing_id]
                service_dict = service.model_dump()
                service_dict["service_id"] = existing_id
                service_dict["registered_at"] = existing.registered_at
                updated_service = ServiceRegistration(**service_dict)
                self._services[existing_id] = updated_service
                return existing_id, False
            else:
                # Create new
                self._services[service.service_id] = service
                self._name_index[service.name] = service.service_id
                return service.service_id, True

    def get(self, service_id: str) -> ServiceRegistration | None:
        """Get a service by ID. Returns None if not found."""
        with self._lock:
            return self._services.get(service_id)

    def _is_timed_out(self, service: ServiceRegistration) -> bool:
        """Check if a service has been unhealthy long enough to be considered down."""
        if service.health_status == "healthy":
            return False
        if service.last_health_check is None:
            # Never checked - not timed out yet
            return False
        return datetime.utcnow() - service.last_health_check > UNHEALTHY_TIMEOUT

    def list(
        self, filters: dict | None = None, include_down: bool = False
    ) -> list[ServiceRegistration]:
        """List all services, optionally filtered.

        Args:
            filters: Optional dict of filters
            include_down: If False (default), exclude services that have been
                         unhealthy for longer than UNHEALTHY_TIMEOUT
        """
        with self._lock:
            services = list(self._services.values())

        # Filter out timed-out services by default
        if not include_down:
            services = [s for s in services if not self._is_timed_out(s)]

        if not filters:
            return services

        result = services

        # Filter by name (partial match, case-insensitive)
        if filters.get("name"):
            name_filter = filters["name"].lower()
            result = [s for s in result if name_filter in s.name.lower()]

        # Filter by tags (any match)
        if filters.get("tags"):
            filter_tags = set(filters["tags"])
            result = [s for s in result if filter_tags & set(s.tags)]

        # Filter by environment (must have endpoint for this env)
        if filters.get("environment"):
            env = filters["environment"]
            result = [s for s in result if env in s.endpoints]

        # Filter by mrtd (exact match)
        if filters.get("mrtd"):
            mrtd = filters["mrtd"]
            result = [s for s in result if s.mrtd == mrtd]

        # Filter by health_status
        if filters.get("health_status"):
            status = filters["health_status"]
            result = [s for s in result if s.health_status == status]

        return result

    def delete(self, service_id: str) -> bool:
        """Delete a service by ID. Returns True if deleted, False if not found."""
        with self._lock:
            if service_id in self._services:
                service = self._services[service_id]
                # Clean up name index
                if self._name_index.get(service.name) == service_id:
                    del self._name_index[service.name]
                del self._services[service_id]
                return True
            return False

    def get_all_for_health_check(self) -> list[ServiceRegistration]:
        """Get all services for health checking (includes timed-out services)."""
        with self._lock:
            return list(self._services.values())

    def update(self, service_id: str, **updates) -> ServiceRegistration | None:
        """Update a service's fields. Returns updated service or None if not found."""
        with self._lock:
            service = self._services.get(service_id)
            if service is None:
                return None

            # Create updated service
            service_dict = service.model_dump()
            service_dict.update(updates)
            updated_service = ServiceRegistration(**service_dict)
            self._services[service_id] = updated_service
            return updated_service

    def search(self, query: str) -> list[ServiceRegistration]:
        """Search services by query string (matches name, description, tags)."""
        query_lower = query.lower()
        with self._lock:
            results = []
            for service in self._services.values():
                # Check name
                if query_lower in service.name.lower():
                    results.append(service)
                    continue
                # Check description
                if query_lower in service.description.lower():
                    results.append(service)
                    continue
                # Check tags
                if any(query_lower in tag.lower() for tag in service.tags):
                    results.append(service)
                    continue
                # Check source_repo
                if service.source_repo and query_lower in service.source_repo.lower():
                    results.append(service)
                    continue
            return results

    def count(self) -> int:
        """Return the total number of registered services."""
        with self._lock:
            return len(self._services)

    def clear(self) -> None:
        """Clear all services (useful for testing)."""
        with self._lock:
            self._services.clear()
            self._name_index.clear()


# Global store instance
store = InMemoryStore()


# How long before a worker is considered offline
WORKER_OFFLINE_TIMEOUT = timedelta(minutes=2)


class WorkerStore:
    """Thread-safe in-memory storage for standby workers."""

    def __init__(self):
        self._workers: dict[str, Worker] = {}
        self._lock = threading.RLock()

    def register(self, worker: Worker) -> str:
        """Register a new worker. Returns the worker_id."""
        with self._lock:
            self._workers[worker.worker_id] = worker
            return worker.worker_id

    def get(self, worker_id: str) -> Worker | None:
        """Get a worker by ID. Returns None if not found."""
        with self._lock:
            return self._workers.get(worker_id)

    def heartbeat(self, worker_id: str) -> bool:
        """Update worker's last heartbeat. Returns False if not found."""
        with self._lock:
            worker = self._workers.get(worker_id)
            if worker is None:
                return False
            # Update worker with new heartbeat
            worker_dict = worker.model_dump()
            worker_dict["last_heartbeat"] = datetime.utcnow()
            self._workers[worker_id] = Worker(**worker_dict)
            return True

    def get_available_worker(self) -> Worker | None:
        """Get an available worker. Returns None if no workers available."""
        with self._lock:
            for worker in self._workers.values():
                if worker.status == "available":
                    # Check if worker is still active (has recent heartbeat)
                    if datetime.utcnow() - worker.last_heartbeat < WORKER_OFFLINE_TIMEOUT:
                        return worker
            return None

    def mark_busy(self, worker_id: str, job_id: str) -> bool:
        """Mark a worker as busy with a job. Returns False if not found."""
        with self._lock:
            worker = self._workers.get(worker_id)
            if worker is None:
                return False
            worker_dict = worker.model_dump()
            worker_dict["status"] = "busy"
            worker_dict["current_job_id"] = job_id
            self._workers[worker_id] = Worker(**worker_dict)
            return True

    def mark_available(self, worker_id: str) -> bool:
        """Mark a worker as available. Returns False if not found."""
        with self._lock:
            worker = self._workers.get(worker_id)
            if worker is None:
                return False
            worker_dict = worker.model_dump()
            worker_dict["status"] = "available"
            worker_dict["current_job_id"] = None
            self._workers[worker_id] = Worker(**worker_dict)
            return True

    def list(self) -> list[Worker]:
        """List all workers."""
        with self._lock:
            return list(self._workers.values())

    def delete(self, worker_id: str) -> bool:
        """Delete a worker. Returns True if deleted, False if not found."""
        with self._lock:
            if worker_id in self._workers:
                del self._workers[worker_id]
                return True
            return False

    def clear(self) -> None:
        """Clear all workers (useful for testing)."""
        with self._lock:
            self._workers.clear()


class JobStore:
    """Thread-safe in-memory storage for jobs."""

    def __init__(self):
        self._jobs: dict[str, Job] = {}
        self._queue: list[str] = []  # FIFO queue of job_ids
        self._lock = threading.RLock()

    def submit(self, job: Job) -> str:
        """Submit a new job to the queue. Returns the job_id."""
        with self._lock:
            self._jobs[job.job_id] = job
            self._queue.append(job.job_id)
            return job.job_id

    def get(self, job_id: str) -> Job | None:
        """Get a job by ID. Returns None if not found."""
        with self._lock:
            return self._jobs.get(job_id)

    def get_next_job(self) -> Job | None:
        """Get the next queued job. Returns None if queue is empty."""
        with self._lock:
            # Find first queued job in FIFO order
            for job_id in self._queue:
                job = self._jobs.get(job_id)
                if job and job.status == "queued":
                    return job
            return None

    def assign_job(self, job_id: str, worker_id: str) -> bool:
        """Assign a job to a worker. Returns False if job not found."""
        with self._lock:
            job = self._jobs.get(job_id)
            if job is None:
                return False
            job_dict = job.model_dump()
            job_dict["status"] = "assigned"
            job_dict["worker_id"] = worker_id
            job_dict["started_at"] = datetime.utcnow()
            self._jobs[job_id] = Job(**job_dict)
            return True

    def update_status(self, job_id: str, status: str) -> bool:
        """Update a job's status. Returns False if job not found."""
        with self._lock:
            job = self._jobs.get(job_id)
            if job is None:
                return False
            job_dict = job.model_dump()
            job_dict["status"] = status
            self._jobs[job_id] = Job(**job_dict)
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
        with self._lock:
            job = self._jobs.get(job_id)
            if job is None:
                return False
            job_dict = job.model_dump()
            job_dict["status"] = status
            job_dict["completed_at"] = datetime.utcnow()
            job_dict["attestation"] = attestation
            job_dict["service_id"] = service_id
            job_dict["error"] = error
            self._jobs[job_id] = Job(**job_dict)
            # Remove from queue
            if job_id in self._queue:
                self._queue.remove(job_id)
            return True

    def list(self, status: str | None = None) -> list[Job]:
        """List all jobs, optionally filtered by status."""
        with self._lock:
            if status:
                return [j for j in self._jobs.values() if j.status == status]
            return list(self._jobs.values())

    def delete(self, job_id: str) -> bool:
        """Delete a job. Returns True if deleted, False if not found."""
        with self._lock:
            if job_id in self._jobs:
                del self._jobs[job_id]
                if job_id in self._queue:
                    self._queue.remove(job_id)
                return True
            return False

    def clear(self) -> None:
        """Clear all jobs (useful for testing)."""
        with self._lock:
            self._jobs.clear()
            self._queue.clear()


# Global store instances
worker_store = WorkerStore()
job_store = JobStore()


# How long before an agent is considered offline
AGENT_OFFLINE_TIMEOUT = timedelta(minutes=5)


class AgentStore:
    """Thread-safe in-memory storage for launcher agents."""

    def __init__(self):
        self._agents: dict[str, LauncherAgent] = {}
        self._vm_name_index: dict[str, str] = {}  # vm_name -> agent_id
        self._lock = threading.RLock()

    def register(self, agent: LauncherAgent) -> str:
        """Register a new agent. Returns the agent_id."""
        with self._lock:
            self._agents[agent.agent_id] = agent
            self._vm_name_index[agent.vm_name] = agent.agent_id
            return agent.agent_id

    def get(self, agent_id: str) -> LauncherAgent | None:
        """Get an agent by ID. Returns None if not found."""
        with self._lock:
            return self._agents.get(agent_id)

    def get_by_vm_name(self, vm_name: str) -> LauncherAgent | None:
        """Get an agent by VM name. Returns None if not found."""
        with self._lock:
            agent_id = self._vm_name_index.get(vm_name)
            if agent_id:
                return self._agents.get(agent_id)
            return None

    def heartbeat(self, agent_id: str) -> bool:
        """Update agent's last heartbeat. Returns False if not found."""
        with self._lock:
            agent = self._agents.get(agent_id)
            if agent is None:
                return False
            agent_dict = agent.model_dump()
            agent_dict["last_heartbeat"] = datetime.utcnow()
            self._agents[agent_id] = LauncherAgent(**agent_dict)
            return True

    def update_status(
        self,
        agent_id: str,
        status: str,
        deployment_id: str | None = None,
        error: str | None = None,
    ) -> bool:
        """Update agent's status. Returns False if not found."""
        with self._lock:
            agent = self._agents.get(agent_id)
            if agent is None:
                return False
            agent_dict = agent.model_dump()
            agent_dict["status"] = status
            if deployment_id is not None:
                agent_dict["current_deployment_id"] = deployment_id
            agent_dict["last_heartbeat"] = datetime.utcnow()
            self._agents[agent_id] = LauncherAgent(**agent_dict)
            return True

    def set_deployment(self, agent_id: str, deployment_id: str | None) -> bool:
        """Set or clear the agent's current deployment. Returns False if not found."""
        with self._lock:
            agent = self._agents.get(agent_id)
            if agent is None:
                return False
            agent_dict = agent.model_dump()
            agent_dict["current_deployment_id"] = deployment_id
            self._agents[agent_id] = LauncherAgent(**agent_dict)
            return True

    def list(self, filters: dict | None = None) -> list[LauncherAgent]:
        """List all agents, optionally filtered."""
        with self._lock:
            agents = list(self._agents.values())

        if not filters:
            return agents

        result = agents

        # Filter by status
        if filters.get("status"):
            result = [a for a in result if a.status == filters["status"]]

        # Filter by vm_name (partial match)
        if filters.get("vm_name"):
            vm_name_filter = filters["vm_name"].lower()
            result = [a for a in result if vm_name_filter in a.vm_name.lower()]

        return result

    def delete(self, agent_id: str) -> bool:
        """Delete an agent. Returns True if deleted, False if not found."""
        with self._lock:
            if agent_id in self._agents:
                agent = self._agents[agent_id]
                # Clean up vm_name index
                if self._vm_name_index.get(agent.vm_name) == agent_id:
                    del self._vm_name_index[agent.vm_name]
                del self._agents[agent_id]
                return True
            return False

    def get_available(self, require_verified: bool = True) -> LauncherAgent | None:
        """Get an available (undeployed, verified) agent. Returns None if none available."""
        with self._lock:
            for agent in self._agents.values():
                if agent.status == "undeployed":
                    # Check if agent is still active (has recent heartbeat)
                    if datetime.utcnow() - agent.last_heartbeat < AGENT_OFFLINE_TIMEOUT:
                        # Only return verified agents by default
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
        with self._lock:
            agent = self._agents.get(agent_id)
            if agent is None:
                return False
            agent_dict = agent.model_dump()
            agent_dict["verified"] = verified
            agent_dict["verification_error"] = error
            self._agents[agent_id] = LauncherAgent(**agent_dict)
            return True

    def update_health(
        self,
        agent_id: str,
        health_status: str,
        service_url: str | None = None,
        health_endpoint: str | None = None,
    ) -> bool:
        """Update agent's health status. Returns False if not found."""
        with self._lock:
            agent = self._agents.get(agent_id)
            if agent is None:
                return False
            agent_dict = agent.model_dump()
            agent_dict["health_status"] = health_status
            agent_dict["last_health_check"] = datetime.utcnow()

            # Track when agent became unhealthy
            if health_status == "unhealthy":
                if agent.health_status != "unhealthy":
                    # Just became unhealthy
                    agent_dict["unhealthy_since"] = datetime.utcnow()
            else:
                # Healthy or unknown - clear unhealthy timestamp
                agent_dict["unhealthy_since"] = None

            if service_url is not None:
                agent_dict["service_url"] = service_url
            if health_endpoint is not None:
                agent_dict["health_endpoint"] = health_endpoint

            self._agents[agent_id] = LauncherAgent(**agent_dict)
            return True

    def update_tunnel_info(
        self,
        agent_id: str,
        tunnel_id: str,
        hostname: str,
        tunnel_token: str | None = None,
    ) -> bool:
        """Update agent's Cloudflare tunnel info. Returns False if not found."""
        with self._lock:
            agent = self._agents.get(agent_id)
            if agent is None:
                return False
            agent_dict = agent.model_dump()
            agent_dict["tunnel_id"] = tunnel_id
            agent_dict["hostname"] = hostname
            if tunnel_token:
                agent_dict["tunnel_token"] = tunnel_token
            agent_dict["tunnel_error"] = None  # Clear any previous error
            self._agents[agent_id] = LauncherAgent(**agent_dict)
            return True

    def update_tunnel_error(self, agent_id: str, error: str) -> bool:
        """Store tunnel creation error on agent. Returns False if not found."""
        with self._lock:
            agent = self._agents.get(agent_id)
            if agent is None:
                return False
            agent_dict = agent.model_dump()
            agent_dict["tunnel_error"] = error
            self._agents[agent_id] = LauncherAgent(**agent_dict)
            return True

    def get_deployed_agents(self) -> list[LauncherAgent]:
        """Get all deployed agents for health checking."""
        with self._lock:
            return [a for a in self._agents.values() if a.status == "deployed"]

    def get_unhealthy_agents(self, unhealthy_timeout: timedelta) -> list[LauncherAgent]:
        """Get agents that have been unhealthy longer than the timeout."""
        with self._lock:
            now = datetime.utcnow()
            unhealthy = []
            for agent in self._agents.values():
                if agent.status == "deployed" and agent.unhealthy_since:
                    if now - agent.unhealthy_since > unhealthy_timeout:
                        unhealthy.append(agent)
            return unhealthy

    def reset_for_reassignment(self, agent_id: str) -> bool:
        """Reset an agent to undeployed state for reassignment. Returns False if not found."""
        with self._lock:
            agent = self._agents.get(agent_id)
            if agent is None:
                return False
            agent_dict = agent.model_dump()
            agent_dict["status"] = "undeployed"
            agent_dict["current_deployment_id"] = None
            agent_dict["service_url"] = None
            agent_dict["health_status"] = "unknown"
            agent_dict["last_health_check"] = None
            agent_dict["unhealthy_since"] = None
            self._agents[agent_id] = LauncherAgent(**agent_dict)
            return True

    def update_attestation_status(
        self,
        agent_id: str,
        attestation_valid: bool,
        error: str | None = None,
        intel_ta_token: str | None = None,
    ) -> bool:
        """Update agent's attestation status. Returns False if not found."""
        with self._lock:
            agent = self._agents.get(agent_id)
            if agent is None:
                return False
            agent_dict = agent.model_dump()
            agent_dict["last_attestation_check"] = datetime.utcnow()
            agent_dict["attestation_valid"] = attestation_valid
            agent_dict["attestation_error"] = error
            if intel_ta_token is not None:
                agent_dict["intel_ta_token"] = intel_ta_token
            self._agents[agent_id] = LauncherAgent(**agent_dict)
            return True

    def update_attestation(
        self,
        agent_id: str,
        intel_ta_token: str,
        verified: bool,
        error: str | None = None,
    ) -> bool:
        """Update agent's attestation from poll. Returns False if not found."""
        with self._lock:
            agent = self._agents.get(agent_id)
            if agent is None:
                return False
            agent_dict = agent.model_dump()
            agent_dict["intel_ta_token"] = intel_ta_token
            agent_dict["verified"] = verified
            agent_dict["last_attestation_check"] = datetime.utcnow()
            agent_dict["attestation_valid"] = verified
            agent_dict["attestation_error"] = error
            self._agents[agent_id] = LauncherAgent(**agent_dict)
            return True

    def update_stats(self, agent_id: str, stats: dict) -> bool:
        """Update agent's system stats. Returns False if not found."""
        with self._lock:
            agent = self._agents.get(agent_id)
            if agent is None:
                return False
            agent_dict = agent.model_dump()
            agent_dict["stats"] = stats
            self._agents[agent_id] = LauncherAgent(**agent_dict)
            return True

    def mark_attestation_failed(
        self,
        agent_id: str,
        error: str,
        clear_tunnel: bool = True,
    ) -> bool:
        """Mark agent as attestation failed. Returns False if not found."""
        with self._lock:
            agent = self._agents.get(agent_id)
            if agent is None:
                return False
            agent_dict = agent.model_dump()
            agent_dict["status"] = "attestation_failed"
            agent_dict["attestation_valid"] = False
            agent_dict["attestation_error"] = error
            agent_dict["last_attestation_check"] = datetime.utcnow()
            if clear_tunnel:
                agent_dict["tunnel_id"] = None
                agent_dict["hostname"] = None
            self._agents[agent_id] = LauncherAgent(**agent_dict)
            return True

    def get_agents_for_attestation_check(self) -> list[LauncherAgent]:
        """Get deployed agents that need attestation check."""
        with self._lock:
            return [a for a in self._agents.values() if a.status == "deployed" and a.verified]

    def clear(self) -> None:
        """Clear all agents (useful for testing)."""
        with self._lock:
            self._agents.clear()
            self._vm_name_index.clear()


class DeploymentStore:
    """Thread-safe in-memory storage for deployments."""

    def __init__(self):
        self._deployments: dict[str, Deployment] = {}
        self._agent_deployments: dict[str, list[str]] = {}  # agent_id -> [deployment_ids]
        self._lock = threading.RLock()

    def create(self, deployment: Deployment) -> str:
        """Create a new deployment. Returns the deployment_id."""
        with self._lock:
            self._deployments[deployment.deployment_id] = deployment
            # Track deployments by agent
            if deployment.agent_id:
                if deployment.agent_id not in self._agent_deployments:
                    self._agent_deployments[deployment.agent_id] = []
                self._agent_deployments[deployment.agent_id].append(deployment.deployment_id)
            return deployment.deployment_id

    def get(self, deployment_id: str) -> Deployment | None:
        """Get a deployment by ID. Returns None if not found."""
        with self._lock:
            return self._deployments.get(deployment_id)

    def get_pending_for_agent(self, agent_id: str) -> Deployment | None:
        """Get the next pending deployment for an agent. Returns None if none pending."""
        with self._lock:
            deployment_ids = self._agent_deployments.get(agent_id, [])
            for dep_id in deployment_ids:
                deployment = self._deployments.get(dep_id)
                if deployment and deployment.status == "pending":
                    return deployment
            return None

    def assign(self, deployment_id: str, agent_id: str) -> bool:
        """Mark a deployment as assigned to an agent. Returns False if not found."""
        with self._lock:
            deployment = self._deployments.get(deployment_id)
            if deployment is None:
                return False
            dep_dict = deployment.model_dump()
            dep_dict["status"] = "assigned"
            dep_dict["agent_id"] = agent_id
            dep_dict["started_at"] = datetime.utcnow()
            self._deployments[deployment_id] = Deployment(**dep_dict)
            return True

    def update_status(
        self,
        deployment_id: str,
        status: str,
        error: str | None = None,
    ) -> bool:
        """Update a deployment's status. Returns False if not found."""
        with self._lock:
            deployment = self._deployments.get(deployment_id)
            if deployment is None:
                return False
            dep_dict = deployment.model_dump()
            dep_dict["status"] = status
            if error:
                dep_dict["error"] = error
            self._deployments[deployment_id] = Deployment(**dep_dict)
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
        with self._lock:
            deployment = self._deployments.get(deployment_id)
            if deployment is None:
                return False
            dep_dict = deployment.model_dump()
            dep_dict["status"] = status
            dep_dict["completed_at"] = datetime.utcnow()
            if service_id:
                dep_dict["service_id"] = service_id
            if attestation:
                dep_dict["attestation"] = attestation
            if error:
                dep_dict["error"] = error
            self._deployments[deployment_id] = Deployment(**dep_dict)
            return True

    def list(self, filters: dict | None = None) -> list[Deployment]:
        """List all deployments, optionally filtered."""
        with self._lock:
            deployments = list(self._deployments.values())

        if not filters:
            return deployments

        result = deployments

        # Filter by status
        if filters.get("status"):
            result = [d for d in result if d.status == filters["status"]]

        # Filter by agent_id
        if filters.get("agent_id"):
            result = [d for d in result if d.agent_id == filters["agent_id"]]

        return result

    def reassign(self, deployment_id: str, new_agent_id: str) -> bool:
        """Reassign a deployment to a different agent. Returns False if not found."""
        with self._lock:
            deployment = self._deployments.get(deployment_id)
            if deployment is None:
                return False

            old_agent_id = deployment.agent_id

            # Update deployment
            dep_dict = deployment.model_dump()
            dep_dict["agent_id"] = new_agent_id
            dep_dict["status"] = "pending"  # Reset to pending for new agent to pick up
            dep_dict["started_at"] = None
            dep_dict["completed_at"] = None
            dep_dict["error"] = None
            self._deployments[deployment_id] = Deployment(**dep_dict)

            # Update agent indexes
            if old_agent_id in self._agent_deployments:
                if deployment_id in self._agent_deployments[old_agent_id]:
                    self._agent_deployments[old_agent_id].remove(deployment_id)

            if new_agent_id not in self._agent_deployments:
                self._agent_deployments[new_agent_id] = []
            self._agent_deployments[new_agent_id].append(deployment_id)

            return True

    def mark_for_reassignment(self, deployment_id: str) -> bool:
        """Mark a deployment as needing reassignment. Returns False if not found."""
        with self._lock:
            deployment = self._deployments.get(deployment_id)
            if deployment is None:
                return False

            dep_dict = deployment.model_dump()
            dep_dict["status"] = "reassigning"
            dep_dict["error"] = "Agent unhealthy - pending reassignment"
            self._deployments[deployment_id] = Deployment(**dep_dict)
            return True

    def get_for_reassignment(self) -> list[Deployment]:
        """Get all deployments marked for reassignment."""
        with self._lock:
            return [d for d in self._deployments.values() if d.status == "reassigning"]

    def delete(self, deployment_id: str) -> bool:
        """Delete a deployment. Returns True if deleted, False if not found."""
        with self._lock:
            if deployment_id in self._deployments:
                deployment = self._deployments[deployment_id]
                # Clean up agent index
                if deployment.agent_id in self._agent_deployments:
                    if deployment_id in self._agent_deployments[deployment.agent_id]:
                        self._agent_deployments[deployment.agent_id].remove(deployment_id)
                del self._deployments[deployment_id]
                return True
            return False

    def clear(self) -> None:
        """Clear all deployments (useful for testing)."""
        with self._lock:
            self._deployments.clear()
            self._agent_deployments.clear()


class TrustedMrtdStore:
    """Thread-safe in-memory storage for trusted MRTD measurements."""

    def __init__(self):
        self._mrtds: dict[str, TrustedMrtd] = {}
        self._lock = threading.RLock()
        self._load_system_mrtds()

    def _load_system_mrtds(self):
        """Load hardcoded system MRTDs from environment variables.

        System MRTDs are locked and cannot be modified via API.
        """
        # Load agent MRTD
        agent_mrtd = os.environ.get("SYSTEM_AGENT_MRTD")
        if agent_mrtd:
            self._mrtds[agent_mrtd] = TrustedMrtd(
                mrtd=agent_mrtd,
                type=MrtdType.AGENT,
                locked=True,
                description="System agent launcher image",
            )
            logger.info(f"Loaded system agent MRTD: {agent_mrtd[:16]}...")

        # Load proxy MRTD
        proxy_mrtd = os.environ.get("SYSTEM_PROXY_MRTD")
        if proxy_mrtd:
            self._mrtds[proxy_mrtd] = TrustedMrtd(
                mrtd=proxy_mrtd,
                type=MrtdType.PROXY,
                locked=True,
                description="System cloudflared proxy image",
            )
            logger.info(f"Loaded system proxy MRTD: {proxy_mrtd[:16]}...")

    def add(self, trusted_mrtd: TrustedMrtd) -> str:
        """Add a trusted MRTD. Returns the MRTD value."""
        with self._lock:
            self._mrtds[trusted_mrtd.mrtd] = trusted_mrtd
            return trusted_mrtd.mrtd

    def get(self, mrtd: str) -> TrustedMrtd | None:
        """Get a trusted MRTD by value. Returns None if not found."""
        with self._lock:
            return self._mrtds.get(mrtd)

    def is_trusted(self, mrtd: str) -> bool:
        """Check if an MRTD is in the trusted list and active."""
        with self._lock:
            trusted = self._mrtds.get(mrtd)
            return trusted is not None and trusted.active

    def list(self, include_inactive: bool = False) -> list[TrustedMrtd]:
        """List all trusted MRTDs."""
        with self._lock:
            if include_inactive:
                return list(self._mrtds.values())
            return [m for m in self._mrtds.values() if m.active]

    def deactivate(self, mrtd: str) -> tuple[bool, str | None]:
        """Deactivate a trusted MRTD.

        Returns:
            Tuple of (success, error_message).
            - (True, None) if deactivated successfully
            - (False, None) if not found
            - (False, error_message) if locked
        """
        with self._lock:
            trusted = self._mrtds.get(mrtd)
            if trusted is None:
                return False, None
            if trusted.locked:
                return False, "Cannot deactivate system MRTD"
            mrtd_dict = trusted.model_dump()
            mrtd_dict["active"] = False
            self._mrtds[mrtd] = TrustedMrtd(**mrtd_dict)
            return True, None

    def activate(self, mrtd: str) -> bool:
        """Activate a trusted MRTD. Returns False if not found."""
        with self._lock:
            trusted = self._mrtds.get(mrtd)
            if trusted is None:
                return False
            mrtd_dict = trusted.model_dump()
            mrtd_dict["active"] = True
            self._mrtds[mrtd] = TrustedMrtd(**mrtd_dict)
            return True

    def delete(self, mrtd: str) -> tuple[bool, str | None]:
        """Delete a trusted MRTD.

        Returns:
            Tuple of (success, error_message).
            - (True, None) if deleted successfully
            - (False, None) if not found
            - (False, error_message) if locked
        """
        with self._lock:
            if mrtd in self._mrtds:
                if self._mrtds[mrtd].locked:
                    return False, "Cannot delete system MRTD"
                del self._mrtds[mrtd]
                return True, None
            return False, None

    def clear(self) -> None:
        """Clear all trusted MRTDs (useful for testing)."""
        with self._lock:
            self._mrtds.clear()


# Global store instances
agent_store = AgentStore()
deployment_store = DeploymentStore()
trusted_mrtd_store = TrustedMrtdStore()


# ==============================================================================
# App Catalog Storage - Apps and their versions
# ==============================================================================


class AppStore:
    """Thread-safe in-memory storage for apps."""

    def __init__(self):
        self._apps: dict[str, App] = {}
        self._name_index: dict[str, str] = {}  # name -> app_id
        self._lock = threading.RLock()

    def register(self, app: App) -> str:
        """Register a new app. Returns the app_id."""
        with self._lock:
            self._apps[app.app_id] = app
            self._name_index[app.name] = app.app_id
            return app.app_id

    def get(self, app_id: str) -> App | None:
        """Get an app by ID. Returns None if not found."""
        with self._lock:
            return self._apps.get(app_id)

    def get_by_name(self, name: str) -> App | None:
        """Get an app by name. Returns None if not found."""
        with self._lock:
            app_id = self._name_index.get(name)
            if app_id:
                return self._apps.get(app_id)
            return None

    def list(self, filters: dict | None = None) -> list[App]:
        """List all apps, optionally filtered."""
        with self._lock:
            apps = list(self._apps.values())

        if not filters:
            return apps

        result = apps

        # Filter by name (partial match)
        if filters.get("name"):
            name_filter = filters["name"].lower()
            result = [a for a in result if name_filter in a.name.lower()]

        # Filter by tags (any match)
        if filters.get("tags"):
            filter_tags = set(filters["tags"])
            result = [a for a in result if filter_tags & set(a.tags)]

        return result

    def update(self, app_id: str, **updates) -> App | None:
        """Update an app's fields. Returns updated app or None if not found."""
        with self._lock:
            app = self._apps.get(app_id)
            if app is None:
                return None

            app_dict = app.model_dump()
            app_dict.update(updates)
            updated_app = App(**app_dict)
            self._apps[app_id] = updated_app
            return updated_app

    def delete(self, app_id: str) -> bool:
        """Delete an app. Returns True if deleted, False if not found."""
        with self._lock:
            if app_id in self._apps:
                app = self._apps[app_id]
                if self._name_index.get(app.name) == app_id:
                    del self._name_index[app.name]
                del self._apps[app_id]
                return True
            return False

    def clear(self) -> None:
        """Clear all apps (useful for testing)."""
        with self._lock:
            self._apps.clear()
            self._name_index.clear()


class AppVersionStore:
    """Thread-safe in-memory storage for app versions."""

    def __init__(self):
        self._versions: dict[str, AppVersion] = {}
        # Index: app_name -> [version_ids] (ordered by published_at)
        self._app_versions: dict[str, list[str]] = {}
        # Index: (app_name, version) -> version_id
        self._version_index: dict[tuple[str, str], str] = {}
        self._lock = threading.RLock()

    def create(self, version: AppVersion) -> str:
        """Create a new app version. Returns the version_id."""
        with self._lock:
            self._versions[version.version_id] = version

            # Update app versions index
            if version.app_name not in self._app_versions:
                self._app_versions[version.app_name] = []
            self._app_versions[version.app_name].append(version.version_id)

            # Update version index
            self._version_index[(version.app_name, version.version)] = version.version_id

            return version.version_id

    def get(self, version_id: str) -> AppVersion | None:
        """Get a version by ID. Returns None if not found."""
        with self._lock:
            return self._versions.get(version_id)

    def get_by_version(self, app_name: str, version: str) -> AppVersion | None:
        """Get a specific version of an app. Returns None if not found."""
        with self._lock:
            version_id = self._version_index.get((app_name, version))
            if version_id:
                return self._versions.get(version_id)
            return None

    def list_for_app(self, app_name: str) -> list[AppVersion]:
        """List all versions for an app, ordered by published_at (newest first)."""
        with self._lock:
            version_ids = self._app_versions.get(app_name, [])
            versions = [self._versions[vid] for vid in version_ids if vid in self._versions]
            return sorted(versions, key=lambda v: v.published_at, reverse=True)

    def update(self, version_id: str, **updates) -> AppVersion | None:
        """Update a version's fields. Returns updated version or None if not found."""
        with self._lock:
            version = self._versions.get(version_id)
            if version is None:
                return None

            version_dict = version.model_dump()
            version_dict.update(updates)
            updated_version = AppVersion(**version_dict)
            self._versions[version_id] = updated_version
            return updated_version

    def update_status(
        self,
        version_id: str,
        status: str,
        mrtd: str | None = None,
        attestation: dict | None = None,
        rejection_reason: str | None = None,
    ) -> bool:
        """Update version status and attestation. Returns False if not found."""
        with self._lock:
            version = self._versions.get(version_id)
            if version is None:
                return False

            version_dict = version.model_dump()
            version_dict["status"] = status
            if mrtd is not None:
                version_dict["mrtd"] = mrtd
            if attestation is not None:
                version_dict["attestation"] = attestation
            if rejection_reason is not None:
                version_dict["rejection_reason"] = rejection_reason

            self._versions[version_id] = AppVersion(**version_dict)
            return True

    def delete(self, version_id: str) -> bool:
        """Delete a version. Returns True if deleted, False if not found."""
        with self._lock:
            if version_id in self._versions:
                version = self._versions[version_id]

                # Clean up indexes
                if version.app_name in self._app_versions:
                    if version_id in self._app_versions[version.app_name]:
                        self._app_versions[version.app_name].remove(version_id)

                key = (version.app_name, version.version)
                if key in self._version_index:
                    del self._version_index[key]

                del self._versions[version_id]
                return True
            return False

    def clear(self) -> None:
        """Clear all versions (useful for testing)."""
        with self._lock:
            self._versions.clear()
            self._app_versions.clear()
            self._version_index.clear()


# Log level priority for filtering
LOG_LEVEL_PRIORITY = {
    LogLevel.DEBUG: 0,
    LogLevel.INFO: 1,
    LogLevel.WARNING: 2,
    LogLevel.ERROR: 3,
}

# Maximum number of logs to keep in memory per agent
MAX_LOGS_PER_AGENT = 1000


class LogStore:
    """Thread-safe in-memory storage for agent and container logs.

    Keeps recent logs in memory with automatic cleanup of old entries.
    Logs are indexed by agent_id for efficient retrieval.
    """

    def __init__(self, max_logs_per_agent: int = MAX_LOGS_PER_AGENT):
        self._logs: dict[str, list[LogEntry]] = {}  # agent_id -> [logs]
        self._lock = threading.Lock()
        self._max_logs_per_agent = max_logs_per_agent

    def add(self, log: LogEntry) -> str:
        """Add a log entry. Returns the log_id."""
        with self._lock:
            if log.agent_id not in self._logs:
                self._logs[log.agent_id] = []

            self._logs[log.agent_id].append(log)

            # Trim old logs if over limit
            if len(self._logs[log.agent_id]) > self._max_logs_per_agent:
                # Keep the most recent logs
                self._logs[log.agent_id] = self._logs[log.agent_id][-self._max_logs_per_agent :]

            return log.log_id

    def add_batch(self, agent_id: str, logs: list[dict]) -> tuple[int, int]:
        """Add a batch of logs. Returns (received, stored) count."""
        received = len(logs)
        stored = 0

        with self._lock:
            if agent_id not in self._logs:
                self._logs[agent_id] = []

            for log_dict in logs:
                try:
                    # Parse log level
                    level_str = log_dict.get("level", "info").lower()
                    try:
                        level = LogLevel(level_str)
                    except ValueError:
                        level = LogLevel.INFO

                    # Parse source
                    source_str = log_dict.get("source", "agent").lower()
                    try:
                        source = LogSource(source_str)
                    except ValueError:
                        source = LogSource.AGENT

                    # Create log entry
                    log = LogEntry(
                        agent_id=agent_id,
                        source=source,
                        container_name=log_dict.get("container_name"),
                        level=level,
                        message=log_dict.get("message", ""),
                        timestamp=datetime.fromisoformat(log_dict["timestamp"])
                        if "timestamp" in log_dict
                        else datetime.utcnow(),
                        metadata=log_dict.get("metadata", {}),
                    )
                    self._logs[agent_id].append(log)
                    stored += 1
                except Exception as e:
                    logger.warning(f"Failed to parse log entry: {e}")
                    continue

            # Trim old logs if over limit
            if len(self._logs[agent_id]) > self._max_logs_per_agent:
                self._logs[agent_id] = self._logs[agent_id][-self._max_logs_per_agent :]

        return received, stored

    def query(
        self,
        agent_id: str | None = None,
        source: LogSource | None = None,
        container_name: str | None = None,
        min_level: LogLevel = LogLevel.INFO,
        since: datetime | None = None,
        until: datetime | None = None,
        limit: int = 100,
    ) -> list[LogEntry]:
        """Query logs with filters."""
        min_priority = LOG_LEVEL_PRIORITY.get(min_level, 1)
        result = []

        # Strip timezone info to avoid comparison errors with naive datetimes
        if since and since.tzinfo is not None:
            since = since.replace(tzinfo=None)
        if until and until.tzinfo is not None:
            until = until.replace(tzinfo=None)

        with self._lock:
            # Determine which agents to search
            if agent_id:
                agent_ids = [agent_id] if agent_id in self._logs else []
            else:
                agent_ids = list(self._logs.keys())

            for aid in agent_ids:
                for log in self._logs.get(aid, []):
                    # Filter by level
                    if LOG_LEVEL_PRIORITY.get(log.level, 1) < min_priority:
                        continue

                    # Filter by source
                    if source and log.source != source:
                        continue

                    # Filter by container name
                    if container_name and log.container_name != container_name:
                        continue

                    # Filter by time range
                    if since and log.timestamp < since:
                        continue
                    if until and log.timestamp > until:
                        continue

                    result.append(log)

            # Sort by timestamp descending (most recent first) and limit
            # Normalize to naive datetime for comparison (some logs may be tz-aware, others naive)
            result.sort(key=lambda x: x.timestamp.replace(tzinfo=None), reverse=True)
            return result[:limit]

    def get_agent_logs(self, agent_id: str, limit: int = 100) -> list[LogEntry]:
        """Get recent logs for a specific agent."""
        with self._lock:
            logs = self._logs.get(agent_id, [])
            # Return most recent logs first
            return list(reversed(logs[-limit:]))

    def clear_agent_logs(self, agent_id: str) -> int:
        """Clear all logs for an agent. Returns count cleared."""
        with self._lock:
            if agent_id in self._logs:
                count = len(self._logs[agent_id])
                del self._logs[agent_id]
                return count
            return 0

    def clear(self) -> None:
        """Clear all logs."""
        with self._lock:
            self._logs.clear()


# Global app store instances
app_store = AppStore()
app_version_store = AppVersionStore()
log_store = LogStore()
