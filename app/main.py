"""EasyEnclave Discovery Service - FastAPI Application."""

from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from pathlib import Path

import httpx
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from .ita import verify_attestation_token
from .models import (
    AgentDeployedRequest,
    AgentListResponse,
    AgentPollResponse,
    AgentRegistrationRequest,
    AgentRegistrationResponse,
    AgentStatusRequest,
    Deployment,
    DeploymentCreateRequest,
    DeploymentCreateResponse,
    DeploymentListResponse,
    HealthResponse,
    Job,
    JobCompleteRequest,
    JobPollResponse,
    JobStatusResponse,
    JobSubmitRequest,
    JobSubmitResponse,
    LauncherAgent,
    ServiceListResponse,
    ServiceRegistration,
    ServiceRegistrationRequest,
    TrustedMrtd,
    TrustedMrtdCreateRequest,
    TrustedMrtdListResponse,
    VerificationResponse,
    Worker,
    WorkerRegistrationRequest,
    WorkerRegistrationResponse,
)
from .storage import (
    agent_store,
    deployment_store,
    job_store,
    store,
    trusted_mrtd_store,
    worker_store,
)

logger = logging.getLogger(__name__)

# Health check interval in seconds
HEALTH_CHECK_INTERVAL = 60

# Agent health check settings
AGENT_HEALTH_CHECK_INTERVAL = 30  # Check agents every 30 seconds
AGENT_UNHEALTHY_TIMEOUT = timedelta(minutes=5)  # Reassign after 5 minutes unhealthy


async def check_service_health(service: ServiceRegistration) -> str:
    """Check health of a single service. Returns health status."""
    for _env, url in service.endpoints.items():
        try:
            health_url = url.rstrip("/") + "/health"
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.get(health_url)
                if response.status_code == 200:
                    return "healthy"
        except Exception:
            continue
    return "unhealthy"


async def background_health_checker():
    """Background task to periodically check health of all services."""
    while True:
        try:
            services = store.get_all_for_health_check()
            for service in services:
                try:
                    status = await check_service_health(service)
                    store.update(
                        service.service_id,
                        health_status=status,
                        last_health_check=datetime.utcnow(),
                    )
                except Exception as e:
                    logger.warning(f"Health check failed for {service.name}: {e}")
        except Exception as e:
            logger.error(f"Background health checker error: {e}")

        await asyncio.sleep(HEALTH_CHECK_INTERVAL)


async def check_agent_health(agent: LauncherAgent) -> str:
    """Check health of a deployed agent's service. Returns health status."""
    if not agent.service_url:
        return "unknown"

    try:
        health_url = agent.service_url.rstrip("/") + agent.health_endpoint
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(health_url)
            if response.status_code == 200:
                return "healthy"
    except Exception:
        pass
    return "unhealthy"


async def background_agent_health_checker():
    """Background task to check health of deployed agents and handle reassignment."""
    while True:
        try:
            # Check health of all deployed agents
            deployed_agents = agent_store.get_deployed_agents()
            for agent in deployed_agents:
                try:
                    status = await check_agent_health(agent)
                    agent_store.update_health(agent.agent_id, status)
                    logger.debug(f"Agent {agent.agent_id} health: {status}")
                except Exception as e:
                    logger.warning(f"Health check failed for agent {agent.agent_id}: {e}")

            # Check for agents that have been unhealthy too long
            unhealthy_agents = agent_store.get_unhealthy_agents(AGENT_UNHEALTHY_TIMEOUT)
            for agent in unhealthy_agents:
                try:
                    await handle_agent_reassignment(agent)
                except Exception as e:
                    logger.error(f"Reassignment failed for agent {agent.agent_id}: {e}")

            # Try to reassign pending deployments to available agents
            await process_pending_reassignments()

        except Exception as e:
            logger.error(f"Background agent health checker error: {e}")

        await asyncio.sleep(AGENT_HEALTH_CHECK_INTERVAL)


async def handle_agent_reassignment(agent: LauncherAgent):
    """Handle reassignment of an unhealthy agent's deployment."""
    deployment_id = agent.current_deployment_id
    if not deployment_id:
        # No deployment to reassign, just reset the agent
        agent_store.reset_for_reassignment(agent.agent_id)
        logger.info(f"Reset unhealthy agent {agent.agent_id} (no deployment)")
        return

    # Mark deployment for reassignment
    deployment_store.mark_for_reassignment(deployment_id)
    logger.warning(
        f"Marked deployment {deployment_id} for reassignment "
        f"(agent {agent.agent_id} unhealthy for >{AGENT_UNHEALTHY_TIMEOUT})"
    )

    # Reset the old agent
    agent_store.reset_for_reassignment(agent.agent_id)


async def process_pending_reassignments():
    """Try to reassign deployments marked for reassignment to available agents."""
    deployments = deployment_store.get_for_reassignment()

    for deployment in deployments:
        # Find an available agent
        available_agent = agent_store.get_available()
        if available_agent:
            # Reassign the deployment
            deployment_store.reassign(deployment.deployment_id, available_agent.agent_id)
            logger.info(
                f"Reassigned deployment {deployment.deployment_id} "
                f"to agent {available_agent.agent_id}"
            )
        else:
            logger.debug(
                f"No available agent for deployment {deployment.deployment_id} - will retry"
            )


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage application lifespan - start background tasks."""
    # Start background health checkers
    service_health_task = asyncio.create_task(background_health_checker())
    agent_health_task = asyncio.create_task(background_agent_health_checker())
    logger.info("Started background health checkers (services + agents)")
    yield
    # Shutdown
    service_health_task.cancel()
    agent_health_task.cancel()
    try:
        await service_health_task
    except asyncio.CancelledError:
        pass
    try:
        await agent_health_task
    except asyncio.CancelledError:
        pass

# Create FastAPI app
app = FastAPI(
    title="EasyEnclave Discovery Service",
    description="Confidential discovery service for TDX-attested applications",
    version="0.1.0",
    lifespan=lifespan,
)

# CORS middleware - allow requests from easyenclave.com
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://easyenclave.com",
        "https://www.easyenclave.com",
        "http://localhost:8080",  # Local development
        "http://127.0.0.1:8080",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Static files directory
STATIC_DIR = Path(__file__).parent / "static"


# Health check endpoint (required by launcher)
@app.get("/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint."""
    return HealthResponse(
        status="healthy",
        timestamp=datetime.utcnow(),
    )


# API v1 endpoints
@app.post("/api/v1/register", response_model=ServiceRegistration)
async def register_service(request: ServiceRegistrationRequest):
    """Register a new service with the discovery service.

    Requires:
    - Valid MRTD (TDX measurement)
    - Valid Intel Trust Authority token
    - At least one endpoint that responds to health checks
    """
    # Require attestation
    if not request.mrtd:
        raise HTTPException(
            status_code=400,
            detail="Registration requires MRTD (TDX measurement)"
        )
    if not request.intel_ta_token:
        raise HTTPException(
            status_code=400,
            detail="Registration requires Intel Trust Authority token"
        )

    # Verify at least one endpoint is healthy
    if not request.endpoints:
        raise HTTPException(
            status_code=400,
            detail="Registration requires at least one endpoint"
        )

    health_status = "unknown"
    health_error = None

    for _env, url in request.endpoints.items():
        try:
            # Try /health endpoint
            health_url = url.rstrip('/') + '/health'
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.get(health_url)
                if response.status_code == 200:
                    health_status = "healthy"
                    break
        except Exception as e:
            health_error = str(e)
            continue

    if health_status != "healthy":
        raise HTTPException(
            status_code=400,
            detail=f"No endpoint responded to health check. Last error: {health_error}"
        )

    service = ServiceRegistration.from_request(request)
    service.health_status = health_status
    service.last_health_check = datetime.utcnow()

    # Upsert: update existing service with same name, or create new
    service_id, is_new = store.upsert(service)

    # Return the stored service (may have preserved service_id if updated)
    stored_service = store.get(service_id)
    logger.info(
        f"Service {'created' if is_new else 'updated'}: {service.name} ({service_id})"
    )
    return stored_service


@app.get("/api/v1/services", response_model=ServiceListResponse)
async def list_services(
    name: str | None = Query(None, description="Filter by name (partial match)"),
    tags: str | None = Query(None, description="Filter by tags (comma-separated)"),
    environment: str | None = Query(None, description="Filter by environment"),
    mrtd: str | None = Query(None, description="Filter by MRTD (exact match)"),
    health_status: str | None = Query(None, description="Filter by health status"),
    q: str | None = Query(None, description="Search query"),
    include_down: bool = Query(
        False, description="Include services that have been down for extended period"
    ),
):
    """List all registered services with optional filters.

    By default, services that have been unhealthy for more than 1 hour are hidden.
    Use include_down=true to show all services.
    """
    # If search query provided, use search
    if q:
        services = store.search(q)
        # Filter out timed-out services from search results too
        if not include_down:
            services = [s for s in services if not store._is_timed_out(s)]
    else:
        # Build filters dict
        filters = {}
        if name:
            filters["name"] = name
        if tags:
            filters["tags"] = [t.strip() for t in tags.split(",")]
        if environment:
            filters["environment"] = environment
        if mrtd:
            filters["mrtd"] = mrtd
        if health_status:
            filters["health_status"] = health_status

        services = store.list(filters if filters else None, include_down=include_down)

    return ServiceListResponse(services=services, total=len(services))


@app.get("/api/v1/services/{service_id}", response_model=ServiceRegistration)
async def get_service(service_id: str):
    """Get details for a specific service."""
    service = store.get(service_id)
    if service is None:
        raise HTTPException(status_code=404, detail="Service not found")
    return service


@app.delete("/api/v1/services/{service_id}")
async def delete_service(service_id: str):
    """Deregister a service."""
    if not store.delete(service_id):
        raise HTTPException(status_code=404, detail="Service not found")
    return {"status": "deleted", "service_id": service_id}


@app.get("/api/v1/services/{service_id}/verify", response_model=VerificationResponse)
async def verify_service(service_id: str):
    """Verify a service's attestation via Intel Trust Authority."""
    service = store.get(service_id)
    if service is None:
        raise HTTPException(status_code=404, detail="Service not found")

    if not service.intel_ta_token:
        return VerificationResponse(
            service_id=service_id,
            verified=False,
            verification_time=datetime.utcnow(),
            error="Service has no Intel Trust Authority token",
        )

    result = await verify_attestation_token(service.intel_ta_token)
    return VerificationResponse(
        service_id=service_id,
        verified=result["verified"],
        verification_time=result["verification_time"],
        details=result["details"],
        error=result["error"],
    )


# ==============================================================================
# Job Queue API - Workers and Jobs
# ==============================================================================


@app.post("/api/v1/workers/register", response_model=WorkerRegistrationResponse)
async def register_worker(request: WorkerRegistrationRequest):
    """Register a standby worker with the service.

    Workers are TDX VMs that poll for jobs and execute workloads.
    Requires valid TDX attestation to register.
    """
    if not request.attestation:
        raise HTTPException(
            status_code=400,
            detail="Registration requires attestation"
        )

    worker = Worker(
        attestation=request.attestation,
        capabilities=request.capabilities,
    )
    worker_id = worker_store.register(worker)
    logger.info(f"Worker registered: {worker_id}")

    return WorkerRegistrationResponse(worker_id=worker_id, poll_interval=30)


@app.get("/api/v1/jobs/poll", response_model=JobPollResponse)
async def poll_for_job(worker_id: str = Query(..., description="Worker ID")):
    """Poll for available jobs.

    Workers call this endpoint periodically to check for jobs.
    If a job is available, it's assigned to the worker and returned.
    """
    # Update worker heartbeat
    if not worker_store.heartbeat(worker_id):
        raise HTTPException(status_code=404, detail="Worker not found")

    # Check if there's a job available
    job = job_store.get_next_job()
    if job is None:
        return JobPollResponse()

    # Assign job to worker
    job_store.assign_job(job.job_id, worker_id)
    worker_store.mark_busy(worker_id, job.job_id)
    logger.info(f"Job {job.job_id} assigned to worker {worker_id}")

    return JobPollResponse(
        job_id=job.job_id,
        compose=job.compose,
        build_context=job.build_context,
        config=job.config,
    )


@app.post("/api/v1/jobs/submit", response_model=JobSubmitResponse)
async def submit_job(request: JobSubmitRequest):
    """Submit a job to the queue.

    Jobs are picked up by standby workers for execution.
    """
    if not request.compose:
        raise HTTPException(
            status_code=400,
            detail="Job requires compose file (base64 encoded)"
        )

    job = Job(
        compose=request.compose,
        build_context=request.build_context,
        config=request.config,
    )
    job_id = job_store.submit(job)
    logger.info(f"Job submitted: {job_id}")

    return JobSubmitResponse(job_id=job_id, status="queued")


@app.post("/api/v1/jobs/{job_id}/complete")
async def complete_job(job_id: str, request: JobCompleteRequest):
    """Report job completion.

    Workers call this after executing a job to report results.
    """
    job = job_store.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Job not found")

    # Complete the job
    job_store.complete_job(
        job_id=job_id,
        status=request.status,
        attestation=request.attestation,
        service_id=request.service_id,
        error=request.error,
    )

    # Mark worker as available
    if job.worker_id:
        worker_store.mark_available(job.worker_id)

    logger.info(f"Job {job_id} completed with status: {request.status}")

    return {"status": "ok", "job_id": job_id}


@app.get("/api/v1/jobs/{job_id}", response_model=JobStatusResponse)
async def get_job_status(job_id: str):
    """Get job status and results."""
    job = job_store.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Job not found")

    return JobStatusResponse(
        job_id=job.job_id,
        status=job.status,
        submitted_at=job.submitted_at,
        started_at=job.started_at,
        completed_at=job.completed_at,
        attestation=job.attestation,
        service_id=job.service_id,
        error=job.error,
    )


# ==============================================================================
# Launcher Agent API - Agents register, poll, and report status
# ==============================================================================


@app.post("/api/v1/agents/register", response_model=AgentRegistrationResponse)
async def register_agent(request: AgentRegistrationRequest):
    """Register a launcher agent with the control plane.

    Launcher agents call this on boot to register themselves.
    Requires valid TDX attestation to register.
    The agent's MRTD is verified against the trusted MRTD list.
    """
    if not request.attestation:
        raise HTTPException(
            status_code=400,
            detail="Registration requires attestation"
        )

    if not request.vm_name:
        raise HTTPException(
            status_code=400,
            detail="Registration requires vm_name"
        )

    # Check if agent with this vm_name already exists
    existing = agent_store.get_by_vm_name(request.vm_name)
    if existing:
        # Update heartbeat and return existing agent
        agent_store.heartbeat(existing.agent_id)
        logger.info(f"Agent re-registered: {existing.agent_id} ({request.vm_name})")
        return AgentRegistrationResponse(agent_id=existing.agent_id, poll_interval=30)

    # Extract MRTD from attestation if present
    mrtd = ""
    if "tdx" in request.attestation:
        measurements = request.attestation["tdx"].get("measurements", {})
        mrtd = measurements.get("mrtd", "")
    intel_ta_token = request.attestation.get("tdx", {}).get("intel_ta_token")

    # Verify MRTD against trusted list
    verified = False
    verification_error = None
    if mrtd:
        if trusted_mrtd_store.is_trusted(mrtd):
            verified = True
            logger.info(f"Agent MRTD verified: {mrtd[:16]}...")
        else:
            verification_error = "MRTD not in trusted list"
            logger.warning(f"Agent MRTD not trusted: {mrtd[:16]}... ({request.vm_name})")
    else:
        verification_error = "No MRTD in attestation"
        logger.warning(f"Agent has no MRTD: {request.vm_name}")

    agent = LauncherAgent(
        vm_name=request.vm_name,
        attestation=request.attestation,
        mrtd=mrtd,
        intel_ta_token=intel_ta_token,
        version=request.version,
        status="undeployed",
        verified=verified,
        verification_error=verification_error,
    )
    agent_id = agent_store.register(agent)
    logger.info(
        f"Agent registered: {agent_id} ({request.vm_name}) verified={verified}"
    )

    return AgentRegistrationResponse(agent_id=agent_id, poll_interval=30)


@app.get("/api/v1/agents/{agent_id}/poll", response_model=AgentPollResponse)
async def poll_for_deployment(agent_id: str):
    """Poll for available deployments.

    Launcher agents call this periodically to check for work.
    If a deployment is available, it's returned for execution.
    Only verified agents receive deployments.
    """
    # Update heartbeat
    if not agent_store.heartbeat(agent_id):
        raise HTTPException(status_code=404, detail="Agent not found")

    # Check if agent is verified
    agent = agent_store.get(agent_id)
    if not agent.verified:
        # Unverified agents don't receive deployments
        logger.debug(f"Agent {agent_id} not verified - no deployment")
        return AgentPollResponse()

    # Check for pending deployment
    deployment = deployment_store.get_pending_for_agent(agent_id)
    if deployment is None:
        return AgentPollResponse()

    # Mark deployment as assigned
    deployment_store.assign(deployment.deployment_id, agent_id)
    agent_store.update_status(agent_id, "deploying", deployment.deployment_id)
    logger.info(f"Deployment {deployment.deployment_id} assigned to agent {agent_id}")

    return AgentPollResponse(
        deployment={
            "deployment_id": deployment.deployment_id,
            "compose": deployment.compose,
            "build_context": deployment.build_context,
            "config": deployment.config,
        }
    )


@app.post("/api/v1/agents/{agent_id}/status")
async def update_agent_status(agent_id: str, request: AgentStatusRequest):
    """Update agent status during deployment.

    Agents call this to report deployment progress.
    """
    agent = agent_store.get(agent_id)
    if agent is None:
        raise HTTPException(status_code=404, detail="Agent not found")

    # Update agent status
    agent_store.update_status(agent_id, request.status, request.deployment_id)

    # Update deployment status if error
    if request.status == "error" and request.error:
        deployment_store.complete(
            request.deployment_id,
            status="failed",
            error=request.error,
        )

    logger.info(f"Agent {agent_id} status: {request.status}")
    return {"status": "ok"}


@app.post("/api/v1/agents/{agent_id}/deployed")
async def agent_deployment_complete(agent_id: str, request: AgentDeployedRequest):
    """Report successful deployment completion.

    Agents call this after successfully deploying a workload.
    """
    agent = agent_store.get(agent_id)
    if agent is None:
        raise HTTPException(status_code=404, detail="Agent not found")

    # Get deployment to extract service_url for health checking
    deployment = deployment_store.get(request.deployment_id)
    service_url = None
    health_endpoint = "/health"
    if deployment:
        config = deployment.config or {}
        service_url = config.get("service_url")
        health_endpoint = config.get("health_endpoint", "/health")

    # Update agent status and health check info
    agent_store.update_status(agent_id, "deployed", request.deployment_id)
    agent_store.update_health(
        agent_id,
        health_status="healthy",  # Just deployed, assume healthy
        service_url=service_url,
        health_endpoint=health_endpoint,
    )

    # Complete the deployment
    deployment_store.complete(
        request.deployment_id,
        status="completed",
        service_id=request.service_id,
        attestation=request.attestation,
    )

    logger.info(
        f"Agent {agent_id} deployed: deployment={request.deployment_id}, service={request.service_id}"
    )
    return {"status": "ok", "service_id": request.service_id}


@app.get("/api/v1/agents", response_model=AgentListResponse)
async def list_agents(
    status: str | None = Query(None, description="Filter by status"),
    vm_name: str | None = Query(None, description="Filter by VM name (partial match)"),
):
    """List all registered launcher agents."""
    filters = {}
    if status:
        filters["status"] = status
    if vm_name:
        filters["vm_name"] = vm_name

    agents = agent_store.list(filters if filters else None)
    return AgentListResponse(agents=agents, total=len(agents))


@app.get("/api/v1/agents/{agent_id}", response_model=LauncherAgent)
async def get_agent(agent_id: str):
    """Get details for a specific agent."""
    agent = agent_store.get(agent_id)
    if agent is None:
        raise HTTPException(status_code=404, detail="Agent not found")
    return agent


@app.post("/api/v1/agents/{agent_id}/undeploy")
async def undeploy_agent(agent_id: str):
    """Tell an agent to undeploy its workload.

    Resets the agent to undeployed state so it can accept new deployments.
    """
    agent = agent_store.get(agent_id)
    if agent is None:
        raise HTTPException(status_code=404, detail="Agent not found")

    # Reset agent to undeployed
    agent_store.update_status(agent_id, "undeployed", deployment_id=None)
    logger.info(f"Agent {agent_id} undeployed")

    return {"status": "ok", "agent_id": agent_id}


@app.delete("/api/v1/agents/{agent_id}")
async def delete_agent(agent_id: str):
    """Delete an agent from the registry."""
    if not agent_store.delete(agent_id):
        raise HTTPException(status_code=404, detail="Agent not found")
    logger.info(f"Agent deleted: {agent_id}")
    return {"status": "deleted", "agent_id": agent_id}


# ==============================================================================
# Deployment API - Create and track deployments
# ==============================================================================


@app.post("/api/v1/deployments", response_model=DeploymentCreateResponse)
async def create_deployment(request: DeploymentCreateRequest):
    """Submit a deployment for an agent.

    The deployment will be picked up by the specified agent on its next poll.
    Only verified agents can receive deployments.
    """
    if not request.compose:
        raise HTTPException(
            status_code=400,
            detail="Deployment requires compose file (base64 encoded)"
        )

    if not request.agent_id:
        raise HTTPException(
            status_code=400,
            detail="Deployment requires agent_id"
        )

    # Verify agent exists
    agent = agent_store.get(request.agent_id)
    if agent is None:
        raise HTTPException(status_code=404, detail="Agent not found")

    # Check if agent is verified (MRTD in trusted list)
    if not agent.verified:
        raise HTTPException(
            status_code=403,
            detail=f"Agent not verified: {agent.verification_error or 'MRTD not trusted'}"
        )

    # Check if agent is available
    if agent.status not in ("undeployed", "deployed"):
        raise HTTPException(
            status_code=400,
            detail=f"Agent is not available (status: {agent.status})"
        )

    deployment = Deployment(
        compose=request.compose,
        build_context=request.build_context,
        config=request.config,
        agent_id=request.agent_id,
        status="pending",
    )
    deployment_id = deployment_store.create(deployment)
    logger.info(f"Deployment created: {deployment_id} for agent {request.agent_id}")

    return DeploymentCreateResponse(deployment_id=deployment_id, status="pending")


@app.get("/api/v1/deployments", response_model=DeploymentListResponse)
async def list_deployments(
    status: str | None = Query(None, description="Filter by status"),
    agent_id: str | None = Query(None, description="Filter by agent ID"),
):
    """List all deployments."""
    filters = {}
    if status:
        filters["status"] = status
    if agent_id:
        filters["agent_id"] = agent_id

    deployments = deployment_store.list(filters if filters else None)
    return DeploymentListResponse(deployments=deployments, total=len(deployments))


@app.get("/api/v1/deployments/{deployment_id}", response_model=Deployment)
async def get_deployment(deployment_id: str):
    """Get details for a specific deployment."""
    deployment = deployment_store.get(deployment_id)
    if deployment is None:
        raise HTTPException(status_code=404, detail="Deployment not found")
    return deployment


# ==============================================================================
# Trusted MRTD API - Manage trusted launcher measurements
# ==============================================================================


@app.post("/api/v1/trusted-mrtds", response_model=TrustedMrtd)
async def add_trusted_mrtd(request: TrustedMrtdCreateRequest):
    """Add a trusted MRTD to the allowlist.

    Only agents with MRTDs in this list can receive deployments.
    This ensures only known-good launcher images can run workloads.
    """
    if not request.mrtd:
        raise HTTPException(
            status_code=400,
            detail="MRTD is required"
        )

    # Check if already exists
    existing = trusted_mrtd_store.get(request.mrtd)
    if existing:
        raise HTTPException(
            status_code=409,
            detail="MRTD already in trusted list"
        )

    trusted = TrustedMrtd(
        mrtd=request.mrtd,
        description=request.description,
        image_version=request.image_version,
    )
    trusted_mrtd_store.add(trusted)
    logger.info(f"Added trusted MRTD: {request.mrtd[:16]}... ({request.description})")

    # Re-verify any unverified agents that now match
    for agent in agent_store.list():
        if not agent.verified and agent.mrtd == request.mrtd:
            agent_store.set_verified(agent.agent_id, True)
            logger.info(f"Agent {agent.agent_id} now verified")

    return trusted


@app.get("/api/v1/trusted-mrtds", response_model=TrustedMrtdListResponse)
async def list_trusted_mrtds(
    include_inactive: bool = Query(False, description="Include inactive MRTDs"),
):
    """List all trusted MRTDs."""
    mrtds = trusted_mrtd_store.list(include_inactive=include_inactive)
    return TrustedMrtdListResponse(trusted_mrtds=mrtds, total=len(mrtds))


@app.get("/api/v1/trusted-mrtds/{mrtd}", response_model=TrustedMrtd)
async def get_trusted_mrtd(mrtd: str):
    """Get details for a specific trusted MRTD."""
    trusted = trusted_mrtd_store.get(mrtd)
    if trusted is None:
        raise HTTPException(status_code=404, detail="Trusted MRTD not found")
    return trusted


@app.post("/api/v1/trusted-mrtds/{mrtd}/deactivate")
async def deactivate_trusted_mrtd(mrtd: str):
    """Deactivate a trusted MRTD.

    Agents with this MRTD will no longer be verified for new deployments.
    Existing deployments are not affected.
    """
    if not trusted_mrtd_store.deactivate(mrtd):
        raise HTTPException(status_code=404, detail="Trusted MRTD not found")

    # Mark agents with this MRTD as unverified
    for agent in agent_store.list():
        if agent.mrtd == mrtd and agent.verified:
            agent_store.set_verified(
                agent.agent_id,
                False,
                error="MRTD deactivated"
            )
            logger.info(f"Agent {agent.agent_id} unverified (MRTD deactivated)")

    logger.info(f"Deactivated trusted MRTD: {mrtd[:16]}...")
    return {"status": "deactivated", "mrtd": mrtd}


@app.post("/api/v1/trusted-mrtds/{mrtd}/activate")
async def activate_trusted_mrtd(mrtd: str):
    """Activate a previously deactivated trusted MRTD."""
    if not trusted_mrtd_store.activate(mrtd):
        raise HTTPException(status_code=404, detail="Trusted MRTD not found")

    # Re-verify agents with this MRTD
    for agent in agent_store.list():
        if agent.mrtd == mrtd and not agent.verified:
            agent_store.set_verified(agent.agent_id, True)
            logger.info(f"Agent {agent.agent_id} re-verified (MRTD activated)")

    logger.info(f"Activated trusted MRTD: {mrtd[:16]}...")
    return {"status": "activated", "mrtd": mrtd}


@app.delete("/api/v1/trusted-mrtds/{mrtd}")
async def delete_trusted_mrtd(mrtd: str):
    """Delete a trusted MRTD from the allowlist."""
    if not trusted_mrtd_store.delete(mrtd):
        raise HTTPException(status_code=404, detail="Trusted MRTD not found")

    # Mark agents with this MRTD as unverified
    for agent in agent_store.list():
        if agent.mrtd == mrtd and agent.verified:
            agent_store.set_verified(
                agent.agent_id,
                False,
                error="MRTD removed from trusted list"
            )
            logger.info(f"Agent {agent.agent_id} unverified (MRTD deleted)")

    logger.info(f"Deleted trusted MRTD: {mrtd[:16]}...")
    return {"status": "deleted", "mrtd": mrtd}


# Serve static files and web GUI
@app.get("/")
async def serve_gui():
    """Serve the web GUI."""
    index_path = STATIC_DIR / "index.html"
    if index_path.exists():
        return FileResponse(index_path)
    return {"message": "EasyEnclave Discovery Service", "docs": "/docs"}


# Mount static files after routes to avoid conflicts
if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


# Run with: uvicorn app.main:app --host 0.0.0.0 --port 8080
if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8080)
