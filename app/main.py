"""EasyEnclave Discovery Service - FastAPI Application."""

from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path

import httpx
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from .ita import verify_attestation_token
from .models import (
    HealthResponse,
    ServiceListResponse,
    ServiceRegistration,
    ServiceRegistrationRequest,
    VerificationResponse,
)
from .storage import store

logger = logging.getLogger(__name__)

# Health check interval in seconds
HEALTH_CHECK_INTERVAL = 60


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


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage application lifespan - start background tasks."""
    # Start background health checker
    task = asyncio.create_task(background_health_checker())
    logger.info("Started background health checker")
    yield
    # Shutdown
    task.cancel()
    try:
        await task
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
