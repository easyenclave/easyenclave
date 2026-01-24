"""EasyEnclave Discovery Service - FastAPI Application."""

from __future__ import annotations

from datetime import datetime
from typing import Optional
from pathlib import Path

import httpx
from fastapi import FastAPI, HTTPException, Query
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware

from .models import (
    ServiceRegistration,
    ServiceRegistrationRequest,
    ServiceListResponse,
    VerificationResponse,
    HealthResponse,
)
from .storage import store
from .ita import verify_attestation_token

# Create FastAPI app
app = FastAPI(
    title="EasyEnclave Discovery Service",
    description="Confidential discovery service for TDX-attested applications",
    version="0.1.0",
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

    for env, url in request.endpoints.items():
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
    store.register(service)
    return service


@app.get("/api/v1/services", response_model=ServiceListResponse)
async def list_services(
    name: Optional[str] = Query(None, description="Filter by name (partial match)"),
    tags: Optional[str] = Query(None, description="Filter by tags (comma-separated)"),
    environment: Optional[str] = Query(None, description="Filter by environment"),
    mrtd: Optional[str] = Query(None, description="Filter by MRTD (exact match)"),
    health_status: Optional[str] = Query(None, description="Filter by health status"),
    q: Optional[str] = Query(None, description="Search query"),
):
    """List all registered services with optional filters."""
    # If search query provided, use search
    if q:
        services = store.search(q)
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

        services = store.list(filters if filters else None)

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
