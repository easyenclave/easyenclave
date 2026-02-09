"""ORAM Contact Discovery Service.

Privacy-preserving contact discovery using Oblivious RAM (ORAM).
Protects access patterns even if TEE is compromised.
"""

import hashlib
import logging
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from models import (
    HealthResponse,
    LookupRequest,
    LookupResponse,
    RegisterRequest,
    StatsResponse,
)
from oram_store import ORAMContactStore

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Global ORAM store
store: ORAMContactStore | None = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize ORAM store on startup."""
    global store

    # Get configuration from environment
    db_path = os.getenv("ORAM_DB_PATH", "/data/contacts.db")
    num_buckets = int(os.getenv("ORAM_BUCKETS", "1024"))
    stash_size = int(os.getenv("ORAM_STASH_SIZE", "100"))

    logger.info(f"Initializing ORAM store: db={db_path}, buckets={num_buckets}")

    try:
        store = ORAMContactStore(
            db_path=db_path,
            num_buckets=num_buckets,
            stash_size=stash_size,
        )
        logger.info("ORAM store initialized successfully")
        logger.info(f"Initial stats: {store.stats()}")
    except Exception as e:
        logger.error(f"Failed to initialize ORAM store: {e}")
        raise

    yield

    logger.info("Shutting down ORAM contact service")


# Create FastAPI app
app = FastAPI(
    title="ORAM Contact Discovery",
    description="Privacy-preserving contact discovery using Oblivious RAM",
    version="1.0.0",
    lifespan=lifespan,
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health", response_model=HealthResponse)
async def health():
    """Health check endpoint with basic stats.

    Returns:
        Health status and ORAM statistics
    """
    if store is None:
        raise HTTPException(status_code=503, detail="ORAM store not initialized")

    return HealthResponse(
        status="healthy",
        oram_stats=store.stats(),
    )


@app.post("/register")
async def register_contact(request: RegisterRequest):
    """Register a contact.

    The phone number is hashed server-side using SHA-256.
    User ID is stored obliviously in the ORAM.

    Args:
        request: Registration request with phone number and user ID

    Returns:
        Registration status
    """
    if store is None:
        raise HTTPException(status_code=503, detail="ORAM store not initialized")

    try:
        # Hash phone number server-side
        phone_hash = hashlib.sha256(request.phone_number.encode()).digest()

        # Register in ORAM
        success = store.register_contact(phone_hash, request.user_id)

        if success:
            logger.info(f"Registered contact: user_id={request.user_id}")
            return {"registered": True, "user_id": request.user_id}
        else:
            logger.info(f"Contact already registered: user_id={request.user_id}")
            return {"registered": False, "user_id": request.user_id, "reason": "already_exists"}

    except OverflowError as e:
        logger.error(f"ORAM capacity exceeded: {e}")
        raise HTTPException(status_code=507, detail="Storage capacity exceeded")
    except Exception as e:
        logger.error(f"Registration failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/lookup", response_model=LookupResponse)
async def lookup_contacts(request: LookupRequest):
    """Oblivious contact lookup.

    All queries access the same number of ORAM buckets, hiding the access pattern.
    An attacker with physical access cannot determine which contacts were queried.

    Args:
        request: Lookup request with hex-encoded phone hashes

    Returns:
        List of user IDs (null if not found)
    """
    if store is None:
        raise HTTPException(status_code=503, detail="ORAM store not initialized")

    try:
        # Decode hex hashes
        phone_hashes = [bytes.fromhex(h) for h in request.phone_hashes]

        # Validate hash lengths (SHA-256 = 32 bytes)
        for h in phone_hashes:
            if len(h) != 32:
                raise ValueError(f"Invalid hash length: {len(h)} (expected 32)")

        # Oblivious lookup
        user_ids = store.lookup_contacts(phone_hashes)

        logger.info(f"Looked up {len(phone_hashes)} contacts (found {sum(1 for u in user_ids if u)})")

        return LookupResponse(results=user_ids)

    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Lookup failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/stats", response_model=StatsResponse)
async def get_stats():
    """Get ORAM statistics.

    Returns:
        ORAM occupancy, stash size, and performance metrics
    """
    if store is None:
        raise HTTPException(status_code=503, detail="ORAM store not initialized")

    stats = store.stats()
    return StatsResponse(**stats)


@app.get("/")
async def root():
    """Root endpoint with service information."""
    return {
        "service": "ORAM Contact Discovery",
        "version": "1.0.0",
        "description": "Privacy-preserving contact discovery using Oblivious RAM",
        "endpoints": {
            "health": "GET /health",
            "register": "POST /register",
            "lookup": "POST /lookup",
            "stats": "GET /stats",
        },
        "security": {
            "oram": "Cuckoo hash bucketing",
            "encryption": "AES-GCM",
            "threat_model": "Protects access patterns even with physical access",
        },
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8080)
