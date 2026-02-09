"""Request/Response models for ORAM contacts API."""

from pydantic import BaseModel, Field


class RegisterRequest(BaseModel):
    """Request to register a contact."""

    phone_number: str = Field(..., description="Phone number (will be hashed by service)")
    user_id: str = Field(..., description="Public user identifier")


class LookupRequest(BaseModel):
    """Request to lookup contacts."""

    phone_hashes: list[str] = Field(
        ..., description="List of hex-encoded SHA-256 phone hashes"
    )


class LookupResponse(BaseModel):
    """Response from contact lookup."""

    results: list[str | None] = Field(
        ..., description="List of user_ids (null if not found)"
    )


class HealthResponse(BaseModel):
    """Health check response."""

    status: str
    oram_stats: dict


class StatsResponse(BaseModel):
    """ORAM statistics response."""

    total_capacity: int
    num_contacts: int
    stash_size: int
    occupancy: float
