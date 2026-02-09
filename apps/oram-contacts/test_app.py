#!/usr/bin/env python3
"""Basic tests for ORAM contacts app."""

import hashlib
import sys
import tempfile
import os

# Set temp DB path for testing
os.environ["ORAM_DB_PATH"] = tempfile.mktemp(suffix=".db")
os.environ["ORAM_BUCKETS"] = "32"

from fastapi.testclient import TestClient
from app import app

# Client will be created in main
client = None


def get_client():
    """Get the test get_client()."""
    return client


def test_health():
    """Test health endpoint."""
    response = get_client().get("/health")
    if response.status_code != 200:
        print(f"Error: {response.json()}")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert "oram_stats" in data
    print("✓ Health check passed")


def test_root():
    """Test root endpoint."""
    response = get_client().get("/")
    assert response.status_code == 200
    data = response.json()
    assert data["service"] == "ORAM Contact Discovery"
    print("✓ Root endpoint passed")


def test_register():
    """Test contact registration."""
    response = get_client().post(
        "/register", json={"phone_number": "+1-555-0100", "user_id": "alice"}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["registered"] == True
    assert data["user_id"] == "alice"
    print("✓ Registration passed")


def test_lookup():
    """Test contact lookup."""
    # Register first
    get_client().post("/register", json={"phone_number": "+1-555-0101", "user_id": "bob"})

    # Lookup
    phone_hash = hashlib.sha256(b"+1-555-0101").hexdigest()
    response = get_client().post("/lookup", json={"phone_hashes": [phone_hash]})
    assert response.status_code == 200
    data = response.json()
    assert data["results"][0] == "bob"
    print("✓ Lookup passed")


def test_lookup_not_found():
    """Test lookup for non-existent contact."""
    phone_hash = hashlib.sha256(b"+1-555-9999").hexdigest()
    response = get_client().post("/lookup", json={"phone_hashes": [phone_hash]})
    assert response.status_code == 200
    data = response.json()
    assert data["results"][0] is None
    print("✓ Lookup not found passed")


def test_stats():
    """Test stats endpoint."""
    response = get_client().get("/stats")
    assert response.status_code == 200
    data = response.json()
    assert "total_capacity" in data
    assert "num_contacts" in data
    assert "stash_size" in data
    assert "occupancy" in data
    print("✓ Stats passed")


def test_batch_lookup():
    """Test batch contact lookup."""
    # Register multiple contacts
    contacts = [
        ("+1-555-0200", "charlie"),
        ("+1-555-0201", "diana"),
        ("+1-555-0202", "eve"),
    ]

    for phone, user_id in contacts:
        get_client().post("/register", json={"phone_number": phone, "user_id": user_id})

    # Batch lookup
    hashes = [hashlib.sha256(phone.encode()).hexdigest() for phone, _ in contacts]
    response = get_client().post("/lookup", json={"phone_hashes": hashes})
    assert response.status_code == 200
    data = response.json()
    results = data["results"]

    assert results[0] == "charlie"
    assert results[1] == "diana"
    assert results[2] == "eve"
    print("✓ Batch lookup passed")


if __name__ == "__main__":
    try:
        print("=" * 60)
        print("ORAM Contacts App - Unit Tests")
        print("=" * 60)
        print()

        # Create test client with context manager
        with TestClient(app) as client:
            test_health()
            test_root()
            test_register()
            test_lookup()
            test_lookup_not_found()
            test_stats()
            test_batch_lookup()

        print()
        print("=" * 60)
        print("All tests passed!")
        print("=" * 60)
    finally:
        # Cleanup temp DB
        db_path = os.environ.get("ORAM_DB_PATH")
        if db_path and os.path.exists(db_path):
            os.unlink(db_path)
