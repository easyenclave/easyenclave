#!/usr/bin/env python3
"""Example: Privacy-preserving contact discovery with ORAM.

This demonstrates how to use the ORAM contacts service for
privacy-preserving contact discovery with defense-in-depth security.
"""

import hashlib
import sys
from pathlib import Path

# Add SDK to path (for local development)
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "sdk" / "python"))

try:
    from easyenclave import EasyEnclaveClient
except ImportError:
    print("Warning: EasyEnclave SDK not available, using requests directly")
    import requests

    class MockService:
        def __init__(self, base_url):
            self.base_url = base_url

        def get(self, path):
            return requests.get(f"{self.base_url}{path}")

        def post(self, path, **kwargs):
            return requests.post(f"{self.base_url}{path}", **kwargs)

    class EasyEnclaveClient:
        def __init__(self, url):
            self.url = url

        def service(self, name):
            # For local testing
            return MockService("http://localhost:8080")


def main():
    """Run ORAM contact discovery example."""
    print("=" * 60)
    print("ORAM Contact Discovery Example")
    print("=" * 60)
    print()

    # Initialize client (change URL for production)
    print("1. Connecting to ORAM service...")
    client = EasyEnclaveClient("https://app.easyenclave.com")
    service = client.service("oram-contacts")

    # For local testing, use:
    # service = MockService("http://localhost:8080")

    # Verify service is healthy
    health = service.get("/health").json()
    print(f"   ✓ Service status: {health['status']}")
    print(f"   ✓ ORAM stats: {health['oram_stats']}")
    print()

    # Register some users (simulating users signing up)
    print("2. Registering users...")
    users = [
        ("+1-555-0100", "alice"),
        ("+1-555-0101", "bob"),
        ("+1-555-0102", "charlie"),
        ("+1-555-0103", "diana"),
        ("+1-555-0104", "eve"),
    ]

    for phone, user_id in users:
        response = service.post("/register", json={
            "phone_number": phone,
            "user_id": user_id
        })
        result = response.json()
        if result.get("registered"):
            print(f"   ✓ Registered {user_id} ({phone})")
        else:
            print(f"   ⚠ {user_id} already registered")
    print()

    # Lookup contacts (oblivious)
    print("3. Looking up contacts (oblivious)...")
    print("   Note: All queries access the same number of ORAM buckets,")
    print("   hiding which contacts you're actually looking for.")
    print()

    my_contacts = [
        "+1-555-0100",  # alice (registered)
        "+1-555-0199",  # not registered
        "+1-555-0102",  # charlie (registered)
        "+1-555-0200",  # not registered
        "+1-555-0104",  # eve (registered)
    ]

    # Hash phone numbers locally (client-side)
    print("   Hashing phone numbers client-side...")
    contact_hashes = [
        hashlib.sha256(c.encode()).hexdigest()
        for c in my_contacts
    ]

    # Oblivious lookup (server can't tell which you queried)
    print("   Sending oblivious lookup request...")
    response = service.post("/lookup", json={
        "phone_hashes": contact_hashes
    })

    results = response.json()["results"]

    print()
    print("   Lookup results:")
    for phone, user_id in zip(my_contacts, results):
        if user_id:
            print(f"   ✅ {phone} → {user_id}")
        else:
            print(f"   ❌ {phone} not registered")

    print()
    print("=" * 60)
    print("🔒 Security Guarantees:")
    print("=" * 60)
    print()
    print("✅ Server never learned which numbers you checked")
    print("   All queries looked identical (ORAM access pattern hiding)")
    print()
    print("✅ Even with physical access to the server, an attacker cannot:")
    print("   • Tell which contacts you looked up")
    print("   • Correlate database accesses to phone numbers")
    print("   • Reconstruct your query history")
    print()
    print("✅ Defense-in-depth:")
    print("   • TDX: Protects against OS/hypervisor attacks")
    print("   • ORAM: Protects against physical/side-channel attacks")
    print("   • AES-GCM: Encrypts all data at rest")
    print()

    # Show final stats
    stats = service.get("/stats").json()
    print("=" * 60)
    print("ORAM Statistics:")
    print("=" * 60)
    print(f"Total capacity:  {stats['total_capacity']} contacts")
    print(f"Registered:      {stats['num_contacts']} contacts")
    print(f"Stash size:      {stats['stash_size']} blocks")
    print(f"Occupancy:       {stats['occupancy']:.1%}")
    print()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nInterrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Error: {e}")
        sys.exit(1)
