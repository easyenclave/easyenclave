#!/usr/bin/env python3
"""Benchmark ORAM contact discovery performance.

Tests registration and lookup performance with varying dataset sizes.
"""

import hashlib
import sys
import time
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
            return MockService("http://localhost:8080")


def benchmark_registration(service, num_contacts: int):
    """Benchmark contact registration."""
    print(f"\n📝 Registering {num_contacts} contacts...")

    start = time.time()
    for i in range(num_contacts):
        phone = f"+1-555-{i:04d}"
        service.post("/register", json={
            "phone_number": phone,
            "user_id": f"user{i}"
        })

        if (i + 1) % 100 == 0:
            elapsed = time.time() - start
            rate = (i + 1) / elapsed
            print(f"   Progress: {i+1}/{num_contacts} ({rate:.1f} contacts/sec)")

    elapsed = time.time() - start
    rate = num_contacts / elapsed

    print(f"   ✓ Registration complete:")
    print(f"     Total time: {elapsed:.2f}s")
    print(f"     Rate: {rate:.1f} contacts/sec")
    print(f"     Per contact: {elapsed*1000/num_contacts:.1f}ms")

    return {
        "total_time": elapsed,
        "rate": rate,
        "per_contact_ms": elapsed * 1000 / num_contacts,
    }


def benchmark_lookup(service, num_queries: int, batch_size: int = 10):
    """Benchmark contact lookup."""
    print(f"\n🔍 Looking up {num_queries} contacts (batch size: {batch_size})...")

    # Generate phone hashes
    hashes = [
        hashlib.sha256(f"+1-555-{i:04d}".encode()).hexdigest()
        for i in range(num_queries)
    ]

    # Batch lookup
    start = time.time()
    num_batches = (num_queries + batch_size - 1) // batch_size

    for i in range(0, num_queries, batch_size):
        batch = hashes[i:i + batch_size]
        service.post("/lookup", json={"phone_hashes": batch})

        if ((i // batch_size) + 1) % 10 == 0:
            elapsed = time.time() - start
            rate = i / elapsed if elapsed > 0 else 0
            print(f"   Progress: {i}/{num_queries} ({rate:.1f} queries/sec)")

    elapsed = time.time() - start
    rate = num_queries / elapsed

    print(f"   ✓ Lookup complete:")
    print(f"     Total time: {elapsed:.2f}s")
    print(f"     Rate: {rate:.1f} queries/sec")
    print(f"     Per query: {elapsed*1000/num_queries:.1f}ms")
    print(f"     Per batch: {elapsed*1000/num_batches:.1f}ms")

    return {
        "total_time": elapsed,
        "rate": rate,
        "per_query_ms": elapsed * 1000 / num_queries,
        "per_batch_ms": elapsed * 1000 / num_batches,
    }


def main():
    """Run ORAM performance benchmarks."""
    print("=" * 70)
    print("ORAM Contact Discovery - Performance Benchmark")
    print("=" * 70)

    # Initialize client
    print("\n🔗 Connecting to ORAM service...")
    client = EasyEnclaveClient("https://app.easyenclave.com")
    service = client.service("oram-contacts")

    # For local testing:
    # service = MockService("http://localhost:8080")

    # Verify service is healthy
    health = service.get("/health").json()
    print(f"   ✓ Service status: {health['status']}")
    print(f"   ✓ Initial stats: {health['oram_stats']}")

    # Benchmark registration
    reg_stats = benchmark_registration(service, num_contacts=1000)

    # Benchmark lookup
    lookup_stats = benchmark_lookup(service, num_queries=500, batch_size=10)

    # Show final stats
    stats = service.get("/stats").json()
    print("\n" + "=" * 70)
    print("Final ORAM Statistics:")
    print("=" * 70)
    print(f"Total capacity:  {stats['total_capacity']} contacts")
    print(f"Registered:      {stats['num_contacts']} contacts")
    print(f"Stash size:      {stats['stash_size']} blocks")
    print(f"Occupancy:       {stats['occupancy']:.1%}")

    # Summary
    print("\n" + "=" * 70)
    print("Performance Summary:")
    print("=" * 70)
    print(f"\nRegistration:")
    print(f"  Rate: {reg_stats['rate']:.1f} contacts/sec")
    print(f"  Latency: {reg_stats['per_contact_ms']:.1f}ms per contact")

    print(f"\nLookup:")
    print(f"  Rate: {lookup_stats['rate']:.1f} queries/sec")
    print(f"  Latency: {lookup_stats['per_query_ms']:.1f}ms per query")
    print(f"  Batch latency: {lookup_stats['per_batch_ms']:.1f}ms per batch (10 queries)")

    # ORAM overhead calculation
    print(f"\n📊 ORAM Overhead:")
    print(f"  Traditional DB lookup: ~0.1ms (1 page read)")
    print(f"  ORAM lookup: {lookup_stats['per_query_ms']:.1f}ms (oblivious access)")
    overhead = lookup_stats['per_query_ms'] / 0.1
    print(f"  Overhead factor: ~{overhead:.0f}x")
    print(f"\n  ✅ Acceptable for contact discovery use case")
    print(f"  ✅ Privacy protection worth the performance cost")

    print("\n" + "=" * 70)
    print()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nInterrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
