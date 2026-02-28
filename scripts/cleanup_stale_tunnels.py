"""Delete stale Cloudflare agent tunnels.

Requires:
- CLOUDFLARE_ACCOUNT_ID
- CLOUDFLARE_API_TOKEN

Usage: python3 scripts/cleanup_stale_tunnels.py [--dry-run]
"""

import asyncio
import os
import sys
import time

import httpx

API_URL = "https://api.cloudflare.com/client/v4"

# Rate limiting: Cloudflare allows 1200 req/5min = 4/sec
# Each tunnel deletion = 2 calls (cleanup connections + delete)
BATCH_SIZE = 10
BATCH_DELAY = 1.0  # seconds between batches

DRY_RUN = "--dry-run" in sys.argv


def _require_env(name: str) -> str:
    v = os.environ.get(name)
    if not v:
        raise SystemExit(f"Missing required env var {name}")
    return v


async def list_all_tunnels(
    client: httpx.AsyncClient, headers: dict, *, account_id: str
) -> list[dict]:
    """Fetch all non-deleted tunnels across all pages."""
    tunnels = []
    page = 1
    while True:
        resp = await client.get(
            f"{API_URL}/accounts/{account_id}/cfd_tunnel",
            headers=headers,
            params={"per_page": 100, "is_deleted": "false", "page": page},
        )
        resp.raise_for_status()
        data = resp.json()
        batch = data.get("result", [])
        if not batch:
            break
        tunnels.extend(batch)
        print(f"  Fetched page {page}: {len(batch)} tunnels (total: {len(tunnels)})")
        page += 1
        await asyncio.sleep(0.3)
    return tunnels


async def delete_tunnel(
    client: httpx.AsyncClient, headers: dict, tunnel: dict, *, account_id: str
) -> bool:
    """Delete a single tunnel (clean connections first)."""
    tunnel_id = tunnel["id"]
    name = tunnel["name"]

    try:
        # Clean up connections first
        await client.delete(
            f"{API_URL}/accounts/{account_id}/cfd_tunnel/{tunnel_id}/connections",
            headers=headers,
        )
        await asyncio.sleep(0.2)

        # Delete the tunnel
        resp = await client.delete(
            f"{API_URL}/accounts/{account_id}/cfd_tunnel/{tunnel_id}",
            headers=headers,
        )
        if resp.status_code == 200:
            return True
        else:
            print(f"  FAILED {name}: HTTP {resp.status_code} - {resp.text[:100]}")
            return False
    except Exception as e:
        print(f"  ERROR {name}: {e}")
        return False


async def main():
    account_id = _require_env("CLOUDFLARE_ACCOUNT_ID")
    api_token = _require_env("CLOUDFLARE_API_TOKEN")
    headers = {
        "Authorization": f"Bearer {api_token}",
        "Content-Type": "application/json",
    }

    print("Fetching all tunnels...")
    async with httpx.AsyncClient(timeout=30.0) as client:
        tunnels = await list_all_tunnels(client, headers, account_id=account_id)

    # Filter: only agent-* tunnels with no connections
    stale = [
        t
        for t in tunnels
        if t["name"].startswith("agent-")
        and (not t.get("connections") or len(t["connections"]) == 0)
    ]
    active = [t for t in tunnels if t.get("connections") and len(t["connections"]) > 0]

    print(f"\nTotal tunnels: {len(tunnels)}")
    print(f"Active (keeping): {len(active)}")
    for t in active:
        print(f"  {t['name']} ({len(t['connections'])} connections)")
    print(f"Stale agent tunnels to delete: {len(stale)}")

    if DRY_RUN:
        print("\n[DRY RUN] Would delete the above stale tunnels. Run without --dry-run to proceed.")
        return

    if not stale:
        print("Nothing to clean up!")
        return

    print(f"\nDeleting {len(stale)} stale tunnels in batches of {BATCH_SIZE}...")
    deleted = 0
    failed = 0
    start = time.time()

    async with httpx.AsyncClient(timeout=30.0) as client:
        for i in range(0, len(stale), BATCH_SIZE):
            batch = stale[i : i + BATCH_SIZE]

            # Run batch concurrently
            results = await asyncio.gather(
                *[delete_tunnel(client, headers, t, account_id=account_id) for t in batch],
                return_exceptions=True,
            )
            for r in results:
                if r is True:
                    deleted += 1
                else:
                    failed += 1

            elapsed = time.time() - start
            total_done = deleted + failed
            rate = total_done / elapsed if elapsed > 0 else 0
            remaining = (len(stale) - total_done) / rate if rate > 0 else 0
            print(
                f"  Progress: {total_done}/{len(stale)} "
                f"({deleted} deleted, {failed} failed) "
                f"~{remaining:.0f}s remaining"
            )

            # Rate limit pause between batches
            await asyncio.sleep(BATCH_DELAY)

    elapsed = time.time() - start
    print(f"\nDone in {elapsed:.0f}s: {deleted} deleted, {failed} failed")


if __name__ == "__main__":
    asyncio.run(main())
