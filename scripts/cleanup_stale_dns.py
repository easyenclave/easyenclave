"""Delete stale agent-* CNAME records from Cloudflare DNS.

Requires:
- CLOUDFLARE_ACCOUNT_ID
- CLOUDFLARE_API_TOKEN
- CLOUDFLARE_ZONE_ID

Usage: python3 scripts/cleanup_stale_dns.py [--dry-run]
"""

import asyncio
import os
import sys
import time

import httpx

API_URL = "https://api.cloudflare.com/client/v4"

BATCH_SIZE = 10
BATCH_DELAY = 1.0

DRY_RUN = "--dry-run" in sys.argv


def _require_env(name: str) -> str:
    v = os.environ.get(name)
    if not v:
        raise SystemExit(f"Missing required env var {name}")
    return v


async def main():
    account_id = _require_env("CLOUDFLARE_ACCOUNT_ID")
    api_token = _require_env("CLOUDFLARE_API_TOKEN")
    zone_id = _require_env("CLOUDFLARE_ZONE_ID")
    headers = {
        "Authorization": f"Bearer {api_token}",
        "Content-Type": "application/json",
    }

    # First, get active tunnel IDs (to know which CNAMEs to keep)
    print("Fetching active tunnels...")
    active_tunnel_ids = set()
    async with httpx.AsyncClient(timeout=30.0) as client:
        page = 1
        while True:
            resp = await client.get(
                f"{API_URL}/accounts/{account_id}/cfd_tunnel",
                headers=headers,
                params={"per_page": 100, "is_deleted": "false", "page": page},
            )
            resp.raise_for_status()
            tunnels = resp.json().get("result", [])
            if not tunnels:
                break
            for t in tunnels:
                if t.get("connections") and len(t["connections"]) > 0:
                    active_tunnel_ids.add(t["id"])
            page += 1
            await asyncio.sleep(0.3)
    print(f"  Found {len(active_tunnel_ids)} active tunnels")

    # Fetch all agent-* CNAME records
    print("Fetching CNAME records...")
    all_records = []
    async with httpx.AsyncClient(timeout=30.0) as client:
        page = 1
        while True:
            resp = await client.get(
                f"{API_URL}/zones/{zone_id}/dns_records",
                headers=headers,
                params={"per_page": 100, "type": "CNAME", "page": page},
            )
            resp.raise_for_status()
            records = resp.json().get("result", [])
            if not records:
                break
            all_records.extend(records)
            print(f"  Fetched page {page}: {len(records)} records (total: {len(all_records)})")
            page += 1
            await asyncio.sleep(0.3)

    # Filter: agent-* CNAMEs pointing to deleted tunnels
    stale = []
    keeping = []
    for r in all_records:
        name = r["name"]
        content = r["content"]  # e.g. "uuid.cfargotunnel.com"
        tunnel_id = content.split(".")[0] if ".cfargotunnel.com" in content else None

        if not name.startswith("agent-"):
            keeping.append(r)
            continue

        if tunnel_id and tunnel_id in active_tunnel_ids:
            keeping.append(r)
        else:
            stale.append(r)

    print(f"\nTotal CNAME records: {len(all_records)}")
    print(f"Keeping: {len(keeping)} (non-agent or active tunnel)")
    for r in keeping:
        print(f"  {r['name']}")
    print(f"Stale (to delete): {len(stale)}")

    if DRY_RUN:
        print("\n[DRY RUN] Would delete the above. Run without --dry-run to proceed.")
        return

    if not stale:
        print("Nothing to clean up!")
        return

    # Delete stale records in batches
    print(f"\nDeleting {len(stale)} stale CNAME records...")
    deleted = 0
    failed = 0
    start = time.time()

    async with httpx.AsyncClient(timeout=30.0) as client:
        for i in range(0, len(stale), BATCH_SIZE):
            batch = stale[i : i + BATCH_SIZE]

            async def delete_record(record):
                try:
                    resp = await client.delete(
                        f"{API_URL}/zones/{zone_id}/dns_records/{record['id']}",
                        headers=headers,
                    )
                    return resp.status_code == 200
                except Exception:
                    return False

            results = await asyncio.gather(*[delete_record(r) for r in batch])
            for ok in results:
                if ok:
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
            await asyncio.sleep(BATCH_DELAY)

    elapsed = time.time() - start
    print(f"\nDone in {elapsed:.0f}s: {deleted} deleted, {failed} failed")


if __name__ == "__main__":
    asyncio.run(main())
