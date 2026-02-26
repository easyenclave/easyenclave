from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone

from app.main import reclaim_orphaned_managed_gcp_instances


def _iso_utc_ago(*, hours: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat().replace("+00:00", "Z")


def test_reclaim_gcp_orphans_cleans_older_networks_in_same_env(monkeypatch):
    monkeypatch.setenv("EASYENCLAVE_NETWORK_NAME", "nova-beacon-a14733")
    monkeypatch.setenv("EASYENCLAVE_ENV", "staging")

    deleted: list[str] = []

    async def _list_instances(*, owned_only: bool = True):
        assert owned_only is False
        return [
            {
                "name": "ee-old-staging-vm",
                "datacenter": "gcp:us-central1-a",
                "creation_timestamp": _iso_utc_ago(hours=2),
                "labels": {"ee-network": "cosmic-drifter-68c25", "ee-env": "staging"},
            },
            {
                # Current network but still within grace window: do not reclaim.
                "name": "ee-current-staging-vm",
                "datacenter": "gcp:us-central1-a",
                "creation_timestamp": _iso_utc_ago(hours=0),
                "labels": {"ee-network": "nova-beacon-a14733", "ee-env": "staging"},
            },
            {
                # Different env must never be touched by this CP.
                "name": "ee-prod-vm",
                "datacenter": "gcp:us-central1-a",
                "creation_timestamp": _iso_utc_ago(hours=2),
                "labels": {"ee-network": "solar-spectrum-e19f1", "ee-env": "production"},
            },
        ]

    async def _delete_instance(*, datacenter: str, instance_name: str):
        assert datacenter.startswith("gcp:")
        deleted.append(instance_name)
        return True

    reclaimed = asyncio.run(
        reclaim_orphaned_managed_gcp_instances(
            delete_gcp_instance=_delete_instance,
            list_managed_gcp_instances=_list_instances,
        )
    )

    assert reclaimed == 1
    assert deleted == ["ee-old-staging-vm"]


def test_reclaim_gcp_orphans_uses_owned_only_when_scope_unset(monkeypatch):
    monkeypatch.delenv("EASYENCLAVE_NETWORK_NAME", raising=False)
    monkeypatch.delenv("EASYENCLAVE_ENV", raising=False)
    monkeypatch.delenv("ENVIRONMENT", raising=False)

    calls: list[bool] = []

    async def _list_instances(*, owned_only: bool = True):
        calls.append(owned_only)
        return []

    async def _delete_instance(*, datacenter: str, instance_name: str):
        return True

    reclaimed = asyncio.run(
        reclaim_orphaned_managed_gcp_instances(
            delete_gcp_instance=_delete_instance,
            list_managed_gcp_instances=_list_instances,
        )
    )

    assert reclaimed == 0
    assert calls == [True]


def test_reclaim_gcp_orphans_supports_inventory_fn_without_owned_only(monkeypatch):
    monkeypatch.setenv("EASYENCLAVE_NETWORK_NAME", "nova-beacon-a14733")
    monkeypatch.setenv("EASYENCLAVE_ENV", "staging")

    calls = {"count": 0}

    async def _list_instances_no_args():
        calls["count"] += 1
        return []

    async def _delete_instance(*, datacenter: str, instance_name: str):
        return True

    reclaimed = asyncio.run(
        reclaim_orphaned_managed_gcp_instances(
            delete_gcp_instance=_delete_instance,
            list_managed_gcp_instances=_list_instances_no_args,
        )
    )

    assert reclaimed == 0
    assert calls["count"] == 1
