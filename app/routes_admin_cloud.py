"""Admin routes for trust baselines, settings, and cloud cleanup."""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable
from datetime import timedelta
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Query

from .billing import _ensure_stripe, _stripe_mod
from .db_models import AdminSession
from .models import (
    AdminAgentCleanupRequest,
    AdminAgentCleanupResponse,
    AdminStaleAgentCleanupRequest,
    AdminStaleAgentCleanupResponse,
    CloudflareCleanupRequest,
    CloudflareCleanupResponse,
    ExternalCloudCleanupRequest,
    ExternalCloudCleanupResponse,
    UnifiedOrphanCleanupRequest,
    UnifiedOrphanCleanupResponse,
)

CLOUDFLARE_AGENT_TUNNEL_PREFIX = "agent-"
CLOUDFLARE_CONTROL_PLANE_TUNNEL_NAME = "easyenclave-control-plane"


def _is_agent_tunnel_name(name: str | None) -> bool:
    return bool(name) and name.startswith(CLOUDFLARE_AGENT_TUNNEL_PREFIX)


def _is_protected_tunnel_name(name: str | None) -> bool:
    return name == CLOUDFLARE_CONTROL_PLANE_TUNNEL_NAME


def register_admin_cloud_routes(
    app: FastAPI,
    *,
    logger: logging.Logger,
    verify_admin_token: Callable[..., Any],
    require_admin_session: Callable[..., Any],
    is_admin_session: Callable[[AdminSession], bool],
    list_trusted_mrtds_fn: Callable[[], dict[str, str]],
    setting_defs: dict[str, Any],
    list_settings_fn: Callable[..., Any],
    set_setting_fn: Callable[[str, str], None],
    delete_setting_fn: Callable[[str], bool],
    get_setting_fn: Callable[[str], str],
    get_setting_source_fn: Callable[[str], str],
    get_setting_int_fn: Callable[..., int],
    cloudflare_module: Any,
    agent_store: Any,
    capacity_reservation_store: Any,
    get_or_404_fn: Callable[[Any, str, str], Any],
    list_external_cloud_resources_fn: Callable[..., Awaitable[Any]],
    dispatch_external_cleanup_fn: Callable[
        [dict], Awaitable[tuple[bool, bool, int | None, str | None, dict]]
    ],
    fetch_external_inventory_fn: Callable[[], Awaitable[tuple[bool, int | None, str | None, dict]]],
    extract_cleanup_requested_count_fn: Callable[[dict], int],
    cloudflare_delete_many_fn: Callable[..., Awaitable[dict[str, int]]],
) -> None:
    """Register admin and cloud management routes."""

    @app.get("/api/v1/trusted-mrtds")
    async def get_trusted_mrtds():
        """List all trusted MRTDs (effective trust list)."""
        mrtds = list_trusted_mrtds_fn()
        return {
            "trusted_mrtds": [{"mrtd": k, "type": v} for k, v in mrtds.items()],
            "total": len(mrtds),
        }

    @app.get("/api/v1/admin/trusted-mrtds")
    async def list_trusted_mrtds_admin(session: AdminSession = Depends(verify_admin_token)):
        """Admin-only view of DB-backed trusted MRTDs."""
        if not is_admin_session(session):
            raise HTTPException(status_code=403, detail="Admin access required")
        from .storage import trusted_mrtd_store

        rows = trusted_mrtd_store.list()
        return {
            "trusted_mrtds": [
                {
                    "mrtd": r.mrtd,
                    "type": r.mrtd_type,
                    "note": r.note,
                    "added_at": r.added_at.isoformat() if r.added_at else None,
                }
                for r in rows
            ],
            "total": len(rows),
        }

    @app.post("/api/v1/admin/trusted-mrtds")
    async def add_trusted_mrtd_admin(
        request: dict,
        session: AdminSession = Depends(verify_admin_token),
    ):
        """Admin-only: add a trusted MRTD baseline without rebooting the control plane."""
        if not is_admin_session(session):
            raise HTTPException(status_code=403, detail="Admin access required")
        mrtd = str(request.get("mrtd") or "").strip()
        mrtd_type = str(request.get("type") or "agent").strip()
        note = str(request.get("note") or "").strip()
        if not mrtd:
            raise HTTPException(status_code=400, detail="mrtd is required")
        from .storage import trusted_mrtd_store

        try:
            obj = trusted_mrtd_store.upsert(mrtd, mrtd_type=mrtd_type, note=note)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return {"mrtd": obj.mrtd, "type": obj.mrtd_type, "note": obj.note}

    @app.delete("/api/v1/admin/trusted-mrtds/{mrtd}")
    async def delete_trusted_mrtd_admin(
        mrtd: str,
        session: AdminSession = Depends(verify_admin_token),
    ):
        """Admin-only: remove a trusted MRTD baseline."""
        if not is_admin_session(session):
            raise HTTPException(status_code=403, detail="Admin access required")
        from .storage import trusted_mrtd_store

        ok = trusted_mrtd_store.delete(mrtd)
        if not ok:
            raise HTTPException(status_code=404, detail="MRTD not found")
        return {"status": "deleted", "mrtd": mrtd}

    @app.get("/api/v1/admin/settings")
    async def admin_list_settings(
        group: str | None = Query(None),
        _admin: AdminSession = Depends(require_admin_session),
    ):
        """List all settings with values, sources, and metadata."""
        return {"settings": list_settings_fn(group=group)}

    @app.put("/api/v1/admin/settings/{key:path}")
    async def admin_update_setting(
        key: str,
        body: dict,
        _admin: AdminSession = Depends(require_admin_session),
    ):
        """Save a setting value to the database."""
        if key not in setting_defs:
            raise HTTPException(status_code=404, detail=f"Unknown setting: {key}")
        value = body.get("value")
        if value is None:
            raise HTTPException(status_code=422, detail="Missing 'value' field")
        set_setting_fn(key, str(value))
        logger.info(f"Setting updated: {key}")
        return {"key": key, "status": "saved"}

    @app.delete("/api/v1/admin/settings/{key:path}")
    async def admin_reset_setting(
        key: str,
        _admin: AdminSession = Depends(require_admin_session),
    ):
        """Remove a setting from DB (reverts to env var or default)."""
        if key not in setting_defs:
            raise HTTPException(status_code=404, detail=f"Unknown setting: {key}")
        deleted = delete_setting_fn(key)
        logger.info(f"Setting reset: {key} (was_in_db={deleted})")
        return {"key": key, "status": "reset"}

    @app.get("/api/v1/admin/stripe/status")
    async def admin_stripe_status(
        validate: bool = Query(False),
        _admin: AdminSession = Depends(require_admin_session),
    ):
        """Return basic Stripe integration status for the admin UI."""
        secret_key = get_setting_fn("stripe.secret_key")
        webhook_secret = get_setting_fn("stripe.webhook_secret")

        mode = ""
        if secret_key.startswith("sk_test_"):
            mode = "test"
        elif secret_key.startswith("sk_live_"):
            mode = "live"

        stripe_available = _stripe_mod is not None
        stripe_enabled = _ensure_stripe()

        validation = {"attempted": bool(validate), "ok": None, "error": None}
        if validate:
            if not stripe_enabled:
                validation["ok"] = False
                validation["error"] = (
                    "Stripe not enabled (missing STRIPE_SECRET_KEY or SDK unavailable)"
                )
            else:
                try:
                    _stripe_mod.Balance.retrieve()
                    validation["ok"] = True
                except Exception as exc:
                    validation["ok"] = False
                    validation["error"] = f"{type(exc).__name__}: {str(exc)[:200]}"

        return {
            "stripe_available": stripe_available,
            "stripe_enabled": stripe_enabled,
            "mode": mode,
            "secret_key_configured": bool(secret_key),
            "secret_key_source": get_setting_source_fn("stripe.secret_key"),
            "webhook_secret_configured": bool(webhook_secret),
            "webhook_secret_source": get_setting_source_fn("stripe.webhook_secret"),
            "webhook_path": "/api/v1/webhooks/stripe",
            "validation": validation,
        }

    @app.get("/api/v1/admin/cloudflare/status")
    async def cloudflare_status(_admin: AdminSession = Depends(require_admin_session)):
        """Check if Cloudflare is configured and return domain info."""
        return {
            "configured": cloudflare_module.is_configured(),
            "domain": cloudflare_module.get_domain(),
            "protected_tunnel_names": [CLOUDFLARE_CONTROL_PLANE_TUNNEL_NAME],
        }

    @app.get("/api/v1/admin/cloudflare/tunnels")
    async def cloudflare_tunnels(_admin: AdminSession = Depends(require_admin_session)):
        """List Cloudflare tunnels cross-referenced with agents."""
        if not cloudflare_module.is_configured():
            raise HTTPException(status_code=400, detail="Cloudflare not configured")

        tunnels = await cloudflare_module.list_tunnels()
        agents = agent_store.list()

        tunnel_to_agent = {}
        for agent in agents:
            if agent.tunnel_id:
                tunnel_to_agent[agent.tunnel_id] = agent

        enriched = []
        orphaned_count = 0
        for tunnel in tunnels:
            agent = tunnel_to_agent.get(tunnel["tunnel_id"])
            name = tunnel.get("name")
            protected = _is_protected_tunnel_name(name)
            is_orphaned = (agent is None) and (not protected) and _is_agent_tunnel_name(name)
            if is_orphaned:
                orphaned_count += 1
            enriched.append(
                {
                    **tunnel,
                    "agent_id": agent.agent_id if agent else None,
                    "agent_vm_name": agent.vm_name if agent else None,
                    "agent_status": agent.status if agent else None,
                    "orphaned": is_orphaned,
                    "protected": protected,
                    "owner": "agent"
                    if _is_agent_tunnel_name(name)
                    else ("control-plane" if protected else "unmanaged"),
                }
            )

        return {
            "tunnels": enriched,
            "total": len(enriched),
            "orphaned_count": orphaned_count,
            "connected_count": sum(1 for tunnel in enriched if tunnel["has_connections"]),
        }

    @app.get("/api/v1/admin/cloudflare/dns")
    async def cloudflare_dns(_admin: AdminSession = Depends(require_admin_session)):
        """List Cloudflare DNS CNAME records cross-referenced with tunnels."""
        if not cloudflare_module.is_configured():
            raise HTTPException(status_code=400, detail="Cloudflare not configured")

        records = await cloudflare_module.list_dns_records()
        tunnels = await cloudflare_module.list_tunnels()
        tunnel_ids = {tunnel["tunnel_id"] for tunnel in tunnels}

        enriched = []
        orphaned_count = 0
        for record in records:
            content = record.get("content", "")
            is_tunnel_record = content.endswith(".cfargotunnel.com")
            linked_tunnel_id = None
            if is_tunnel_record:
                linked_tunnel_id = content.replace(".cfargotunnel.com", "")

            is_orphaned = is_tunnel_record and linked_tunnel_id not in tunnel_ids
            if is_orphaned:
                orphaned_count += 1

            enriched.append(
                {
                    **record,
                    "is_tunnel_record": is_tunnel_record,
                    "linked_tunnel_id": linked_tunnel_id,
                    "orphaned": is_orphaned,
                }
            )

        return {
            "records": enriched,
            "total": len(enriched),
            "orphaned_count": orphaned_count,
            "tunnel_record_count": sum(1 for record in enriched if record["is_tunnel_record"]),
        }

    @app.delete("/api/v1/admin/cloudflare/tunnels/{tunnel_id}")
    async def cloudflare_delete_tunnel(
        tunnel_id: str, _admin: AdminSession = Depends(require_admin_session)
    ):
        """Delete a Cloudflare tunnel and clear the agent's tunnel fields."""
        if not cloudflare_module.is_configured():
            raise HTTPException(status_code=400, detail="Cloudflare not configured")

        try:
            tunnels = await cloudflare_module.list_tunnels()
            match = next((t for t in tunnels if t.get("tunnel_id") == tunnel_id), None)
            if match and _is_protected_tunnel_name(match.get("name")):
                raise HTTPException(
                    status_code=400,
                    detail="Refusing to delete the protected control plane tunnel.",
                )
        except HTTPException:
            raise
        except Exception as exc:
            logger.warning(f"Cloudflare delete tunnel precheck failed: {exc}")

        deleted = await cloudflare_module.delete_tunnel(tunnel_id)
        for agent in agent_store.list():
            if agent.tunnel_id == tunnel_id:
                agent_store.clear_tunnel_info(agent.agent_id)
                logger.info(f"Cleared tunnel info for agent {agent.agent_id}")
        return {"deleted": deleted, "tunnel_id": tunnel_id}

    @app.delete("/api/v1/admin/cloudflare/dns/{record_id}")
    async def cloudflare_delete_dns(
        record_id: str, _admin: AdminSession = Depends(require_admin_session)
    ):
        """Delete a Cloudflare DNS record by ID."""
        if not cloudflare_module.is_configured():
            raise HTTPException(status_code=400, detail="Cloudflare not configured")

        deleted = await cloudflare_module.delete_dns_record_by_id(record_id)
        return {"deleted": deleted, "record_id": record_id}

    async def cloudflare_cleanup(
        request: CloudflareCleanupRequest | None = None,
    ) -> CloudflareCleanupResponse:
        """Bulk delete all orphaned tunnels and DNS records."""
        if not cloudflare_module.is_configured():
            raise HTTPException(status_code=400, detail="Cloudflare not configured")

        dry_run = bool(request and request.dry_run)

        tunnels = await cloudflare_module.list_tunnels()
        agents = agent_store.list()
        tunnel_to_agent = {}
        for agent in agents:
            if agent.tunnel_id:
                tunnel_to_agent[agent.tunnel_id] = agent

        orphan_tunnel_ids = [
            tunnel["tunnel_id"]
            for tunnel in tunnels
            if tunnel.get("tunnel_id")
            and tunnel["tunnel_id"] not in tunnel_to_agent
            and _is_agent_tunnel_name(tunnel.get("name"))
            and not _is_protected_tunnel_name(tunnel.get("name"))
        ]

        records = await cloudflare_module.list_dns_records()
        tunnel_ids = {tunnel.get("tunnel_id") for tunnel in tunnels if tunnel.get("tunnel_id")}
        orphan_dns_record_ids: list[str] = []
        for record in records:
            content = (record.get("content") or "").strip()
            if not content.endswith(".cfargotunnel.com"):
                continue
            linked_id = content.replace(".cfargotunnel.com", "")
            if linked_id in orphan_tunnel_ids or linked_id not in tunnel_ids:
                if record.get("record_id"):
                    orphan_dns_record_ids.append(record["record_id"])

        if dry_run:
            return CloudflareCleanupResponse(
                dry_run=True,
                tunnels_deleted=0,
                dns_deleted=0,
                tunnels_candidates=len(orphan_tunnel_ids),
                dns_candidates=len(orphan_dns_record_ids),
                tunnels_failed=0,
                dns_failed=0,
            )

        tunnel_results = await cloudflare_delete_many_fn(
            ids=orphan_tunnel_ids,
            delete_fn=cloudflare_module.delete_tunnel,
            concurrency=8,
        )
        tunnels_deleted = int(tunnel_results["deleted"])
        tunnels_failed = int(tunnel_results["failed"])

        dns_results = await cloudflare_delete_many_fn(
            ids=orphan_dns_record_ids,
            delete_fn=cloudflare_module.delete_dns_record_by_id,
            concurrency=8,
        )
        dns_deleted = int(dns_results["deleted"])
        dns_failed = int(dns_results["failed"])

        logger.info(
            "Cloudflare cleanup complete: "
            f"tunnels_deleted={tunnels_deleted}/{len(orphan_tunnel_ids)} "
            f"dns_deleted={dns_deleted}/{len(orphan_dns_record_ids)} "
            f"tunnels_failed={tunnels_failed} dns_failed={dns_failed}"
        )
        return CloudflareCleanupResponse(
            dry_run=False,
            tunnels_deleted=tunnels_deleted,
            dns_deleted=dns_deleted,
            tunnels_candidates=len(orphan_tunnel_ids),
            dns_candidates=len(orphan_dns_record_ids),
            tunnels_failed=tunnels_failed,
            dns_failed=dns_failed,
        )

    @app.post("/api/v1/admin/cleanup/orphans", response_model=UnifiedOrphanCleanupResponse)
    async def unified_orphan_cleanup(
        request: UnifiedOrphanCleanupRequest,
        session: AdminSession = Depends(require_admin_session),
    ):
        """Unified orphan cleanup across Cloudflare + external provisioner inventory."""
        detail_parts: list[str] = []

        cf_configured = cloudflare_module.is_configured()
        cf_result: CloudflareCleanupResponse | None = None
        if request.cloudflare:
            if not cf_configured:
                detail_parts.append("Cloudflare is not configured.")
            else:
                try:
                    cf_result = await cloudflare_cleanup(
                        CloudflareCleanupRequest(dry_run=request.dry_run),
                    )
                except Exception as exc:
                    detail_parts.append(f"Cloudflare cleanup failed: {exc}")

        ext_result: ExternalCloudCleanupResponse | None = None
        ext_configured = bool(get_setting_fn("provisioner.cleanup_url").strip())
        if request.external_cloud:
            if not ext_configured:
                detail_parts.append("External cloud cleanup webhook is not configured.")
            else:
                try:
                    (
                        configured,
                        dispatched,
                        status_code,
                        ext_detail,
                        payload,
                    ) = await dispatch_external_cleanup_fn(
                        ExternalCloudCleanupRequest(
                            dry_run=request.dry_run,
                            only_orphaned=request.external_only_orphaned,
                            providers=request.external_providers,
                            resource_ids=request.external_resource_ids,
                            reason=request.reason,
                        ).model_dump()
                    )
                    ext_result = ExternalCloudCleanupResponse(
                        configured=configured,
                        dispatched=dispatched,
                        dry_run=request.dry_run,
                        requested_count=extract_cleanup_requested_count_fn(payload),
                        status_code=status_code,
                        detail=ext_detail
                        or (
                            payload.get("detail")
                            if isinstance(payload.get("detail"), str)
                            else None
                        ),
                    )
                    ext_configured = configured
                except Exception as exc:
                    detail_parts.append(f"External cloud cleanup failed: {exc}")

        detail = " ".join([part for part in detail_parts if part]).strip() or None
        return UnifiedOrphanCleanupResponse(
            dry_run=request.dry_run,
            cloudflare_configured=cf_configured,
            external_cloud_configured=ext_configured,
            cloudflare=cf_result,
            external_cloud=ext_result,
            detail=detail,
        )

    @app.post("/api/v1/admin/agents/{agent_id}/cleanup", response_model=AdminAgentCleanupResponse)
    async def admin_agent_cleanup(
        agent_id: str,
        request: AdminAgentCleanupRequest,
        session: AdminSession = Depends(require_admin_session),
    ):
        """Delete an agent and attempt to delete linked external cloud resources as well."""
        agent = get_or_404_fn(agent_store, agent_id, "Agent")
        dry_run = bool(request.dry_run)

        external_candidates: list[str] = []
        external_response: ExternalCloudCleanupResponse | None = None
        detail_parts: list[str] = []

        configured, _status_code, inv_detail, _payload = await fetch_external_inventory_fn()
        if not configured:
            detail_parts.append("External inventory not configured; skipping linked VM cleanup.")
        elif inv_detail:
            detail_parts.append(
                f"External inventory error; skipping linked VM cleanup: {inv_detail}"
            )
        else:
            inventory = await list_external_cloud_resources_fn(_admin=session)
            vm_name_norm = (agent.vm_name or "").strip().lower()
            for resource in inventory.resources:
                if resource.linked_agent_id == agent_id:
                    external_candidates.append(resource.resource_id)
                    continue
                if vm_name_norm and (resource.linked_vm_name or "").strip().lower() == vm_name_norm:
                    external_candidates.append(resource.resource_id)

            external_candidates = sorted(
                {candidate for candidate in external_candidates if candidate}
            )

            if external_candidates:
                if dry_run:
                    external_response = ExternalCloudCleanupResponse(
                        configured=bool(get_setting_fn("provisioner.cleanup_url").strip()),
                        dispatched=False,
                        dry_run=True,
                        requested_count=len(external_candidates),
                        status_code=None,
                        detail="dry run",
                    )
                else:
                    ext_cfg = bool(get_setting_fn("provisioner.cleanup_url").strip())
                    if not ext_cfg:
                        detail_parts.append(
                            "External cleanup webhook not configured; skipping linked VM deletion."
                        )
                    else:
                        (
                            configured2,
                            dispatched,
                            status_code,
                            ext_detail,
                            payload2,
                        ) = await dispatch_external_cleanup_fn(
                            ExternalCloudCleanupRequest(
                                dry_run=False,
                                only_orphaned=False,
                                providers=[],
                                resource_ids=external_candidates,
                                reason=request.reason,
                            ).model_dump()
                        )
                        external_response = ExternalCloudCleanupResponse(
                            configured=configured2,
                            dispatched=dispatched,
                            dry_run=False,
                            requested_count=extract_cleanup_requested_count_fn(payload2)
                            or len(external_candidates),
                            status_code=status_code,
                            detail=ext_detail
                            or (
                                payload2.get("detail")
                                if isinstance(payload2.get("detail"), str)
                                else None
                            ),
                        )

        cloudflare_deleted = False
        agent_deleted = False
        if not dry_run:
            if agent.tunnel_id and cloudflare_module.is_configured():
                try:
                    await cloudflare_module.delete_tunnel(agent.tunnel_id)
                    if agent.hostname:
                        await cloudflare_module.delete_dns_record(agent.hostname)
                    cloudflare_deleted = True
                except Exception as exc:
                    detail_parts.append(f"Cloudflare cleanup failed for agent: {exc}")

            capacity_reservation_store.expire_open_for_agent(agent.agent_id)
            agent_deleted = bool(agent_store.delete(agent.agent_id))

        detail = " ".join([part for part in detail_parts if part]).strip() or None
        return AdminAgentCleanupResponse(
            dry_run=dry_run,
            agent_id=agent.agent_id,
            vm_name=agent.vm_name,
            cloudflare_deleted=cloudflare_deleted,
            agent_deleted=agent_deleted,
            external_cloud=external_response,
            external_candidates=len(external_candidates),
            detail=detail,
        )

    @app.post(
        "/api/v1/admin/agents/cleanup/stale",
        response_model=AdminStaleAgentCleanupResponse,
    )
    async def admin_cleanup_stale_agents(
        request: AdminStaleAgentCleanupRequest,
        _admin: AdminSession = Depends(require_admin_session),
    ):
        """Admin-only: delete stale agents (DB + Cloudflare tunnel/DNS best-effort)."""
        stale_hours = float(
            request.stale_hours
            if request.stale_hours is not None
            else get_setting_int_fn("operational.agent_stale_hours", fallback=24)
        )
        if stale_hours <= 0:
            raise HTTPException(status_code=422, detail="stale_hours must be > 0")

        include_deployed = bool(request.include_deployed)
        dry_run = bool(request.dry_run)

        stale_agents = agent_store.get_stale_agents(timedelta(hours=stale_hours))
        deleted: list[dict] = []
        skipped: list[dict] = []
        errors: list[str] = []

        for agent in stale_agents:
            try:
                if (
                    not include_deployed
                    and agent.current_deployment_id
                    and agent.status == "deployed"
                ):
                    skipped.append(
                        {
                            "agent_id": agent.agent_id,
                            "vm_name": agent.vm_name,
                            "reason": "active_deployment",
                        }
                    )
                    continue

                if dry_run:
                    deleted.append(
                        {
                            "agent_id": agent.agent_id,
                            "vm_name": agent.vm_name,
                            "dry_run": True,
                        }
                    )
                    continue

                if agent.tunnel_id and cloudflare_module.is_configured():
                    try:
                        await cloudflare_module.delete_tunnel(agent.tunnel_id)
                        if agent.hostname:
                            await cloudflare_module.delete_dns_record(agent.hostname)
                    except Exception as exc:
                        logger.warning(
                            f"Failed to clean up Cloudflare for stale agent {agent.agent_id}: {exc}"
                        )

                capacity_reservation_store.expire_open_for_agent(agent.agent_id)
                ok = bool(agent_store.delete(agent.agent_id))
                if ok:
                    deleted.append({"agent_id": agent.agent_id, "vm_name": agent.vm_name})
                else:
                    errors.append(f"Failed to delete agent record: {agent.agent_id}")
            except Exception as exc:
                errors.append(f"{agent.agent_id}: {exc}")

        return AdminStaleAgentCleanupResponse(
            dry_run=dry_run,
            stale_hours=stale_hours,
            candidates=len(stale_agents),
            deleted_agents=deleted,
            skipped_agents=skipped,
            errors=errors,
        )
