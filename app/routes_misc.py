"""Miscellaneous route registration for trust/proxy, logs, and static UI."""

from __future__ import annotations

import asyncio
import io
import logging
import shutil
import zipfile
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx
from fastapi import FastAPI, Header, HTTPException, Query, Request
from fastapi.responses import FileResponse, StreamingResponse

from . import proxy


def register_misc_routes(
    app: FastAPI,
    *,
    get_proxy_url: Callable[[], str],
    generate_tdx_quote_fn: Callable[[str | None], Any],
    get_or_404_fn: Callable[[Any, str, str], Any],
    agent_store: Any,
    log_handler: Any,
    admin_tokens: set[str],
    static_dir: Path,
) -> None:
    """Register endpoints that are independent from core deploy/capacity flows."""

    @app.get("/api/v1/attestation")
    async def get_control_plane_attestation(
        nonce: str = Query(None, description="Nonce to include in attestation"),
    ):
        """Get the control plane's TDX attestation."""
        quote_result = generate_tdx_quote_fn(nonce)
        result = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "nonce": nonce,
        }
        if quote_result.error:
            result["error"] = quote_result.error
        else:
            result["quote_b64"] = quote_result.quote_b64
            result["measurements"] = quote_result.measurements
        return result

    @app.get("/api/v1/proxy")
    async def get_proxy_endpoint():
        """Get the proxy endpoint for routing service traffic."""
        proxy_url = get_proxy_url()
        return {
            "proxy_url": proxy_url,
            "proxies": [proxy_url],
            "note": "Route service requests through /proxy/{service_name}/{path}",
        }

    @app.api_route(
        "/proxy/{service_name}/{path:path}",
        methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"],
    )
    async def proxy_service_request(
        service_name: str,
        path: str,
        request: Request,
    ):
        """Proxy a request to a service through the control plane."""
        return await proxy.proxy_request(service_name, path, request)

    @app.get("/api/v1/agents/{agent_id}/logs")
    async def get_agent_logs(
        agent_id: str,
        since: str = Query("5m", description="Logs since (e.g., '5m', '1h')"),
        container: str | None = Query(None, description="Filter by container name"),
    ):
        """Get logs for a specific agent (pull model)."""
        agent = get_or_404_fn(agent_store, agent_id, "Agent")
        if not agent.hostname:
            raise HTTPException(
                status_code=400,
                detail="Agent does not have a tunnel hostname - cannot pull logs",
            )

        try:
            agent_url = f"https://{agent.hostname}/api/logs"
            params = {"since": since}
            if container:
                params["container"] = container

            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.get(agent_url, params=params)
                response.raise_for_status()
                content_type = response.headers.get("content-type", "")
                if "application/json" not in content_type:
                    raise HTTPException(
                        status_code=502,
                        detail=f"Agent returned non-JSON response (content-type: {content_type}). "
                        "The tunnel may be routing to the workload instead of the agent API.",
                    )

                try:
                    return response.json()
                except Exception as exc:
                    body_preview = response.text[:100] if response.text else "(empty)"
                    raise HTTPException(
                        status_code=502,
                        detail=f"Agent returned invalid JSON: {body_preview}. "
                        "The tunnel may be routing to the workload instead of the agent API.",
                    ) from exc
        except httpx.RequestError as exc:
            raise HTTPException(
                status_code=502,
                detail=f"Failed to reach agent at {agent.hostname}: {exc}",
            ) from exc
        except httpx.HTTPStatusError as exc:
            raise HTTPException(
                status_code=502,
                detail=f"Agent returned error {exc.response.status_code}: {exc.response.text[:200]}",
            ) from exc

    @app.get("/api/v1/agents/{agent_id}/stats")
    async def get_agent_stats(agent_id: str):
        """Get system stats for a specific agent (pull model)."""
        agent = get_or_404_fn(agent_store, agent_id, "Agent")
        if not agent.hostname:
            raise HTTPException(
                status_code=400,
                detail="Agent does not have a tunnel hostname - cannot pull stats",
            )

        try:
            agent_url = f"https://{agent.hostname}/api/stats"
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.get(agent_url)
                response.raise_for_status()
                content_type = response.headers.get("content-type", "")
                if "application/json" not in content_type:
                    raise HTTPException(
                        status_code=502,
                        detail=f"Agent returned non-JSON response (content-type: {content_type}). "
                        "The tunnel may be routing to the workload instead of the agent API.",
                    )

                try:
                    return response.json()
                except Exception as exc:
                    body_preview = response.text[:100] if response.text else "(empty)"
                    raise HTTPException(
                        status_code=502,
                        detail=f"Agent returned invalid JSON: {body_preview}. "
                        "The tunnel may be routing to the workload instead of the agent API.",
                    ) from exc
        except httpx.RequestError as exc:
            raise HTTPException(
                status_code=502,
                detail=f"Failed to reach agent at {agent.hostname}: {exc}",
            ) from exc
        except httpx.HTTPStatusError as exc:
            raise HTTPException(
                status_code=502,
                detail=f"Agent returned error {exc.response.status_code}: {exc.response.text[:200]}",
            ) from exc

    @app.get("/api/v1/logs/control-plane")
    async def get_control_plane_logs(
        lines: int = Query(100, description="Number of lines to return", le=1000),
        min_level: str = Query("INFO", description="Minimum log level"),
    ):
        """Get recent control plane logs from in-memory buffer."""
        level_num = getattr(logging, min_level.upper(), logging.INFO)
        filtered = [
            rec for rec in log_handler.records if getattr(logging, rec["level"], 0) >= level_num
        ]
        return {"logs": filtered[-lines:], "total": len(filtered)}

    @app.get("/api/v1/logs/containers")
    async def get_container_logs(
        since: str = Query("5m", description="Logs since (e.g., '5m', '1h')"),
        container: str | None = Query(None, description="Filter by container name"),
        lines: int = Query(200, description="Max lines per container", le=1000),
    ):
        """Get Docker container logs from the host via mounted docker socket."""
        if not shutil.which("docker"):
            return {"logs": [], "count": 0, "error": "docker CLI not available"}

        try:
            ps_proc = await asyncio.create_subprocess_exec(
                "docker",
                "ps",
                "--format",
                "{{.Names}}",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            ps_stdout, ps_stderr = await asyncio.wait_for(ps_proc.communicate(), timeout=10)
        except (asyncio.TimeoutError, OSError) as exc:
            return {"logs": [], "count": 0, "error": f"Failed to list containers: {exc}"}

        if ps_proc.returncode != 0:
            err = ps_stderr.decode(errors="replace").strip()
            return {"logs": [], "count": 0, "error": f"docker ps failed: {err}"}

        container_names = [n for n in ps_stdout.decode().strip().split("\n") if n]
        if container and container_names:
            container_names = [n for n in container_names if container in n]

        all_logs = []
        for name in container_names:
            try:
                log_proc = await asyncio.create_subprocess_exec(
                    "docker",
                    "logs",
                    "--since",
                    since,
                    "--tail",
                    str(lines),
                    name,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.STDOUT,
                )
                log_stdout, _ = await asyncio.wait_for(log_proc.communicate(), timeout=10)
                for line in log_stdout.decode(errors="replace").strip().split("\n"):
                    if line:
                        all_logs.append({"container": name, "line": line})
            except (asyncio.TimeoutError, OSError):
                all_logs.append({"container": name, "line": "[error fetching logs]"})

        return {"logs": all_logs, "count": len(all_logs)}

    @app.get("/api/v1/logs/export")
    async def export_logs(
        since: str = Query("1h", description="Container logs since (e.g., '5m', '1h')"),
        min_level: str = Query("DEBUG", description="Min level for control-plane logs"),
    ):
        """Export control plane + container logs as a zip file."""
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            level_num = getattr(logging, min_level.upper(), logging.DEBUG)
            filtered = [
                rec for rec in log_handler.records if getattr(logging, rec["level"], 0) >= level_num
            ]
            cp_lines = [
                f"{rec['timestamp']} {rec['level']:7s} [{rec['logger']}] {rec['message']}"
                for rec in filtered
            ]
            zf.writestr("control-plane.log", "\n".join(cp_lines))

            container_lines: list[str] = []
            if shutil.which("docker"):
                try:
                    ps_proc = await asyncio.create_subprocess_exec(
                        "docker",
                        "ps",
                        "--format",
                        "{{.Names}}",
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                    )
                    ps_stdout, _ = await asyncio.wait_for(ps_proc.communicate(), timeout=10)
                    container_names = [n for n in ps_stdout.decode().strip().split("\n") if n]

                    for name in container_names:
                        try:
                            log_proc = await asyncio.create_subprocess_exec(
                                "docker",
                                "logs",
                                "--since",
                                since,
                                name,
                                stdout=asyncio.subprocess.PIPE,
                                stderr=asyncio.subprocess.STDOUT,
                            )
                            log_stdout, _ = await asyncio.wait_for(
                                log_proc.communicate(), timeout=10
                            )
                            for line in log_stdout.decode(errors="replace").strip().split("\n"):
                                if line:
                                    container_lines.append(f"[{name}] {line}")
                        except (asyncio.TimeoutError, OSError):
                            container_lines.append(f"[{name}] [error fetching logs]")
                except (asyncio.TimeoutError, OSError):
                    container_lines.append("[error] failed to list containers")
            else:
                container_lines.append("[info] docker CLI not available")

            zf.writestr("containers.log", "\n".join(container_lines))

        buf.seek(0)
        ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        return StreamingResponse(
            buf,
            media_type="application/zip",
            headers={"Content-Disposition": f'attachment; filename="easyenclave-logs-{ts}.zip"'},
        )

    @app.post("/admin/logout")
    async def admin_logout(authorization: str | None = Header(None)):
        """Invalidate admin session token."""
        if authorization and authorization.startswith("Bearer "):
            admin_tokens.discard(authorization[7:])
        return {"message": "Logged out"}

    @app.get("/admin")
    async def serve_admin():
        """Serve the admin dashboard."""
        admin_path = static_dir / "admin.html"
        if admin_path.exists():
            return FileResponse(admin_path)
        raise HTTPException(status_code=404, detail="Admin page not found")

    @app.get("/")
    async def serve_gui():
        """Serve the web GUI."""
        index_path = static_dir / "index.html"
        if index_path.exists():
            return FileResponse(index_path)
        return {"message": "EasyEnclave Discovery Service", "docs": "/docs"}
