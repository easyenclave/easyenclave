"""App version measurement (compose -> immutable image digests + optional signature verification).

This replaces the external "measuring-enclave" service:
- The control plane already runs inside a TDX-attested environment and can
  safely perform digest resolution and signature verification itself.
- Avoids dedicating/holding agent capacity just to run a measurer service.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import logging
import os
import re
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone

import httpx
import yaml

logger = logging.getLogger(__name__)


class MeasurementError(RuntimeError):
    pass


@dataclass(frozen=True)
class ImageRef:
    registry: str  # e.g. "registry-1.docker.io"
    name: str  # e.g. "library/nginx"
    tag: str  # e.g. "latest" or "sha256:..."


MANIFEST_TYPES = ",".join(
    [
        "application/vnd.docker.distribution.manifest.v2+json",
        "application/vnd.oci.image.manifest.v1+json",
        "application/vnd.docker.distribution.manifest.list.v2+json",
        "application/vnd.oci.image.index.v1+json",
    ]
)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def parse_image_ref(image: str) -> ImageRef:
    """Parse a Docker image reference into registry, name, and tag."""
    image = (image or "").strip()
    if not image:
        raise ValueError("Empty image ref")

    # Digest ref: repo@sha256:...
    if "@" in image:
        name_part, digest = image.rsplit("@", 1)
        # registry is unused in this case; keep empty so resolve_digest() can fast-path.
        return ImageRef(registry="", name=name_part, tag=digest)

    tag = "latest"
    if ":" in image.split("/")[-1]:
        image, tag = image.rsplit(":", 1)

    parts = image.split("/")
    if len(parts) == 1:
        return ImageRef(registry="registry-1.docker.io", name=f"library/{image}", tag=tag)
    if "." in parts[0] or ":" in parts[0] or parts[0] == "localhost":
        return ImageRef(registry=parts[0], name="/".join(parts[1:]), tag=tag)
    return ImageRef(registry="registry-1.docker.io", name=image, tag=tag)


def _parse_www_authenticate(header: str) -> dict[str, str]:
    params: dict[str, str] = {}
    for match in re.finditer(r'(\w+)="([^"]*)"', header or ""):
        params[match.group(1)] = match.group(2)
    return params


async def _get_anonymous_token(
    client: httpx.AsyncClient, realm: str, service: str, scope: str
) -> str:
    params: dict[str, str] = {"scope": scope}
    if service:
        params["service"] = service
    resp = await client.get(realm, params=params)
    resp.raise_for_status()
    data = resp.json()
    return data.get("token") or data.get("access_token") or ""


async def _request_with_auth(
    client: httpx.AsyncClient, method: str, url: str, headers: dict[str, str], ref: ImageRef
) -> httpx.Response:
    resp = await client.request(method, url, headers=headers, follow_redirects=True)
    if resp.status_code != 401:
        return resp

    www_auth = resp.headers.get("www-authenticate", "")
    if "bearer" not in www_auth.lower():
        resp.raise_for_status()

    challenge = _parse_www_authenticate(www_auth)
    realm = challenge.get("realm", "")
    if not realm:
        resp.raise_for_status()

    service = challenge.get("service", "")
    scope = challenge.get("scope", f"repository:{ref.name}:pull")
    token = await _get_anonymous_token(client, realm, service, scope)
    if not token:
        resp.raise_for_status()

    headers = {**headers, "Authorization": f"Bearer {token}"}
    return await client.request(method, url, headers=headers, follow_redirects=True)


async def resolve_digest(image: str, client: httpx.AsyncClient) -> str:
    """Resolve image:tag to sha256 digest using the OCI Distribution API."""
    ref = parse_image_ref(image)
    if ref.tag.startswith("sha256:"):
        return ref.tag

    headers = {"Accept": MANIFEST_TYPES}
    url = f"https://{ref.registry}/v2/{ref.name}/manifests/{ref.tag}"

    resp = await _request_with_auth(client, "HEAD", url, headers, ref)
    resp.raise_for_status()
    digest = resp.headers.get("Docker-Content-Digest")
    if digest:
        return digest

    # Some registries omit digest on HEAD.
    resp = await _request_with_auth(client, "GET", url, headers, ref)
    resp.raise_for_status()
    digest = resp.headers.get("Docker-Content-Digest")
    if not digest:
        raise MeasurementError(f"Registry did not return Docker-Content-Digest for {image}")
    return digest


def verify_signature(image: str, digest: str, *, mode: str) -> dict:
    """Verify container signature with cosign (keyless OIDC).

    Returns:
      {signature_verified: bool|None, signature_error: str|None, signed_by: str|None, transparency_log_index: int|None}
    """
    mode = (mode or "warn").strip().lower()
    if mode == "disabled":
        return {
            "signature_verified": None,
            "signature_error": "signature verification disabled",
            "signed_by": None,
            "transparency_log_index": None,
        }

    issuer = os.getenv(
        "COSIGN_CERTIFICATE_OIDC_ISSUER", "https://token.actions.githubusercontent.com"
    )
    identity_re = os.getenv(
        "COSIGN_CERTIFICATE_IDENTITY_REGEXP",
        r"^https://github.com/.+/.+/.github/workflows/.+@refs/.*$",
    )
    cosign_bin = os.getenv("COSIGN_BIN", "cosign")
    digest_ref = image if "@sha256:" in image else f"{image}@{digest}"

    cmd = [
        cosign_bin,
        "verify",
        "--output",
        "json",
        "--certificate-oidc-issuer",
        issuer,
        "--certificate-identity-regexp",
        identity_re,
        digest_ref,
    ]

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
    except FileNotFoundError:
        return {
            "signature_verified": False,
            "signature_error": f"{cosign_bin} binary not found",
            "signed_by": None,
            "transparency_log_index": None,
        }
    except subprocess.TimeoutExpired:
        return {
            "signature_verified": False,
            "signature_error": f"cosign verify timed out for {digest_ref}",
            "signed_by": None,
            "transparency_log_index": None,
        }

    if proc.returncode != 0:
        err = (proc.stderr or proc.stdout or "cosign verify failed").strip().splitlines()[0]
        return {
            "signature_verified": False,
            "signature_error": err,
            "signed_by": None,
            "transparency_log_index": None,
        }

    transparency_log_index = None
    match = re.search(r'"logIndex"\s*:\s*(\d+)', proc.stdout or "")
    if match:
        try:
            transparency_log_index = int(match.group(1))
        except ValueError:
            transparency_log_index = None

    signed_by = None
    try:
        parsed = json.loads(proc.stdout)
        if isinstance(parsed, list) and parsed:
            cert = parsed[0].get("optional", {}).get("Subject")
            if isinstance(cert, str) and cert:
                signed_by = cert
    except Exception:
        signed_by = None

    return {
        "signature_verified": True,
        "signature_error": None,
        "signed_by": signed_by or identity_re,
        "transparency_log_index": transparency_log_index,
    }


async def measure_compose(
    compose_b64: str,
    *,
    node_size: str = "",
    signature_mode: str = "warn",
) -> dict:
    """Return measurement payload compatible with MeasurementCallbackRequest.measurement."""
    try:
        compose_bytes = base64.b64decode(compose_b64)
    except Exception as exc:
        raise MeasurementError(f"Invalid compose (base64 decode failed): {exc}") from exc

    try:
        compose_dict = yaml.safe_load(compose_bytes) or {}
    except Exception as exc:
        raise MeasurementError(f"Invalid compose (YAML parse failed): {exc}") from exc

    compose_hash = hashlib.sha256(compose_bytes).hexdigest()
    services = compose_dict.get("services", {}) if isinstance(compose_dict, dict) else {}
    if not isinstance(services, dict):
        services = {}

    resolved_images: dict[str, dict] = {}
    async with httpx.AsyncClient(timeout=60.0) as client:
        for svc_name, svc_config in services.items():
            if not isinstance(svc_config, dict):
                continue
            image = svc_config.get("image")
            if not image:
                continue
            digest = await asyncio.wait_for(resolve_digest(str(image), client), timeout=60)
            sig_info = await asyncio.to_thread(
                verify_signature, str(image), digest, mode=signature_mode
            )
            resolved_images[str(svc_name)] = {
                "original": str(image),
                "digest": digest,
                "signature_verified": sig_info.get("signature_verified"),
                "signed_by": sig_info.get("signed_by"),
                "transparency_log_index": sig_info.get("transparency_log_index"),
                "signature_error": sig_info.get("signature_error"),
            }

    return {
        "measurement_type": "cp_digest_resolution",
        "measured_at": _now_iso(),
        "node_size": node_size or "",
        "compose_hash": compose_hash,
        "resolved_images": resolved_images,
    }
