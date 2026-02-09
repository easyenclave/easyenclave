"""Docker Registry HTTP API client for resolving image tags to digests."""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass

import httpx

logger = logging.getLogger(__name__)

# Manifest media types to request (in order of preference)
MANIFEST_TYPES = ",".join([
    "application/vnd.docker.distribution.manifest.v2+json",
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
    "application/vnd.oci.image.index.v1+json",
])


@dataclass
class ImageRef:
    """Parsed Docker image reference."""

    registry: str  # e.g. "registry-1.docker.io"
    name: str  # e.g. "library/nginx"
    tag: str  # e.g. "latest"


def parse_image_ref(image: str) -> ImageRef:
    """Parse a Docker image reference into registry, name, and tag.

    Examples:
        nginx:latest -> registry-1.docker.io / library/nginx : latest
        ghcr.io/org/repo:v1 -> ghcr.io / org/repo : v1
        myregistry.com/img -> myregistry.com / img : latest
        ubuntu -> registry-1.docker.io / library/ubuntu : latest
    """
    # Split off tag/digest
    tag = "latest"
    if "@" in image:
        # Already a digest reference, no resolution needed
        name_part, digest = image.rsplit("@", 1)
        return ImageRef(registry="", name=name_part, tag=digest)

    if ":" in image.split("/")[-1]:
        image, tag = image.rsplit(":", 1)

    # Determine registry
    parts = image.split("/")
    if len(parts) == 1:
        # Simple name like "nginx" -> Docker Hub official image
        return ImageRef(registry="registry-1.docker.io", name=f"library/{image}", tag=tag)
    elif "." in parts[0] or ":" in parts[0] or parts[0] == "localhost":
        # Explicit registry
        registry = parts[0]
        name = "/".join(parts[1:])
        return ImageRef(registry=registry, name=name, tag=tag)
    else:
        # Docker Hub user image like "user/repo"
        return ImageRef(registry="registry-1.docker.io", name=image, tag=tag)


def _parse_www_authenticate(header: str) -> dict[str, str]:
    """Parse a WWW-Authenticate Bearer challenge header.

    Example: 'Bearer realm="https://ghcr.io/token",service="ghcr.io",scope="repository:org/repo:pull"'
    Returns: {"realm": "https://ghcr.io/token", "service": "ghcr.io", "scope": "repository:org/repo:pull"}
    """
    params: dict[str, str] = {}
    for match in re.finditer(r'(\w+)="([^"]*)"', header):
        params[match.group(1)] = match.group(2)
    return params


async def _get_anonymous_token(
    client: httpx.AsyncClient,
    realm: str,
    service: str,
    scope: str,
) -> str:
    """Get an anonymous token from an OCI registry token endpoint.

    This implements the standard OCI Distribution token exchange:
    https://distribution.github.io/distribution/spec/auth/token/
    """
    params: dict[str, str] = {"scope": scope}
    if service:
        params["service"] = service
    resp = await client.get(realm, params=params)
    resp.raise_for_status()
    data = resp.json()
    return data.get("token") or data.get("access_token", "")


async def _request_with_auth(
    client: httpx.AsyncClient,
    method: str,
    url: str,
    headers: dict[str, str],
    ref: ImageRef,
) -> httpx.Response:
    """Make a registry request, handling 401 challenges with token exchange.

    If the initial request returns 401 with a WWW-Authenticate Bearer challenge,
    obtains an anonymous token and retries.
    """
    resp = await client.request(method, url, headers=headers, follow_redirects=True)

    if resp.status_code != 401:
        return resp

    # Parse WWW-Authenticate challenge
    www_auth = resp.headers.get("www-authenticate", "")
    if "bearer" not in www_auth.lower():
        resp.raise_for_status()  # Not a Bearer challenge, raise the 401

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


async def resolve_digest(image: str, client: httpx.AsyncClient | None = None) -> str:
    """Resolve a Docker image reference to its manifest digest.

    Uses the Docker Registry HTTP API v2 to fetch the manifest and read
    the Docker-Content-Digest header. Handles anonymous token exchange
    for any OCI-compliant registry (Docker Hub, GHCR, ECR, GCR, etc.).

    Returns the digest string (e.g. "sha256:abc123...").
    """
    ref = parse_image_ref(image)

    # Already a digest reference
    if ref.tag.startswith("sha256:"):
        return ref.tag

    should_close = client is None
    if client is None:
        client = httpx.AsyncClient(timeout=30.0)

    try:
        headers = {"Accept": MANIFEST_TYPES}
        url = f"https://{ref.registry}/v2/{ref.name}/manifests/{ref.tag}"

        resp = await _request_with_auth(client, "HEAD", url, headers, ref)
        resp.raise_for_status()

        digest = resp.headers.get("Docker-Content-Digest")
        if not digest:
            # Fallback: GET request (some registries don't return digest on HEAD)
            resp = await _request_with_auth(client, "GET", url, headers, ref)
            resp.raise_for_status()
            digest = resp.headers.get("Docker-Content-Digest")

        if not digest:
            raise ValueError(f"Registry did not return Docker-Content-Digest for {image}")

        logger.info(f"Resolved {image} -> {digest}")
        return digest

    finally:
        if should_close:
            await client.aclose()
