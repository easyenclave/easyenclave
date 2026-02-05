"""Docker Registry HTTP API client for resolving image tags to digests."""

from __future__ import annotations

import logging
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


async def _get_docker_hub_token(client: httpx.AsyncClient, name: str) -> str:
    """Get an anonymous auth token for Docker Hub."""
    resp = await client.get(
        "https://auth.docker.io/token",
        params={"service": "registry.docker.io", "scope": f"repository:{name}:pull"},
    )
    resp.raise_for_status()
    return resp.json()["token"]


async def resolve_digest(image: str, client: httpx.AsyncClient | None = None) -> str:
    """Resolve a Docker image reference to its manifest digest.

    Uses the Docker Registry HTTP API v2 to fetch the manifest and read
    the Docker-Content-Digest header.

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

        # Get auth token for Docker Hub
        if ref.registry == "registry-1.docker.io":
            token = await _get_docker_hub_token(client, ref.name)
            headers["Authorization"] = f"Bearer {token}"

        url = f"https://{ref.registry}/v2/{ref.name}/manifests/{ref.tag}"
        resp = await client.head(url, headers=headers, follow_redirects=True)
        resp.raise_for_status()

        digest = resp.headers.get("Docker-Content-Digest")
        if not digest:
            # Fallback: GET request (some registries don't return digest on HEAD)
            resp = await client.get(url, headers=headers, follow_redirects=True)
            resp.raise_for_status()
            digest = resp.headers.get("Docker-Content-Digest")

        if not digest:
            raise ValueError(f"Registry did not return Docker-Content-Digest for {image}")

        logger.info(f"Resolved {image} -> {digest}")
        return digest

    finally:
        if should_close:
            await client.aclose()
