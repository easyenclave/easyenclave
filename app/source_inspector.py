"""Source code inspection for app publishing.

This module provides functions to download source code from GitHub and scan
it for forbidden keywords. Apps with forbidden keywords are rejected from
the catalog to prevent malicious code from being deployed.
"""

from __future__ import annotations

import base64
import logging
import re
from dataclasses import dataclass

import httpx

logger = logging.getLogger(__name__)

# Forbidden keywords (case-insensitive)
FORBIDDEN_KEYWORDS = ["HACK", "HAX", "HAX0R"]

# Maximum source code size (10MB)
MAX_SOURCE_SIZE = 10 * 1024 * 1024


@dataclass
class InspectionResult:
    """Result of source code inspection."""

    passed: bool
    rejection_reason: str | None = None
    files_scanned: int = 0
    total_size: int = 0


async def download_github_source(repo: str, commit: str) -> dict[str, str]:
    """Download source files from GitHub.

    Uses the GitHub API to fetch the repository tree and download all
    text files up to the size limit.

    Args:
        repo: GitHub repo (e.g., "org/repo")
        commit: Git commit SHA

    Returns:
        Dict of {filepath: content} for all text files

    Raises:
        ValueError: If source exceeds MAX_SOURCE_SIZE
        httpx.HTTPError: If GitHub API calls fail
    """
    async with httpx.AsyncClient(timeout=30.0) as client:
        # Get tree recursively
        tree_url = f"https://api.github.com/repos/{repo}/git/trees/{commit}?recursive=1"
        logger.info(f"Fetching source tree: {tree_url}")

        resp = await client.get(tree_url)
        resp.raise_for_status()
        tree = resp.json()

        files: dict[str, str] = {}
        total_size = 0

        for item in tree.get("tree", []):
            if item["type"] != "blob":
                continue

            # Check size limit before downloading
            size = item.get("size", 0)
            if total_size + size > MAX_SOURCE_SIZE:
                raise ValueError(f"Source exceeds {MAX_SOURCE_SIZE // (1024 * 1024)}MB limit")

            # Download file content
            blob_url = f"https://api.github.com/repos/{repo}/git/blobs/{item['sha']}"
            blob_resp = await client.get(blob_url)

            if blob_resp.status_code == 200:
                blob = blob_resp.json()
                if blob.get("encoding") == "base64":
                    try:
                        content = base64.b64decode(blob["content"]).decode("utf-8")
                        files[item["path"]] = content
                        total_size += len(content)
                    except UnicodeDecodeError:
                        # Skip binary files
                        pass

        logger.info(f"Downloaded {len(files)} files ({total_size} bytes)")
        return files


def scan_for_forbidden_keywords(files: dict[str, str]) -> InspectionResult:
    """Scan files for forbidden keywords.

    Checks all files for the presence of forbidden keywords (case-insensitive).
    Returns on first match.

    Args:
        files: Dict of {filepath: content}

    Returns:
        InspectionResult with pass/fail and reason if failed
    """
    # Build regex pattern for all forbidden keywords
    pattern = re.compile("|".join(FORBIDDEN_KEYWORDS), re.IGNORECASE)

    total_size = sum(len(c) for c in files.values())

    for filepath, content in files.items():
        for line_num, line in enumerate(content.split("\n"), 1):
            match = pattern.search(line)
            if match:
                return InspectionResult(
                    passed=False,
                    rejection_reason=(
                        f"Forbidden keyword '{match.group()}' found in {filepath}:{line_num}"
                    ),
                    files_scanned=len(files),
                    total_size=total_size,
                )

    return InspectionResult(
        passed=True,
        files_scanned=len(files),
        total_size=total_size,
    )


async def inspect_source(repo: str, commit: str) -> InspectionResult:
    """Download and inspect source code from GitHub.

    This is the main entry point for source inspection. It downloads
    the source code and scans it for forbidden keywords.

    Args:
        repo: GitHub repo (e.g., "org/repo")
        commit: Git commit SHA

    Returns:
        InspectionResult with pass/fail and details
    """
    try:
        files = await download_github_source(repo, commit)
        return scan_for_forbidden_keywords(files)
    except ValueError as e:
        # Size limit exceeded
        return InspectionResult(passed=False, rejection_reason=str(e))
    except httpx.HTTPStatusError as e:
        return InspectionResult(
            passed=False,
            rejection_reason=f"Failed to download source: HTTP {e.response.status_code}",
        )
    except Exception as e:
        logger.error(f"Source inspection failed: {e}")
        return InspectionResult(
            passed=False,
            rejection_reason=f"Failed to download source: {e}",
        )
