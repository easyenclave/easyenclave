"""GitHub OAuth integration for admin authentication."""

import secrets
from typing import Any

import httpx
from fastapi import HTTPException

from .settings import get_setting


def _client_id() -> str:
    return get_setting("github_oauth.client_id")


def _client_secret() -> str:
    return get_setting("github_oauth.client_secret")


def _redirect_uri() -> str:
    return get_setting("github_oauth.redirect_uri")


def is_github_oauth_configured() -> bool:
    """Return whether all GitHub OAuth settings are configured."""
    return bool(_client_id() and _client_secret() and _redirect_uri())


# GitHub OAuth URLs
GITHUB_AUTHORIZE_URL = "https://github.com/login/oauth/authorize"
GITHUB_TOKEN_URL = "https://github.com/login/oauth/access_token"
GITHUB_USER_API = "https://api.github.com/user"
GITHUB_USER_EMAILS_API = "https://api.github.com/user/emails"
GITHUB_USER_ORGS_API = "https://api.github.com/user/orgs"


def get_github_authorize_url(state: str) -> str:
    """Generate GitHub OAuth authorization URL."""
    if not _client_id():
        raise HTTPException(
            status_code=503, detail="GitHub OAuth not configured. Set GITHUB_OAUTH_CLIENT_ID."
        )

    params = {
        "client_id": _client_id(),
        "redirect_uri": _redirect_uri(),
        "scope": "read:user user:email read:org",
        "state": state,  # CSRF protection
    }
    query = "&".join(f"{k}={v}" for k, v in params.items())
    return f"{GITHUB_AUTHORIZE_URL}?{query}"


async def exchange_code_for_token(code: str) -> str:
    """Exchange authorization code for access token."""
    if not _client_id() or not _client_secret():
        raise HTTPException(status_code=503, detail="GitHub OAuth not configured.")

    async with httpx.AsyncClient() as client:
        resp = await client.post(
            GITHUB_TOKEN_URL,
            data={
                "client_id": _client_id(),
                "client_secret": _client_secret(),
                "code": code,
                "redirect_uri": _redirect_uri(),
            },
            headers={"Accept": "application/json"},
        )
        resp.raise_for_status()
        data = resp.json()

        if "error" in data:
            raise HTTPException(
                status_code=400,
                detail=data.get("error_description", "GitHub authentication failed"),
            )

        return data["access_token"]


async def get_github_user(access_token: str) -> dict[str, Any]:
    """Fetch GitHub user profile."""
    async with httpx.AsyncClient() as client:
        # Get user profile
        user_resp = await client.get(
            GITHUB_USER_API,
            headers={
                "Authorization": f"Bearer {access_token}",
                "Accept": "application/vnd.github.v3+json",
            },
        )
        user_resp.raise_for_status()
        user = user_resp.json()

        # Get verified email
        email_resp = await client.get(
            GITHUB_USER_EMAILS_API,
            headers={
                "Authorization": f"Bearer {access_token}",
                "Accept": "application/vnd.github.v3+json",
            },
        )
        email_resp.raise_for_status()
        emails = email_resp.json()

        # Find primary verified email
        primary_email = next((e["email"] for e in emails if e["primary"] and e["verified"]), None)

        return {
            "github_id": user["id"],
            "github_login": user["login"],
            "github_email": primary_email or user.get("email"),
            "github_avatar_url": user.get("avatar_url"),
        }


async def get_github_user_orgs(access_token: str) -> list[str]:
    """Fetch org logins the authenticated user belongs to."""
    async with httpx.AsyncClient() as client:
        resp = await client.get(
            GITHUB_USER_ORGS_API,
            headers={
                "Authorization": f"Bearer {access_token}",
                "Accept": "application/vnd.github.v3+json",
            },
        )
        resp.raise_for_status()
        return [org["login"] for org in resp.json()]


# Simple in-memory CSRF state storage (expires after 10 minutes)
_oauth_states: dict[str, float] = {}


def create_oauth_state() -> str:
    """Create a CSRF state token."""
    import time

    state = secrets.token_urlsafe(32)
    _oauth_states[state] = time.time()

    # Cleanup old states (older than 10 minutes)
    cutoff = time.time() - 600
    expired = [s for s, t in _oauth_states.items() if t < cutoff]
    for s in expired:
        del _oauth_states[s]

    return state


def verify_oauth_state(state: str) -> bool:
    """Verify CSRF state token."""
    import time

    if state not in _oauth_states:
        return False

    # Check expiration (10 minutes)
    if time.time() - _oauth_states[state] > 600:
        del _oauth_states[state]
        return False

    # Consume the state (one-time use)
    del _oauth_states[state]
    return True
