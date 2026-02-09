"""Authentication utilities for EasyEnclave.

Implements Signal-inspired privacy model:
- API key authentication per account
- Admin session-based authentication
- bcrypt hashing for all credentials
"""

import logging
import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING

import bcrypt
from fastapi import Header, HTTPException

if TYPE_CHECKING:
    from app.db_models import AdminSession

logger = logging.getLogger(__name__)


def generate_api_key(key_type: str = "live") -> str:
    """Generate a new API key in format: ee_{type}_{32-chars}

    Args:
        key_type: Type of key ("live" or "test")

    Returns:
        API key string like "ee_live_abcd1234..."
    """
    random_part = secrets.token_urlsafe(24)  # ~32 chars base64
    return f"ee_{key_type}_{random_part}"


def hash_api_key(api_key: str) -> str:
    """Hash an API key using bcrypt.

    Args:
        api_key: The plaintext API key

    Returns:
        bcrypt hash string
    """
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(api_key.encode(), salt).decode()


def verify_api_key(api_key: str, hash: str) -> bool:
    """Verify an API key against its hash.

    Args:
        api_key: The plaintext API key to verify
        hash: The bcrypt hash to check against

    Returns:
        True if valid, False otherwise
    """
    try:
        return bcrypt.checkpw(api_key.encode(), hash.encode())
    except Exception:
        return False


def get_key_prefix(api_key: str) -> str:
    """Extract the prefix from an API key for fast lookup.

    Args:
        api_key: The API key

    Returns:
        First 12 characters of the key
    """
    return api_key[:12] if len(api_key) >= 12 else api_key


def hash_password(password: str) -> str:
    """Hash a password using bcrypt.

    Args:
        password: The plaintext password

    Returns:
        bcrypt hash string
    """
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode(), salt).decode()


def verify_password(password: str, hash: str) -> bool:
    """Verify a password against its hash.

    Args:
        password: The plaintext password to verify
        hash: The bcrypt hash to check against

    Returns:
        True if valid, False otherwise
    """
    try:
        return bcrypt.checkpw(password.encode(), hash.encode())
    except Exception:
        return False


def generate_session_token() -> str:
    """Generate a secure session token.

    Returns:
        Random token string
    """
    return secrets.token_urlsafe(32)


def get_token_prefix(token: str) -> str:
    """Extract the prefix from a token for fast lookup.

    Args:
        token: The session token

    Returns:
        First 12 characters of the token
    """
    return token[:12] if len(token) >= 12 else token


# Middleware dependencies


async def verify_account_api_key(authorization: str = Header(None)) -> str:
    """FastAPI dependency to verify account API key authentication.

    Args:
        authorization: Authorization header value

    Returns:
        account_id of authenticated account

    Raises:
        HTTPException: If authentication fails
    """
    from app.storage import account_store

    if not authorization:
        raise HTTPException(status_code=401, detail="Missing Authorization header")

    # Extract Bearer token
    parts = authorization.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise HTTPException(
            status_code=401,
            detail="Invalid Authorization header format. Expected: Bearer <api_key>",
        )

    api_key = parts[1]

    # Fast lookup by prefix
    prefix = get_key_prefix(api_key)
    account = account_store.get_by_api_key_prefix(prefix)

    if not account:
        raise HTTPException(status_code=401, detail="Invalid API key")

    # Verify hash (secure)
    if not account.api_key_hash or not verify_api_key(api_key, account.api_key_hash):
        raise HTTPException(status_code=401, detail="Invalid API key")

    return account.account_id


async def verify_admin_token(authorization: str = Header(None)) -> "AdminSession":
    """FastAPI dependency to verify admin session token.

    Args:
        authorization: Authorization header value

    Returns:
        AdminSession object if authenticated

    Raises:
        HTTPException: If authentication fails
    """
    from app.storage import admin_session_store

    if not authorization:
        raise HTTPException(status_code=401, detail="Missing Authorization header")

    # Extract Bearer token
    parts = authorization.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise HTTPException(
            status_code=401, detail="Invalid Authorization header format. Expected: Bearer <token>"
        )

    token = parts[1]

    # Fast lookup by prefix
    prefix = get_token_prefix(token)
    session = admin_session_store.get_by_prefix(prefix)

    if not session:
        logger.warning(f"Session not found: prefix={prefix!r}, token_len={len(token)}")
        raise HTTPException(status_code=401, detail="Invalid session token")

    # Check expiration (handle both timezone-aware and naive datetimes)
    expires_at = session.expires_at
    if expires_at.tzinfo is None:
        # Make timezone-naive datetime timezone-aware (assume UTC)
        expires_at = expires_at.replace(tzinfo=timezone.utc)

    if datetime.now(timezone.utc) > expires_at:
        admin_session_store.delete(session.session_id)
        raise HTTPException(status_code=401, detail="Session expired")

    # Verify hash
    if not verify_api_key(token, session.token_hash):
        raise HTTPException(status_code=401, detail="Invalid session token")

    # Update last_used timestamp
    admin_session_store.touch(session.session_id)

    return session


def get_admin_password_hash() -> str | None:
    """Get the admin password hash from environment variable.

    Returns:
        The bcrypt hash or None if not set
    """
    return os.environ.get("ADMIN_PASSWORD_HASH")


def create_session_expiry(hours: int = 24) -> datetime:
    """Create an expiry datetime for a session.

    Args:
        hours: Hours until expiration (default 24)

    Returns:
        Expiry datetime
    """
    return datetime.now(timezone.utc) + timedelta(hours=hours)
