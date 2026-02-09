"""Nonce management for replay attack prevention."""

import logging
import os
import secrets
import time
from dataclasses import dataclass

logger = logging.getLogger(__name__)

# Configuration
NONCE_ENFORCEMENT_MODE = os.environ.get("NONCE_ENFORCEMENT_MODE", "optional").lower()
NONCE_TTL_SECONDS = int(os.environ.get("NONCE_TTL_SECONDS", "300"))
NONCE_LENGTH = int(os.environ.get("NONCE_LENGTH", "32"))


@dataclass
class NonceChallenge:
    """Represents a nonce challenge issued to an agent."""

    nonce: str
    vm_name: str
    issued_at: float

    def is_expired(self) -> bool:
        """Check if nonce has expired based on TTL."""
        return time.time() - self.issued_at > NONCE_TTL_SECONDS


# In-memory storage for nonces (keyed by vm_name)
_nonce_store: dict[str, NonceChallenge] = {}


def generate_nonce() -> str:
    """Generate cryptographically secure random nonce.

    Returns hex-encoded random bytes with length NONCE_LENGTH characters.
    Default length of 32 hex chars = 16 bytes = 128 bits of entropy.
    """
    return secrets.token_hex(NONCE_LENGTH // 2)


def issue_challenge(vm_name: str) -> str:
    """Issue nonce challenge for an agent.

    Args:
        vm_name: VM identifier requesting the challenge

    Returns:
        Generated nonce string

    Note:
        - Overwrites any existing challenge for the same vm_name
        - Nonce is stored in memory with timestamp for verification
    """
    nonce = generate_nonce()
    _nonce_store[vm_name] = NonceChallenge(
        nonce=nonce,
        vm_name=vm_name,
        issued_at=time.time(),
    )
    logger.info(f"Issued nonce challenge for {vm_name}: {nonce[:8]}...")
    return nonce


def verify_nonce(vm_name: str, nonce_from_quote: str) -> tuple[bool, str | None]:
    """Verify nonce matches expected value for vm_name.

    Args:
        vm_name: VM identifier being verified
        nonce_from_quote: Nonce extracted from attestation quote

    Returns:
        Tuple of (verified: bool, error_message: str | None)

    Behavior by enforcement mode:
        - disabled: Always returns (True, None)
        - optional: Logs warnings but allows registration even on mismatch
        - required: Rejects on missing/expired/mismatched nonce

    Note:
        - On successful verification, nonce is consumed (removed from store)
        - Each nonce can only be used once
    """
    if NONCE_ENFORCEMENT_MODE == "disabled":
        return True, None

    challenge = _nonce_store.get(vm_name)

    # Check if challenge exists
    if not challenge:
        error = f"No nonce challenge found for {vm_name}"
        if NONCE_ENFORCEMENT_MODE == "required":
            return False, error
        logger.warning(f"{error} (optional mode, allowing)")
        return True, None

    # Check expiration
    if challenge.is_expired():
        error = f"Nonce expired for {vm_name}"
        _nonce_store.pop(vm_name, None)
        if NONCE_ENFORCEMENT_MODE == "required":
            return False, error
        logger.warning(f"{error} (optional mode, allowing)")
        return True, None

    # Verify match (case-insensitive comparison)
    if nonce_from_quote.strip().lower() != challenge.nonce.strip().lower():
        error = f"Nonce mismatch for {vm_name}"
        if NONCE_ENFORCEMENT_MODE == "required":
            return False, error
        logger.warning(f"{error} (optional mode, allowing)")
        return True, None

    # Success - consume nonce (one-time use)
    _nonce_store.pop(vm_name, None)
    logger.info(f"Nonce verified for {vm_name}")
    return True, None


def cleanup_expired_nonces():
    """Remove expired nonces from memory.

    Should be called periodically by background task to prevent memory leaks.
    """
    expired = [vm for vm, c in _nonce_store.items() if c.is_expired()]
    for vm in expired:
        _nonce_store.pop(vm, None)
    if expired:
        logger.info(f"Cleaned {len(expired)} expired nonces")


def get_nonce_store_size() -> int:
    """Get current number of nonces in memory (for monitoring/testing)."""
    return len(_nonce_store)
