"""Tests for nonce challenge and replay attack prevention."""

import os
import time

import pytest

from app.nonce import generate_nonce, get_nonce_store_size, issue_challenge


@pytest.fixture(autouse=True)
def reset_nonce_config():
    """Reset nonce config and clear store before each test."""
    # Clear in-memory store
    from app import nonce

    nonce._nonce_store.clear()

    # Save original values
    orig_mode = os.environ.get("NONCE_ENFORCEMENT_MODE")
    orig_ttl = os.environ.get("NONCE_TTL_SECONDS")

    yield

    # Restore original values
    if orig_mode is None:
        os.environ.pop("NONCE_ENFORCEMENT_MODE", None)
    else:
        os.environ["NONCE_ENFORCEMENT_MODE"] = orig_mode

    if orig_ttl is None:
        os.environ.pop("NONCE_TTL_SECONDS", None)
    else:
        os.environ["NONCE_TTL_SECONDS"] = orig_ttl

    # Clear store again
    nonce._nonce_store.clear()

    # Reload module
    import importlib

    importlib.reload(nonce)


def test_generate_nonce():
    """Test nonce generation produces unique values."""
    nonce1 = generate_nonce()
    nonce2 = generate_nonce()

    assert len(nonce1) == 32  # Default NONCE_LENGTH
    assert len(nonce2) == 32
    assert nonce1 != nonce2  # Should be unique


def test_issue_challenge():
    """Test issuing nonce challenge."""
    vm_name = "test-vm"
    nonce = issue_challenge(vm_name)

    assert len(nonce) == 32
    assert get_nonce_store_size() == 1


def test_verify_nonce_success():
    """Test successful nonce verification."""
    os.environ["NONCE_ENFORCEMENT_MODE"] = "required"
    import importlib

    import app.nonce

    importlib.reload(app.nonce)

    vm_name = "test-vm"
    nonce = app.nonce.issue_challenge(vm_name)

    # Verify with correct nonce
    verified, error = app.nonce.verify_nonce(vm_name, nonce)

    assert verified is True
    assert error is None
    assert app.nonce.get_nonce_store_size() == 0  # Should be consumed


def test_verify_nonce_mismatch():
    """Test nonce verification with wrong nonce."""
    os.environ["NONCE_ENFORCEMENT_MODE"] = "required"
    import importlib

    import app.nonce

    importlib.reload(app.nonce)

    vm_name = "test-vm"
    app.nonce.issue_challenge(vm_name)

    # Verify with wrong nonce
    verified, error = app.nonce.verify_nonce(vm_name, "wrong_nonce")

    assert verified is False
    assert error is not None
    assert "mismatch" in error.lower()


def test_verify_nonce_missing_challenge():
    """Test verification when no challenge was issued."""
    os.environ["NONCE_ENFORCEMENT_MODE"] = "required"
    import importlib

    import app.nonce

    importlib.reload(app.nonce)

    vm_name = "test-vm"

    # Verify without issuing challenge
    verified, error = app.nonce.verify_nonce(vm_name, "some_nonce")

    assert verified is False
    assert error is not None
    assert "no nonce challenge" in error.lower()


def test_verify_nonce_expired():
    """Test verification of expired nonce."""
    os.environ["NONCE_ENFORCEMENT_MODE"] = "required"
    os.environ["NONCE_TTL_SECONDS"] = "1"  # 1 second TTL
    import importlib

    import app.nonce

    importlib.reload(app.nonce)

    vm_name = "test-vm"
    nonce = app.nonce.issue_challenge(vm_name)

    # Wait for expiration
    time.sleep(1.1)

    # Verify with expired nonce
    verified, error = app.nonce.verify_nonce(vm_name, nonce)

    assert verified is False
    assert error is not None
    assert "expired" in error.lower()


def test_nonce_one_time_use():
    """Test that nonce can only be used once."""
    os.environ["NONCE_ENFORCEMENT_MODE"] = "required"
    import importlib

    import app.nonce

    importlib.reload(app.nonce)

    vm_name = "test-vm"
    nonce = app.nonce.issue_challenge(vm_name)

    # First verification succeeds
    verified1, _ = app.nonce.verify_nonce(vm_name, nonce)
    assert verified1 is True

    # Second verification fails (nonce consumed)
    verified2, error2 = app.nonce.verify_nonce(vm_name, nonce)
    assert verified2 is False
    assert "no nonce challenge" in error2.lower()


def test_optional_mode_allows_missing_nonce():
    """Test that optional mode allows missing nonce."""
    os.environ["NONCE_ENFORCEMENT_MODE"] = "optional"
    import importlib

    import app.nonce

    importlib.reload(app.nonce)

    vm_name = "test-vm"

    # Verify without issuing challenge
    verified, error = app.nonce.verify_nonce(vm_name, "any_nonce")

    assert verified is True
    assert error is None


def test_optional_mode_allows_mismatch():
    """Test that optional mode allows mismatched nonce."""
    os.environ["NONCE_ENFORCEMENT_MODE"] = "optional"
    import importlib

    import app.nonce

    importlib.reload(app.nonce)

    vm_name = "test-vm"
    app.nonce.issue_challenge(vm_name)

    # Verify with wrong nonce
    verified, error = app.nonce.verify_nonce(vm_name, "wrong_nonce")

    assert verified is True  # Optional mode allows
    assert error is None


def test_disabled_mode_always_allows():
    """Test that disabled mode always allows."""
    os.environ["NONCE_ENFORCEMENT_MODE"] = "disabled"
    import importlib

    import app.nonce

    importlib.reload(app.nonce)

    vm_name = "test-vm"

    # Verify without anything
    verified, error = app.nonce.verify_nonce(vm_name, "any_nonce")

    assert verified is True
    assert error is None


def test_cleanup_expired_nonces():
    """Test cleanup of expired nonces."""
    os.environ["NONCE_TTL_SECONDS"] = "1"
    import importlib

    import app.nonce

    importlib.reload(app.nonce)

    # Issue multiple challenges
    app.nonce.issue_challenge("vm1")
    app.nonce.issue_challenge("vm2")
    app.nonce.issue_challenge("vm3")

    assert app.nonce.get_nonce_store_size() == 3

    # Wait for expiration
    time.sleep(1.1)

    # Cleanup
    app.nonce.cleanup_expired_nonces()

    assert app.nonce.get_nonce_store_size() == 0


def test_cleanup_preserves_valid_nonces():
    """Test that cleanup only removes expired nonces."""
    os.environ["NONCE_TTL_SECONDS"] = "10"  # Long TTL
    import importlib

    import app.nonce

    importlib.reload(app.nonce)

    # Issue challenges
    app.nonce.issue_challenge("vm1")
    app.nonce.issue_challenge("vm2")

    assert app.nonce.get_nonce_store_size() == 2

    # Cleanup should preserve valid nonces
    app.nonce.cleanup_expired_nonces()

    assert app.nonce.get_nonce_store_size() == 2


def test_case_insensitive_verification():
    """Test that nonce verification is case-insensitive."""
    os.environ["NONCE_ENFORCEMENT_MODE"] = "required"
    import importlib

    import app.nonce

    importlib.reload(app.nonce)

    vm_name = "test-vm"
    nonce = app.nonce.issue_challenge(vm_name)

    # Verify with different case
    verified, error = app.nonce.verify_nonce(vm_name, nonce.upper())

    assert verified is True
    assert error is None


def test_nonce_overwrite():
    """Test that issuing new challenge overwrites old one."""
    os.environ["NONCE_ENFORCEMENT_MODE"] = "required"
    import importlib

    import app.nonce

    importlib.reload(app.nonce)

    vm_name = "test-vm"
    nonce1 = app.nonce.issue_challenge(vm_name)
    nonce2 = app.nonce.issue_challenge(vm_name)  # Overwrites first

    assert nonce1 != nonce2
    assert app.nonce.get_nonce_store_size() == 1

    # Old nonce should fail
    verified1, _ = app.nonce.verify_nonce(vm_name, nonce1)
    assert verified1 is False

    # New nonce should succeed
    vm_name2 = "test-vm"
    nonce2_reissued = app.nonce.issue_challenge(vm_name2)
    verified2, _ = app.nonce.verify_nonce(vm_name2, nonce2_reissued)
    assert verified2 is True
