#!/usr/bin/env python3
"""Script to generate bcrypt hash for admin password.

Usage:
    python3 scripts/hash_admin_password.py

Then set the output as ADMIN_PASSWORD_HASH environment variable:
    export ADMIN_PASSWORD_HASH='$2b$12$...'
"""

import getpass
import sys

import bcrypt


def hash_password(password: str) -> str:
    """Hash a password using bcrypt."""
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode(), salt).decode()


def main():
    print("=== EasyEnclave Admin Password Hasher ===\n")
    print("This script will generate a bcrypt hash for your admin password.")
    print("The hash should be set as the ADMIN_PASSWORD_HASH environment variable.\n")

    # Get password from user
    password = getpass.getpass("Enter admin password: ")
    password_confirm = getpass.getpass("Confirm admin password: ")

    if password != password_confirm:
        print("\nError: Passwords do not match!", file=sys.stderr)
        sys.exit(1)

    if len(password) < 8:
        print("\nError: Password must be at least 8 characters long!", file=sys.stderr)
        sys.exit(1)

    # Generate hash
    print("\nGenerating bcrypt hash...")
    password_hash = hash_password(password)

    print("\n" + "=" * 70)
    print("SUCCESS! Add this to your environment variables:")
    print("=" * 70)
    print(f"\nexport ADMIN_PASSWORD_HASH='{password_hash}'")
    print("\nOr add to your .env file:")
    print(f"\nADMIN_PASSWORD_HASH={password_hash}")
    print("\n" + "=" * 70)
    print("\nIMPORTANT: Store this securely. The plaintext password cannot be recovered.")
    print("=" * 70)


if __name__ == "__main__":
    main()
