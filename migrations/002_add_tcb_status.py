#!/usr/bin/env python3
"""Migration script for adding TCB status fields to Agent table.

Changes:
- Add tcb_status field to Agent table (nullable string)
- Add tcb_verified_at field to Agent table (nullable timestamp)

Usage:
    python3 migrations/002_add_tcb_status.py

Note: This migration is idempotent - safe to run multiple times.
"""

import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.database import get_db
from sqlmodel import text


def add_tcb_fields():
    """Add TCB status fields to agents table."""
    print("\n=== Adding TCB Status Fields ===")

    with get_db() as session:
        # Check if columns already exist
        result = session.exec(
            text("PRAGMA table_info(agents)")
        ).fetchall()

        existing_columns = {row[1] for row in result}

        # Add tcb_status if not exists
        if "tcb_status" not in existing_columns:
            print("Adding tcb_status column...")
            session.exec(text("ALTER TABLE agents ADD COLUMN tcb_status VARCHAR"))
            print("  ✓ tcb_status column added")
        else:
            print("  - tcb_status column already exists")

        # Add tcb_verified_at if not exists
        if "tcb_verified_at" not in existing_columns:
            print("Adding tcb_verified_at column...")
            session.exec(text("ALTER TABLE agents ADD COLUMN tcb_verified_at TIMESTAMP"))
            print("  ✓ tcb_verified_at column added")
        else:
            print("  - tcb_verified_at column already exists")

        session.commit()

        # Count agents without using ORM
        count_result = session.exec(text("SELECT COUNT(*) FROM agents")).first()
        agent_count = count_result if count_result else 0
        print(f"\nVerified: {agent_count} agents now have TCB fields")


def main():
    print("=" * 70)
    print("EasyEnclave Migration: TCB Status Enforcement")
    print("=" * 70)

    try:
        add_tcb_fields()

        print("\n" + "=" * 70)
        print("Migration completed successfully!")
        print("=" * 70)

        print("\nNext steps:")
        print("1. Configure TCB enforcement mode (default: warn):")
        print("   export TCB_ENFORCEMENT_MODE=warn  # strict | warn | disabled")
        print("2. Configure allowed TCB statuses (default: UpToDate):")
        print("   export ALLOWED_TCB_STATUSES=UpToDate")
        print("3. Restart the control plane to enable TCB enforcement")

    except Exception as e:
        print(f"\nError during migration: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
