#!/usr/bin/env python3
"""Migration script for adding GitHub ownership fields.

Changes:
- Add github_owner column to agents table (for ownership tracking)
- Add github_orgs column to admin_sessions table (for org-based matching)

Usage:
    python3 migrations/003_add_github_owner.py

Note: This migration is idempotent - safe to run multiple times.
"""

import sqlite3
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.database import DB_PATH


def migrate():
    db_path = DB_PATH
    print(f"Migrating database: {db_path}")

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # Check existing columns in agents table
    cursor.execute("PRAGMA table_info(agents)")
    agent_cols = {row[1] for row in cursor.fetchall()}

    if "github_owner" not in agent_cols:
        print("Adding github_owner column to agents table...")
        cursor.execute("ALTER TABLE agents ADD COLUMN github_owner TEXT")
        cursor.execute("CREATE INDEX IF NOT EXISTS ix_agents_github_owner ON agents(github_owner)")
        print("  Done.")
    else:
        print("agents.github_owner already exists, skipping.")

    # Check existing columns in admin_sessions table
    cursor.execute("PRAGMA table_info(admin_sessions)")
    session_cols = {row[1] for row in cursor.fetchall()}

    if "github_orgs" not in session_cols:
        print("Adding github_orgs column to admin_sessions table...")
        cursor.execute("ALTER TABLE admin_sessions ADD COLUMN github_orgs TEXT")
        print("  Done.")
    else:
        print("admin_sessions.github_orgs already exists, skipping.")

    conn.commit()
    conn.close()
    print("Migration completed successfully!")


if __name__ == "__main__":
    migrate()
