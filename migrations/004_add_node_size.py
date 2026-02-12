#!/usr/bin/env python3
"""Migration script for adding the node_size column to agents.

Changes:
- Add node_size column to agents table (VM size label, e.g. "64G")

Usage:
    python3 migrations/004_add_node_size.py

Note: This migration is idempotent - safe to run multiple times.
      It is also applied automatically on startup via init_db().
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

    cursor.execute("PRAGMA table_info(agents)")
    agent_cols = {row[1] for row in cursor.fetchall()}

    if "node_size" not in agent_cols:
        print("Adding node_size column to agents table...")
        cursor.execute("ALTER TABLE agents ADD COLUMN node_size TEXT DEFAULT ''")
        print("  Done.")
    else:
        print("agents.node_size already exists, skipping.")

    conn.commit()
    conn.close()
    print("Migration completed successfully!")


if __name__ == "__main__":
    migrate()
