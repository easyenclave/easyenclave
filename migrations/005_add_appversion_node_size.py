#!/usr/bin/env python3
"""Migration script for adding the node_size column to app_versions.

Changes:
- Add node_size column to app_versions table (per-size attestation)
- Create unique index on (app_name, version, node_size)

Usage:
    python3 migrations/005_add_appversion_node_size.py

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

    cursor.execute("PRAGMA table_info(app_versions)")
    cols = {row[1] for row in cursor.fetchall()}

    if "node_size" not in cols:
        print("Adding node_size column to app_versions table...")
        cursor.execute("ALTER TABLE app_versions ADD COLUMN node_size TEXT NOT NULL DEFAULT ''")
        print("  Done.")
    else:
        print("app_versions.node_size already exists, skipping.")

    # Create unique index on (app_name, version, node_size)
    cursor.execute("SELECT name FROM sqlite_master WHERE type='index' AND name='ix_app_versions_name_ver_size'")
    if not cursor.fetchone():
        print("Creating unique index ix_app_versions_name_ver_size...")
        cursor.execute(
            "CREATE UNIQUE INDEX ix_app_versions_name_ver_size "
            "ON app_versions(app_name, version, node_size)"
        )
        print("  Done.")
    else:
        print("Index ix_app_versions_name_ver_size already exists, skipping.")

    conn.commit()
    conn.close()
    print("Migration completed successfully!")


if __name__ == "__main__":
    migrate()
