"""SQLModel database configuration for EasyEnclave storage."""

from __future__ import annotations

import os
from contextlib import contextmanager

from sqlalchemy import event
from sqlmodel import Session, SQLModel, create_engine

DB_PATH = os.environ.get("EASYENCLAVE_DB_PATH", "easyenclave.db")
DATABASE_URL = f"sqlite:///{DB_PATH}"

# Create engine with SQLite-specific settings
engine = create_engine(
    DATABASE_URL,
    echo=False,
    connect_args={"check_same_thread": False},
)


# Enable WAL mode and foreign keys for SQLite
@event.listens_for(engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    """Set SQLite pragmas on each connection."""
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()


def get_session() -> Session:
    """Create a new database session."""
    return Session(engine, expire_on_commit=False)


@contextmanager
def get_db():
    """Context manager for database sessions with auto-commit."""
    session = get_session()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def init_db():
    """Initialize database schema using SQLModel metadata."""
    # Import models to register them with SQLModel
    from . import db_models  # noqa: F401

    SQLModel.metadata.create_all(engine)
    _migrate_add_columns()


def _migrate_add_columns():
    """Add columns that create_all() won't add to existing tables.

    This is idempotent and runs on every startup. To add a new column,
    append a tuple to the migrations list below.
    """
    import sqlite3

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # (table, column, sql_type, default)
    migrations = [
        ("agents", "node_size", "TEXT", "''"),
        ("agents", "datacenter", "TEXT", "''"),
        ("agents", "deployed_app", "TEXT", "NULL"),
        ("app_versions", "node_size", "TEXT", "''"),
        ("deployments", "app_name", "TEXT", "NULL"),
        ("deployments", "app_version", "TEXT", "NULL"),
    ]

    for table, column, sql_type, default in migrations:
        cursor.execute(f"PRAGMA table_info({table})")
        existing = {row[1] for row in cursor.fetchall()}
        if column not in existing:
            cursor.execute(f"ALTER TABLE {table} ADD COLUMN {column} {sql_type} DEFAULT {default}")

    # Unique index: (app_name, version, node_size) on app_versions
    cursor.execute(
        "SELECT name FROM sqlite_master WHERE type='index' AND name='ix_app_versions_name_ver_size'"
    )
    if not cursor.fetchone():
        cursor.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS ix_app_versions_name_ver_size "
            "ON app_versions(app_name, version, node_size)"
        )

    conn.commit()
    conn.close()


def run_migrations():
    """Run Alembic migrations to latest version."""
    from alembic.config import Config

    from alembic import command

    # Get the directory containing this file
    app_dir = os.path.dirname(os.path.abspath(__file__))
    project_dir = os.path.dirname(app_dir)
    alembic_ini = os.path.join(project_dir, "alembic.ini")

    if os.path.exists(alembic_ini):
        alembic_cfg = Config(alembic_ini)
        alembic_cfg.set_main_option("sqlalchemy.url", DATABASE_URL)
        command.upgrade(alembic_cfg, "head")
