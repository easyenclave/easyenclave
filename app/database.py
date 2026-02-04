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
    return Session(engine)


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
