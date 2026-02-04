"""CRUD helper functions for common route patterns."""

from __future__ import annotations

from fastapi import HTTPException


def get_or_404(store, item_id: str, name: str):
    """Get item by ID or raise 404."""
    item = store.get(item_id)
    if item is None:
        raise HTTPException(status_code=404, detail=f"{name} not found")
    return item


def delete_or_404(store, item_id: str, name: str, id_field: str = "id"):
    """Delete item or raise 404."""
    if not store.delete(item_id):
        raise HTTPException(status_code=404, detail=f"{name} not found")
    return {"status": "deleted", id_field: item_id}


def build_filters(**kwargs) -> dict | None:
    """Build filter dict from kwargs, excluding None values."""
    filters = {}
    for key, value in kwargs.items():
        if value is None:
            continue
        if key == "tags" and isinstance(value, str):
            filters[key] = [t.strip() for t in value.split(",")]
        else:
            filters[key] = value
    return filters or None
