"""CRUD helper functions for common route patterns."""

from __future__ import annotations

from fastapi import HTTPException

from .db_models import Transaction


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


def create_transaction(
    account_store,
    transaction_store,
    account_id: str,
    amount: float,
    tx_type: str,
    description: str = "",
    reference_id: str | None = None,
) -> Transaction:
    """Create a transaction, updating the account's running balance.

    Raises HTTPException on insufficient funds or missing account.
    """
    account = account_store.get(account_id)
    if account is None:
        raise HTTPException(status_code=404, detail="Account not found")

    current_balance = account_store.get_balance(account_id)
    new_balance = current_balance + amount

    if amount < 0 and new_balance < 0:
        raise HTTPException(
            status_code=400,
            detail=f"Insufficient funds: balance {current_balance:.2f}, requested {amount:.2f}",
        )

    txn = Transaction(
        account_id=account_id,
        amount=amount,
        balance_after=new_balance,
        tx_type=tx_type,
        description=description,
        reference_id=reference_id,
    )
    transaction_store.create(txn)
    return txn
