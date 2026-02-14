"""Automated billing and charging for EasyEnclave deployments.

Handles:
- Hourly charging for running deployments
- 70/30 revenue split with agents
- Insufficient funds handling and termination
- Stripe payment processing
"""

import asyncio
import logging
from datetime import datetime, timezone

import httpx

from app.pricing import calculate_deployment_cost_per_hour, split_revenue
from app.settings import get_setting
from app.storage import (
    account_store,
    agent_store,
    app_revenue_share_store,
    app_store,
    deployment_store,
    transaction_store,
)

logger = logging.getLogger(__name__)

# Stripe configuration (lazy init)
try:
    import stripe as _stripe_mod
except ImportError:
    logger.warning("Stripe SDK not installed. Payment processing disabled.")
    _stripe_mod = None


def _ensure_stripe() -> bool:
    """Configure Stripe SDK lazily and return True if enabled."""
    if _stripe_mod is None:
        return False
    key = get_setting("stripe.secret_key")
    if not key:
        return False
    _stripe_mod.api_key = key
    return True


def _webhook_secret() -> str:
    return get_setting("stripe.webhook_secret")


def _get_setting_or_default(key: str, default: str) -> str:
    try:
        return get_setting(key)
    except Exception:
        return default


def create_transaction(
    account_id: str,
    amount: float,
    tx_type: str,
    description: str = "",
    reference_id: str | None = None,
) -> str:
    """Create a transaction and update account balance.

    Args:
        account_id: Account to transact on
        amount: Amount (positive for deposit/earning, negative for charge/withdrawal)
        tx_type: Type of transaction
        description: Optional description
        reference_id: Optional reference (deployment_id, payment_id, etc.)

    Returns:
        transaction_id
    """
    from app.db_models import Transaction

    if not account_store.get(account_id):
        raise ValueError(f"Account not found: {account_id}")

    # Get current balance
    current_balance = account_store.get_balance(account_id)
    new_balance = current_balance + amount

    # Create transaction
    transaction = Transaction(
        account_id=account_id,
        amount=amount,
        balance_after=new_balance,
        tx_type=tx_type,
        description=description,
        reference_id=reference_id,
    )

    return transaction_store.create(transaction)


def _resolve_contributor_shares(app_name: str) -> list[tuple[str, int, str]]:
    """Resolve contributor split rules as list of (account_id, share_bps, label)."""
    if not app_name:
        return []

    explicit = app_revenue_share_store.list_for_app(app_name)
    if explicit:
        return [(entry.account_id, int(entry.share_bps), entry.label or "") for entry in explicit]

    # Fallback: derive equal split from app maintainers with linked contributor accounts.
    app = app_store.get_by_name(app_name)
    if not app:
        return []
    maintainers = [m.strip() for m in (app.maintainers or []) if isinstance(m, str) and m.strip()]
    if not maintainers:
        return []

    linked_accounts: list[str] = []
    for login in maintainers:
        account = account_store.get_by_github_login(login)
        if not account:
            continue
        if account.account_type not in ("contributor", "agent"):
            continue
        linked_accounts.append(account.account_id)

    if not linked_accounts:
        return []

    even_bps = 10000 // len(linked_accounts)
    remainder = 10000 - (even_bps * len(linked_accounts))
    resolved: list[tuple[str, int, str]] = []
    for idx, account_id in enumerate(linked_accounts):
        bps = even_bps + (1 if idx < remainder else 0)
        resolved.append((account_id, bps, "maintainer-auto"))
    return resolved


async def charge_deployment(deployment_id: str, charge_time: datetime) -> bool:
    """Charge a single deployment for usage since last charge.

    Args:
        deployment_id: Deployment to charge
        charge_time: Current charge time

    Returns:
        True if charged successfully, False if insufficient funds
    """
    deployment = deployment_store.get(deployment_id)
    if not deployment:
        logger.warning(f"Deployment {deployment_id} not found")
        return False

    # Skip if no account_id (free/legacy deployments)
    if not deployment.account_id:
        return True

    # Calculate hours since last charge
    if deployment.last_charge_time:
        hours = (charge_time - deployment.last_charge_time).total_seconds() / 3600
    elif deployment.started_at:
        hours = (charge_time - deployment.started_at).total_seconds() / 3600
    else:
        logger.warning(f"Deployment {deployment_id} has no start time")
        return True

    # Skip if less than 1 minute has passed (avoid micro-charges)
    if hours < 0.0167:  # 1/60 hour
        return True

    # Calculate cost
    try:
        hourly_cost = calculate_deployment_cost_per_hour(
            deployment.cpu_vcpus,
            deployment.memory_gb,
            deployment.gpu_count,
            deployment.sla_class,
            deployment.machine_size,
        )
    except Exception as e:
        logger.error(f"Error calculating cost for deployment {deployment_id}: {e}")
        return True

    charge_amount = hourly_cost * hours

    # Check sufficient funds
    balance = account_store.get_balance(deployment.account_id)
    if balance < charge_amount:
        # Mark for termination
        logger.warning(
            f"Insufficient funds for deployment {deployment_id}: "
            f"balance={balance:.2f}, charge={charge_amount:.2f}"
        )
        deployment_store.update_status(deployment_id, "insufficient_funds")
        return False

    # Create charge transaction
    create_transaction(
        account_id=deployment.account_id,
        amount=-charge_amount,
        tx_type="charge",
        description=f"Deployment {deployment_id} usage ({hours:.2f} hours)",
        reference_id=deployment_id,
    )

    # Pay the agent (70/30 split)
    agent = agent_store.get(deployment.agent_id)
    agent_share = 0.0
    platform_share = charge_amount
    if agent and agent.account_id:
        agent_share, platform_share = split_revenue(charge_amount)
        try:
            create_transaction(
                account_id=agent.account_id,
                amount=agent_share,
                tx_type="earning",
                description=f"Agent revenue from deployment {deployment_id}",
                reference_id=deployment_id,
            )
            logger.info(
                f"Paid agent {agent.agent_id} ${agent_share:.2f} for deployment {deployment_id}"
            )
        except Exception as e:
            logger.error(f"Error paying agent {agent.agent_id}: {e}")

    app_name = str(
        deployment.app_name
        or (deployment.config or {}).get("app_name")
        or (deployment.config or {}).get("service_name")
        or ""
    ).strip()
    contributor_pool_bps = int(_get_setting_or_default("billing.contributor_pool_bps", "5000"))
    if contributor_pool_bps < 0:
        contributor_pool_bps = 0
    if contributor_pool_bps > 10000:
        contributor_pool_bps = 10000

    contributor_pool_amount = platform_share * (contributor_pool_bps / 10000.0)
    contributor_distributed = 0.0
    contributor_rules = _resolve_contributor_shares(app_name)
    if contributor_pool_amount > 0 and contributor_rules:
        total_rule_bps = sum(
            max(0, int(rule_bps)) for _account_id, rule_bps, _label in contributor_rules
        )
        if total_rule_bps > 10000:
            logger.warning(
                f"Contributor split exceeds 10000 bps for app '{app_name}': {total_rule_bps}; skipping credits"
            )
        else:
            for account_id, share_bps, label in contributor_rules:
                share_amount = contributor_pool_amount * (max(0, share_bps) / 10000.0)
                if share_amount <= 0:
                    continue
                try:
                    create_transaction(
                        account_id=account_id,
                        amount=share_amount,
                        tx_type="contributor_credit",
                        description=(
                            f"Contributor credit for {app_name or 'deployment'} "
                            f"({hours:.2f}h, {label or 'configured'})"
                        ),
                        reference_id=deployment_id,
                    )
                    contributor_distributed += share_amount
                except Exception as e:
                    logger.error(
                        f"Failed contributor payout for app='{app_name}' account={account_id}: {e}"
                    )

    platform_remainder = platform_share - contributor_distributed
    platform_account_id = _get_setting_or_default("billing.platform_account_id", "").strip()
    if platform_remainder > 0 and platform_account_id:
        try:
            create_transaction(
                account_id=platform_account_id,
                amount=platform_remainder,
                tx_type="platform_revenue",
                description=f"Platform revenue from deployment {deployment_id}",
                reference_id=deployment_id,
            )
        except Exception as e:
            logger.error(f"Failed platform revenue credit to {platform_account_id}: {e}")

    # Update deployment
    deployment_store.update(
        deployment_id,
        {
            "last_charge_time": charge_time,
            "total_charged": deployment.total_charged + charge_amount,
        },
    )

    logger.info(
        f"Charged deployment {deployment_id}: ${charge_amount:.2f} "
        f"({hours:.2f} hours @ ${hourly_cost:.2f}/hr, "
        f"agent_share=${agent_share:.2f}, contributor_distributed=${contributor_distributed:.2f})"
    )

    return True


async def charge_all_active_deployments() -> dict[str, int]:
    """Charge all running deployments.

    Returns:
        Dict with counts: {charged, insufficient_funds, errors}
    """
    charge_time = datetime.now(timezone.utc)
    deployments = deployment_store.list({"status": "running"})

    charged = 0
    insufficient_funds = 0
    errors = 0

    for deployment in deployments:
        try:
            success = await charge_deployment(deployment.deployment_id, charge_time)
            if success:
                charged += 1
            else:
                insufficient_funds += 1
        except Exception as e:
            logger.error(f"Error charging deployment {deployment.deployment_id}: {e}")
            errors += 1

    logger.info(
        f"Charging complete: {charged} charged, {insufficient_funds} insufficient funds, {errors} errors"
    )

    return {
        "charged": charged,
        "insufficient_funds": insufficient_funds,
        "errors": errors,
    }


async def background_hourly_charging():
    """Background task to charge all active deployments every hour."""
    logger.info("Starting hourly charging background task")

    while True:
        try:
            await asyncio.sleep(3600)  # Wait 1 hour
            logger.info("Running hourly charging...")
            await charge_all_active_deployments()
        except Exception as e:
            logger.error(f"Error in hourly charging task: {e}")


async def terminate_deployment_on_agent(deployment_id: str) -> bool:
    """Call agent API to terminate a deployment.

    Args:
        deployment_id: Deployment to terminate

    Returns:
        True if successful
    """
    deployment = deployment_store.get(deployment_id)
    if not deployment:
        return False

    agent = agent_store.get(deployment.agent_id)
    if not agent or not agent.service_url:
        logger.warning(f"Agent {deployment.agent_id} not reachable")
        return False

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(f"{agent.service_url}/api/terminate")
            if response.status_code == 200:
                logger.info(f"Terminated deployment {deployment_id} on agent {agent.agent_id}")
                return True
            else:
                logger.error(
                    f"Failed to terminate deployment {deployment_id}: {response.status_code}"
                )
                return False
    except Exception as e:
        logger.error(f"Error terminating deployment {deployment_id}: {e}")
        return False


async def background_insufficient_funds_terminator():
    """Background task to terminate deployments with insufficient funds."""
    logger.info("Starting insufficient funds terminator background task")

    while True:
        try:
            await asyncio.sleep(60)  # Check every minute

            # Find deployments marked for termination
            deployments = deployment_store.list({"status": "insufficient_funds"})

            for deployment in deployments:
                logger.info(
                    f"Terminating deployment {deployment.deployment_id} due to insufficient funds"
                )

                # Try to terminate on agent
                success = await terminate_deployment_on_agent(deployment.deployment_id)

                if success:
                    # Update deployment status
                    deployment_store.update_status(
                        deployment.deployment_id,
                        "terminated",
                        error="Insufficient funds",
                    )

                    # Reset agent
                    agent_store.reset_for_reassignment(deployment.agent_id)
                else:
                    # Mark as failed to terminate (will retry next minute)
                    logger.warning(
                        f"Failed to terminate deployment {deployment.deployment_id}, will retry"
                    )

        except Exception as e:
            logger.error(f"Error in insufficient funds terminator task: {e}")
