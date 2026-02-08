"""Automated billing and charging for EasyEnclave deployments.

Handles:
- Hourly charging for running deployments
- 70/30 revenue split with agents
- Insufficient funds handling and termination
- Stripe payment processing
"""

import asyncio
import logging
import os
from datetime import datetime

import httpx

from app.pricing import calculate_deployment_cost_per_hour, split_revenue
from app.storage import (
    account_store,
    agent_store,
    deployment_store,
    transaction_store,
)

logger = logging.getLogger(__name__)

# Stripe configuration
try:
    import stripe

    stripe.api_key = os.environ.get("STRIPE_SECRET_KEY")
    STRIPE_WEBHOOK_SECRET = os.environ.get("STRIPE_WEBHOOK_SECRET")
    STRIPE_ENABLED = bool(stripe.api_key)
except ImportError:
    logger.warning("Stripe SDK not installed. Payment processing disabled.")
    stripe = None
    STRIPE_ENABLED = False


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
        f"({hours:.2f} hours @ ${hourly_cost:.2f}/hr)"
    )

    return True


async def charge_all_active_deployments() -> dict[str, int]:
    """Charge all running deployments.

    Returns:
        Dict with counts: {charged, insufficient_funds, errors}
    """
    charge_time = datetime.utcnow()
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
