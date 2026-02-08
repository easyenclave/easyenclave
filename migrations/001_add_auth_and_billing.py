#!/usr/bin/env python3
"""Migration script for adding authentication and billing features.

Changes:
- Add API key fields to Account table
- Create AdminSession table
- Add billing fields to Deployment table
- Add billing fields to Agent table
- Generate API keys for existing accounts (printed for users to save)
- Set default SLA/size for existing deployments

Usage:
    python3 migrations/001_add_auth_and_billing.py

Note: This migration is idempotent - safe to run multiple times.
"""

import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.auth import generate_api_key, hash_api_key, get_key_prefix
from app.database import get_db
from app.db_models import Account, Agent, Deployment, AdminSession
from sqlmodel import select


def migrate_accounts():
    """Generate API keys for existing accounts."""
    print("\n=== Migrating Accounts ===")

    with get_db() as session:
        accounts = session.exec(select(Account)).all()

        if not accounts:
            print("No accounts found.")
            return

        print(f"Found {len(accounts)} accounts")
        generated_keys = []

        for account in accounts:
            # Skip if already has API key
            if account.api_key_hash:
                print(f"  - {account.name} ({account.account_id}): Already has API key")
                continue

            # Generate new API key
            api_key = generate_api_key("live")
            account.api_key_hash = hash_api_key(api_key)
            account.api_key_prefix = get_key_prefix(api_key)

            session.add(account)

            generated_keys.append({
                "account_name": account.name,
                "account_id": account.account_id,
                "api_key": api_key,
            })

            print(f"  - {account.name} ({account.account_id}): Generated API key")

        session.commit()

        # Print generated keys for users to save
        if generated_keys:
            print("\n" + "=" * 70)
            print("IMPORTANT: Save these API keys now. They will never be shown again!")
            print("=" * 70)
            for item in generated_keys:
                print(f"\nAccount: {item['account_name']}")
                print(f"Account ID: {item['account_id']}")
                print(f"API Key: {item['api_key']}")
            print("\n" + "=" * 70)


def migrate_deployments():
    """Set default SLA class and machine size for existing deployments."""
    print("\n=== Migrating Deployments ===")

    with get_db() as session:
        deployments = session.exec(select(Deployment)).all()

        if not deployments:
            print("No deployments found.")
            return

        print(f"Found {len(deployments)} deployments")
        updated = 0

        for deployment in deployments:
            # Check if already migrated (has non-default values)
            if hasattr(deployment, 'sla_class') and deployment.sla_class != "adhoc":
                continue

            # Set defaults if not already set
            changed = False
            if not hasattr(deployment, 'sla_class') or deployment.sla_class is None:
                deployment.sla_class = "adhoc"
                changed = True
            if not hasattr(deployment, 'machine_size') or deployment.machine_size is None:
                deployment.machine_size = "default"
                changed = True
            if not hasattr(deployment, 'cpu_vcpus') or deployment.cpu_vcpus is None:
                deployment.cpu_vcpus = 2.0
                changed = True
            if not hasattr(deployment, 'memory_gb') or deployment.memory_gb is None:
                deployment.memory_gb = 4.0
                changed = True
            if not hasattr(deployment, 'gpu_count') or deployment.gpu_count is None:
                deployment.gpu_count = 0
                changed = True
            if not hasattr(deployment, 'total_charged') or deployment.total_charged is None:
                deployment.total_charged = 0.0
                changed = True

            if changed:
                session.add(deployment)
                updated += 1

        session.commit()
        print(f"Updated {updated} deployments with default billing fields")


def migrate_agents():
    """Initialize billing fields for existing agents."""
    print("\n=== Migrating Agents ===")

    with get_db() as session:
        agents = session.exec(select(Agent)).all()

        if not agents:
            print("No agents found.")
            return

        print(f"Found {len(agents)} agents")
        updated = 0

        for agent in agents:
            # Initialize empty lists if not present
            changed = False
            if not hasattr(agent, 'sla_tiers') or agent.sla_tiers is None:
                agent.sla_tiers = []
                changed = True
            if not hasattr(agent, 'machine_sizes') or agent.machine_sizes is None:
                agent.machine_sizes = []
                changed = True

            if changed:
                session.add(agent)
                updated += 1

        session.commit()
        print(f"Updated {updated} agents with billing fields")


def main():
    print("=" * 70)
    print("EasyEnclave Migration: Authentication and Billing")
    print("=" * 70)

    try:
        # Run migrations
        migrate_accounts()
        migrate_deployments()
        migrate_agents()

        print("\n" + "=" * 70)
        print("Migration completed successfully!")
        print("=" * 70)

        print("\nNext steps:")
        print("1. Save the API keys shown above (they won't be shown again)")
        print("2. Set ADMIN_PASSWORD_HASH environment variable:")
        print("   python3 scripts/hash_admin_password.py")
        print("3. (Optional) Set STRIPE_SECRET_KEY and STRIPE_WEBHOOK_SECRET for payment processing")
        print("4. Restart the control plane to pick up schema changes")

    except Exception as e:
        print(f"\nError during migration: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
