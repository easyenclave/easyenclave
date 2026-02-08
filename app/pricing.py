"""Tiered pricing system for EasyEnclave deployments.

Supports:
- SLA tiers: adhoc (dev/test), 3-nines, 4-nines, 5-nines availability
- Machine sizes: default (current specs), h100 (large GPU)
- 70/30 revenue split between agent and platform
"""

from enum import Enum


class SlaClass(str, Enum):
    """SLA tier definitions."""

    ADHOC = "adhoc"  # Development/testing, no guarantees
    THREE_NINES = "three_nines"  # 99.9% uptime
    FOUR_NINES = "four_nines"  # 99.99% uptime
    FIVE_NINES = "five_nines"  # 99.999% uptime


class MachineSize(str, Enum):
    """Machine size definitions."""

    DEFAULT = "default"  # Standard compute
    H100 = "h100"  # Large GPU instances


# SLA multipliers applied to base cost
SLA_MULTIPLIERS = {
    SlaClass.ADHOC: 1.0,
    SlaClass.THREE_NINES: 1.5,
    SlaClass.FOUR_NINES: 2.0,
    SlaClass.FIVE_NINES: 3.0,
}

# Machine size multipliers applied to base cost
SIZE_MULTIPLIERS = {
    MachineSize.DEFAULT: 1.0,
    MachineSize.H100: 10.0,
}

# Base rates per resource per hour (USD)
BASE_RATES = {
    "cpu_per_vcpu_hr": 0.04,
    "memory_per_gb_hr": 0.005,
    "gpu_per_gpu_hr": 0.50,
}

# Revenue split percentages
AGENT_SHARE = 0.70  # 70% to agent
PLATFORM_SHARE = 0.30  # 30% to platform


def calculate_deployment_cost_per_hour(
    cpu_vcpus: float,
    memory_gb: float,
    gpu_count: int,
    sla_class: str,
    machine_size: str,
) -> float:
    """Calculate hourly cost for a deployment.

    Args:
        cpu_vcpus: Number of vCPUs allocated
        memory_gb: GB of memory allocated
        gpu_count: Number of GPUs allocated
        sla_class: SLA tier (adhoc|three_nines|four_nines|five_nines)
        machine_size: Machine size (default|h100)

    Returns:
        Cost per hour in USD

    Examples:
        Adhoc deployment: 2 vCPUs, 4GB RAM, 0 GPUs
        Cost: (2×$0.04 + 4×$0.005) × 1.0 × 1.0 = $0.10/hour

        Production deployment (3-nines): 4 vCPUs, 8GB RAM, 0 GPUs
        Cost: (4×$0.04 + 8×$0.005) × 1.5 × 1.0 = $0.30/hour

        High-availability GPU (5-nines, H100): 8 vCPUs, 32GB RAM, 1 GPU
        Cost: (8×$0.04 + 32×$0.005 + 1×$0.50) × 3.0 × 10.0 = $25.20/hour
    """
    # Calculate base cost from resources
    base_cost = (
        cpu_vcpus * BASE_RATES["cpu_per_vcpu_hr"]
        + memory_gb * BASE_RATES["memory_per_gb_hr"]
        + gpu_count * BASE_RATES["gpu_per_gpu_hr"]
    )

    # Apply SLA multiplier
    sla_multiplier = SLA_MULTIPLIERS.get(sla_class, 1.0)

    # Apply size multiplier
    size_multiplier = SIZE_MULTIPLIERS.get(machine_size, 1.0)

    return base_cost * sla_multiplier * size_multiplier


def split_revenue(amount: float) -> tuple[float, float]:
    """Split revenue between agent and platform (70/30).

    Args:
        amount: Total revenue amount

    Returns:
        Tuple of (agent_share, platform_share)

    Example:
        Deployment charged $1.00/hour
        Returns: ($0.70, $0.30)
    """
    agent_share = amount * AGENT_SHARE
    platform_share = amount * PLATFORM_SHARE
    return agent_share, platform_share
