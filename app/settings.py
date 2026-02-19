"""DB-backed settings with env-var fallback for EasyEnclave.

Resolution order: DB value > env var > default.
All settings are defined in SETTING_DEFS. Values are cached in memory
with a short TTL to avoid repeated DB reads.
"""

from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass
from datetime import datetime, timezone

from sqlmodel import select

from .database import get_db
from .db_models import Setting

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class SettingDef:
    """Definition of a single setting."""

    key: str
    env_var: str
    default: str
    is_secret: bool
    description: str
    group: str  # e.g. "cloudflare", "github_oauth", "operational"


# ── Registry ─────────────────────────────────────────────────────────────────

SETTING_DEFS: dict[str, SettingDef] = {}


def _reg(key: str, env_var: str, default: str, is_secret: bool, description: str, group: str):
    SETTING_DEFS[key] = SettingDef(key, env_var, default, is_secret, description, group)


# Cloudflare
_reg(
    "cloudflare.account_id",
    "CLOUDFLARE_ACCOUNT_ID",
    "",
    False,
    "Cloudflare account ID",
    "cloudflare",
)
_reg(
    "cloudflare.zone_id",
    "CLOUDFLARE_ZONE_ID",
    "",
    False,
    "Cloudflare zone ID for the domain",
    "cloudflare",
)
_reg(
    "cloudflare.api_token",
    "CLOUDFLARE_API_TOKEN",
    "",
    True,
    "Cloudflare API token (Tunnel + DNS edit)",
    "cloudflare",
)
_reg(
    "cloudflare.domain",
    "EASYENCLAVE_DOMAIN",
    "easyenclave.com",
    False,
    "Domain for agent hostnames",
    "cloudflare",
)

# GitHub OAuth
_reg(
    "github_oauth.client_id",
    "GITHUB_OAUTH_CLIENT_ID",
    "",
    False,
    "GitHub OAuth application client ID",
    "github_oauth",
)
_reg(
    "github_oauth.client_secret",
    "GITHUB_OAUTH_CLIENT_SECRET",
    "",
    True,
    "GitHub OAuth application client secret",
    "github_oauth",
)
_reg(
    "github_oauth.redirect_uri",
    "GITHUB_OAUTH_REDIRECT_URI",
    "https://app.easyenclave.com/auth/github/callback",
    False,
    "GitHub OAuth redirect URI",
    "github_oauth",
)

# Stripe
_reg("stripe.secret_key", "STRIPE_SECRET_KEY", "", True, "Stripe secret API key", "stripe")
_reg(
    "stripe.webhook_secret",
    "STRIPE_WEBHOOK_SECRET",
    "",
    True,
    "Stripe webhook signing secret",
    "stripe",
)

# Intel Trust Authority
_reg(
    "intel_ta.jwks_url",
    "ITA_JWKS_URL",
    "https://portal.trustauthority.intel.com/certs",
    False,
    "Intel Trust Authority JWKS endpoint URL",
    "intel_ta",
)

# Operational
_reg(
    "operational.tcb_enforcement_mode",
    "TCB_ENFORCEMENT_MODE",
    "warn",
    False,
    "TCB enforcement mode: strict, warn, or disabled",
    "operational",
)
_reg(
    "operational.allowed_tcb_statuses",
    "ALLOWED_TCB_STATUSES",
    "UpToDate",
    False,
    "Comma-separated list of allowed TCB statuses",
    "operational",
)
_reg(
    "operational.nonce_enforcement_mode",
    "NONCE_ENFORCEMENT_MODE",
    "optional",
    False,
    "Nonce enforcement mode: required, optional, or disabled",
    "operational",
)
_reg(
    "operational.nonce_ttl_seconds",
    "NONCE_TTL_SECONDS",
    "300",
    False,
    "Nonce time-to-live in seconds",
    "operational",
)
_reg(
    "operational.rtmr_enforcement_mode",
    "RTMR_ENFORCEMENT_MODE",
    "warn",
    False,
    "RTMR enforcement mode: strict, warn, or disabled",
    "operational",
)
_reg(
    "operational.signature_verification_mode",
    "SIGNATURE_VERIFICATION_MODE",
    "warn",
    False,
    "Image signature verification enforcement mode: strict, warn, or disabled",
    "operational",
)
_reg(
    "operational.agent_attestation_interval",
    "AGENT_ATTESTATION_INTERVAL",
    "3600",
    False,
    "Seconds between attestation refreshes (0 to disable)",
    "operational",
)
_reg(
    "operational.agent_attestation_pull_enabled",
    "AGENT_ATTESTATION_PULL_ENABLED",
    "false",
    False,
    "If true, control plane will pull agent attestation via /api/health?attest=true (fallback mode)",
    "operational",
)
_reg(
    "operational.agent_stale_hours",
    "AGENT_STALE_HOURS",
    "24",
    False,
    "Hours before a silent agent is deleted",
    "operational",
)
_reg(
    "operational.capacity_reconcile_interval_seconds",
    "CAPACITY_RECONCILE_INTERVAL_SECONDS",
    "30",
    False,
    "Seconds between warm-capacity reconciliation passes",
    "operational",
)
_reg(
    "operational.capacity_dispatch_cooldown_seconds",
    "CAPACITY_DISPATCH_COOLDOWN_SECONDS",
    "300",
    False,
    "Minimum seconds between repeated dispatches for the same capacity pool",
    "operational",
)
_reg(
    "operational.capacity_order_claim_ttl_seconds",
    "CAPACITY_ORDER_CLAIM_TTL_SECONDS",
    "600",
    False,
    "Seconds before a claimed/provisioning launch order is re-queued",
    "operational",
)
_reg(
    "operational.capacity_fulfilled_grace_seconds",
    "CAPACITY_FULFILLED_GRACE_SECONDS",
    "1800",
    False,
    "Grace period (seconds) to treat fulfilled launch orders as pending capacity before re-dispatch",
    "operational",
)
_reg(
    "operational.gcp_stale_reap_interval_seconds",
    "GCP_STALE_REAP_INTERVAL_SECONDS",
    "60",
    False,
    "Seconds between CP-native stale GCP fulfilled-order VM cleanup passes",
    "operational",
)
_reg(
    "operational.default_gcp_tiny_capacity_enabled",
    "DEFAULT_GCP_TINY_CAPACITY_ENABLED",
    "true",
    False,
    "Keep a default warm pool target for tiny nodes in GCP",
    "operational",
)
_reg(
    "operational.default_gcp_tiny_datacenter",
    "DEFAULT_GCP_TINY_DATACENTER",
    "gcp:us-central1-a",
    False,
    "Datacenter used by default warm tiny capacity target",
    "operational",
)
_reg(
    "operational.default_gcp_tiny_capacity_count",
    "DEFAULT_GCP_TINY_CAPACITY_COUNT",
    "1",
    False,
    "Minimum warm tiny agents kept for the default GCP datacenter",
    "operational",
)
_reg(
    "operational.default_gcp_tiny_capacity_dispatch",
    "DEFAULT_GCP_TINY_CAPACITY_DISPATCH",
    "true",
    False,
    "If true, dispatch external provisioning for default warm tiny GCP capacity",
    "operational",
)

# External provisioner webhook
_reg(
    "provisioner.webhook_url",
    "AGENT_PROVISIONER_WEBHOOK_URL",
    "",
    False,
    "Webhook URL for external agent provisioning requests",
    "provisioner",
)
_reg(
    "provisioner.webhook_token",
    "AGENT_PROVISIONER_WEBHOOK_TOKEN",
    "",
    True,
    "Bearer token used when calling the provisioner webhook",
    "provisioner",
)
_reg(
    "provisioner.timeout_seconds",
    "AGENT_PROVISIONER_TIMEOUT_SECONDS",
    "20",
    False,
    "Timeout in seconds for provisioner webhook calls",
    "provisioner",
)
_reg(
    "provisioner.inventory_url",
    "AGENT_PROVISIONER_INVENTORY_URL",
    "",
    False,
    "Webhook URL for external cloud inventory (Azure/GCP resources)",
    "provisioner",
)
_reg(
    "provisioner.inventory_token",
    "AGENT_PROVISIONER_INVENTORY_TOKEN",
    "",
    True,
    "Bearer token used when calling the inventory webhook (falls back to webhook_token)",
    "provisioner",
)
_reg(
    "provisioner.cleanup_url",
    "AGENT_PROVISIONER_CLEANUP_URL",
    "",
    False,
    "Webhook URL for external cloud resource cleanup",
    "provisioner",
)
_reg(
    "provisioner.cleanup_token",
    "AGENT_PROVISIONER_CLEANUP_TOKEN",
    "",
    True,
    "Bearer token used when calling the cleanup webhook (falls back to webhook_token)",
    "provisioner",
)

# Auth
_reg(
    "auth.password_login_enabled",
    "PASSWORD_LOGIN_ENABLED",
    "true",
    False,
    "Enable password-based admin login (set to 'false' to require GitHub OAuth)",
    "auth",
)
_reg(
    "auth.require_github_oauth_in_production",
    "AUTH_REQUIRE_GITHUB_OAUTH_IN_PRODUCTION",
    "true",
    False,
    "If true, production startup fails when GitHub OAuth is not fully configured",
    "auth",
)
_reg(
    "auth.allow_password_login_in_production",
    "AUTH_ALLOW_PASSWORD_LOGIN_IN_PRODUCTION",
    "false",
    False,
    "If true, allows password admin login in production (legacy fallback)",
    "auth",
)

# Billing
_reg(
    "billing.contributor_pool_bps",
    "BILLING_CONTRIBUTOR_POOL_BPS",
    "5000",
    False,
    "Share of platform split (in basis points) allocated to contributor credits",
    "operational",
)
_reg(
    "billing.platform_account_id",
    "BILLING_PLATFORM_ACCOUNT_ID",
    "",
    False,
    "Optional account_id credited with remaining platform revenue",
    "operational",
)
_reg(
    "billing.capacity_request_dev_simulation",
    "BILLING_CAPACITY_REQUEST_DEV_SIMULATION",
    "true",
    False,
    "If true, capacity purchase charges are simulated (ledger entry amount 0)",
    "operational",
)
_reg(
    "billing.capacity_price_tiny_monthly_usd",
    "BILLING_CAPACITY_PRICE_TINY_MONTHLY_USD",
    "25",
    False,
    "Monthly USD list price per tiny warm-capacity unit",
    "operational",
)
_reg(
    "billing.capacity_price_standard_monthly_usd",
    "BILLING_CAPACITY_PRICE_STANDARD_MONTHLY_USD",
    "100",
    False,
    "Monthly USD list price per standard warm-capacity unit",
    "operational",
)
_reg(
    "billing.capacity_price_llm_monthly_usd",
    "BILLING_CAPACITY_PRICE_LLM_MONTHLY_USD",
    "500",
    False,
    "Monthly USD list price per llm warm-capacity unit",
    "operational",
)


# ── TTL cache ────────────────────────────────────────────────────────────────

_CACHE_TTL = 5  # seconds
_cache: dict[str, str] = {}
_cache_time: float = 0.0


def _refresh_cache() -> None:
    """Bulk-load all settings from DB into the cache."""
    global _cache, _cache_time
    try:
        with get_db() as session:
            rows = session.exec(select(Setting)).all()
        _cache = {r.key: r.value for r in rows}
    except Exception:
        # DB not ready yet (e.g. before init_db) — use empty cache
        _cache = {}
    _cache_time = time.monotonic()


def invalidate_cache() -> None:
    """Force next get_setting() to re-read from DB."""
    global _cache_time
    _cache_time = 0.0


def _ensure_cache() -> None:
    if time.monotonic() - _cache_time > _CACHE_TTL:
        _refresh_cache()


# ── Accessors ────────────────────────────────────────────────────────────────


def get_setting(key: str) -> str:
    """Return the effective value for *key*.

    Resolution: DB (non-empty) > env var (non-empty) > default.
    Raises KeyError for unknown keys.
    """
    defn = SETTING_DEFS.get(key)
    if defn is None:
        raise KeyError(f"Unknown setting: {key}")

    _ensure_cache()
    db_val = _cache.get(key)
    if db_val is not None and db_val != "":
        return db_val

    env_val = os.environ.get(defn.env_var, "")
    if env_val:
        return env_val

    return defn.default


def get_setting_int(key: str, fallback: int | None = None) -> int:
    """get_setting() coerced to int."""
    raw = get_setting(key)
    try:
        return int(raw)
    except (ValueError, TypeError):
        if fallback is not None:
            return fallback
        raise


def get_setting_set(key: str) -> set[str]:
    """get_setting() split on commas into a set of stripped strings."""
    return {s.strip() for s in get_setting(key).split(",") if s.strip()}


def get_setting_source(key: str) -> str:
    """Return where the effective value comes from: 'db', 'env', or 'default'."""
    defn = SETTING_DEFS.get(key)
    if defn is None:
        raise KeyError(f"Unknown setting: {key}")

    _ensure_cache()
    db_val = _cache.get(key)
    if db_val is not None and db_val != "":
        return "db"

    env_val = os.environ.get(defn.env_var, "")
    if env_val:
        return "env"

    return "default"


# ── CRUD ─────────────────────────────────────────────────────────────────────


def set_setting(key: str, value: str) -> None:
    """Write a setting to the DB (upsert)."""
    defn = SETTING_DEFS.get(key)
    if defn is None:
        raise KeyError(f"Unknown setting: {key}")

    with get_db() as session:
        existing = session.get(Setting, key)
        if existing:
            existing.value = value
            existing.is_secret = defn.is_secret
            existing.updated_at = datetime.now(timezone.utc)
            session.add(existing)
        else:
            session.add(
                Setting(
                    key=key,
                    value=value,
                    is_secret=defn.is_secret,
                    updated_at=datetime.now(timezone.utc),
                )
            )
    invalidate_cache()


def delete_setting(key: str) -> bool:
    """Remove a setting from the DB (reverts to env/default). Returns True if existed."""
    defn = SETTING_DEFS.get(key)
    if defn is None:
        raise KeyError(f"Unknown setting: {key}")

    with get_db() as session:
        existing = session.get(Setting, key)
        if existing:
            session.delete(existing)
            invalidate_cache()
            return True
    return False


def _mask_secret(value: str) -> str:
    """Mask a secret value for display."""
    if not value or len(value) <= 8:
        return "****"
    return value[:4] + "****" + value[-4:]


def list_settings(group: str | None = None) -> list[dict]:
    """List all settings with metadata, values (masked if secret), and sources."""
    _ensure_cache()
    result = []
    for defn in SETTING_DEFS.values():
        if group and defn.group != group:
            continue

        source = get_setting_source(defn.key)
        raw_value = get_setting(defn.key)

        # Mask secrets — only mask if there's a real value
        if defn.is_secret and raw_value:
            display_value = _mask_secret(raw_value)
        else:
            display_value = raw_value

        result.append(
            {
                "key": defn.key,
                "value": display_value,
                "source": source,
                "is_secret": defn.is_secret,
                "description": defn.description,
                "group": defn.group,
                "env_var": defn.env_var,
                "default": defn.default,
            }
        )
    return result


def clear_settings() -> None:
    """Delete all settings from DB (for tests)."""
    with get_db() as session:
        for s in session.exec(select(Setting)).all():
            session.delete(s)
    invalidate_cache()


def log_settings_sources() -> None:
    """Log the source of each setting on startup."""
    _ensure_cache()
    for defn in SETTING_DEFS.values():
        source = get_setting_source(defn.key)
        value = get_setting(defn.key)
        if defn.is_secret and value:
            value = _mask_secret(value)
        logger.info(f"Setting {defn.key}: source={source}, value={value or '(empty)'}")
