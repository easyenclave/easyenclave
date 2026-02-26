# Authentication and Billing System

This document describes the authentication and automated billing features implemented for EasyEnclave.

## Overview

The system provides:
- **API Key Authentication**: Per-account API keys for secure access (Signal-inspired privacy model)
- **Admin Session Authentication**: Session-based auth for admin UI with 24h expiration
- **Tiered Pricing**: SLA-based pricing (adhoc, 3-nines, 4-nines, 5-nines availability)
- **Machine Sizes**: Default and h100 (GPU) instance types
- **Automated Charging**: Hourly billing for running deployments
- **Agent Revenue Sharing**: 70/30 split between agents and platform
- **Prepaid Model**: Deployments require sufficient funds, auto-terminated on insufficient balance
- **Stripe Integration**: Payment processing for deposits

## Database Schema Changes

### Account Table
- `api_key_hash`: bcrypt hash of API key
- `api_key_prefix`: First 12 chars of API key (indexed for fast lookup)

### AdminSession Table (new)
- `session_id`: UUID primary key
- `token_hash`: bcrypt hash of session token
- `token_prefix`: First 12 chars of token (indexed)
- `created_at`, `expires_at`, `last_used`: Timestamp fields
- `ip_address`: IP of login (audit trail)

### Deployment Table
- `account_id`: Link to billing account (nullable for backward compat)
- `sla_class`: "adhoc"|"three_nines"|"four_nines"|"five_nines"
- `machine_size`: "default"|"h100"
- `cpu_vcpus`, `memory_gb`, `gpu_count`: Resource specs for cost calculation
- `last_charge_time`: Timestamp of last charge
- `total_charged`: Running total of charges

### Agent Table
- `account_id`: Agent's billing account for earnings (nullable)
- `sla_tiers`: List of SLA tiers agent supports
- `machine_sizes`: List of machine sizes agent supports

## API Changes

### Authentication

#### Account API Key Authentication
All billing endpoints now require `Authorization: Bearer ee_live_xxx` header:
- `GET /api/v1/accounts/{id}` - View account (owner only)
- `DELETE /api/v1/accounts/{id}` - Delete account (owner only)
- `POST /api/v1/accounts/{id}/deposit` - Deposit funds (owner only)
- `GET /api/v1/accounts/{id}/transactions` - View transactions (owner only)
- `POST /api/v1/accounts/{id}/payment-intent` - Create Stripe payment (owner only)

#### Admin Authentication
Admin endpoints require `Authorization: Bearer <session_token>`:
- `GET /api/v1/accounts` - List all accounts (admin only)

#### New Endpoints

**Admin Login**
```bash
POST /admin/login
{
  "password": "admin_password"
}

Response:
{
  "token": "session_token",
  "expires_at": "2026-02-09T12:00:00Z"
}
```

**Create Account** (returns API key once!)
```bash
POST /api/v1/accounts
{
  "name": "my-account",
  "account_type": "deployer",
  "description": "Optional"
}

Response:
{
  "account_id": "uuid",
  "name": "my-account",
  "account_type": "deployer",
  "balance": 0.0,
  "created_at": "2026-02-08T...",
  "api_key": "ee_live_xxx",  # ONLY shown once!
  "warning": "Save this API key now. It will never be shown again."
}
```

**Create Payment Intent**
```bash
POST /api/v1/accounts/{id}/payment-intent
Authorization: Bearer ee_live_xxx
{
  "amount": 100.00
}

Response:
{
  "client_secret": "pi_xxx_secret_xxx",
  "amount": 100.00,
  "payment_intent_id": "pi_xxx"
}
```

**Stripe Webhook**
```bash
POST /api/v1/webhooks/stripe
Stripe-Signature: xxx

# Automatically processes payment_intent.succeeded events
# Creates deposit transaction when payment confirmed
```

### Deployment Changes

**Deploy with Billing**
```bash
POST /api/v1/apps/{name}/versions/{version}/deploy
{
  "agent_id": "uuid",
  "config": {},
  "account_id": "uuid",  # Optional for backward compat
  "sla_class": "three_nines",  # adhoc|three_nines|four_nines|five_nines
  "machine_size": "default",  # default|h100
  "cpu_vcpus": 2.0,
  "memory_gb": 4.0,
  "gpu_count": 0
}
```

- If `account_id` provided, checks prepaid balance >= 1 hour cost
- Returns 402 if insufficient funds
- Deployment includes billing fields for hourly charging

## Pricing

### Base Rates (USD per hour)
- CPU: $0.04 per vCPU
- Memory: $0.005 per GB
- GPU: $0.50 per GPU

### SLA Multipliers
- `adhoc`: 1.0x (dev/test, no guarantees)
- `three_nines`: 1.5x (99.9% uptime)
- `four_nines`: 2.0x (99.99% uptime)
- `five_nines`: 3.0x (99.999% uptime)

### Machine Size Multipliers
- `default`: 1.0x
- `h100`: 10.0x (large GPU instances)

### Examples

**Adhoc deployment (dev/test):**
- 2 vCPUs, 4GB RAM, 0 GPUs
- Cost: (2×$0.04 + 4×$0.005) × 1.0 × 1.0 = **$0.10/hour**

**Production deployment (3-nines SLA):**
- 4 vCPUs, 8GB RAM, 0 GPUs
- Cost: (4×$0.04 + 8×$0.005) × 1.5 × 1.0 = **$0.30/hour**

**High-availability GPU (5-nines, H100):**
- 8 vCPUs, 32GB RAM, 1 GPU
- Cost: (8×$0.04 + 32×$0.005 + 1×$0.50) × 3.0 × 10.0 = **$25.20/hour**

## Background Tasks

### Hourly Charging (runs every hour)
1. Finds all `running` deployments
2. Calculates hours since last charge
3. Computes cost based on SLA/size/resources
4. Checks account balance
5. If sufficient: creates charge transaction, pays agent 70%, updates deployment
6. If insufficient: marks deployment `insufficient_funds`

### Insufficient Funds Terminator (runs every minute)
1. Finds deployments with status `insufficient_funds`
2. Calls agent API: `POST /api/terminate`
3. Updates deployment status to `terminated`
4. Resets agent for reassignment

### Session Cleanup (runs every hour)
- Deletes expired admin sessions (>24h old)

## Revenue Sharing

**70/30 Split:**
- 70% goes to agent (if agent has `account_id` set)
- 30% retained by platform

Example: $1.00/hour deployment
- Agent earns: $0.70/hour
- Platform keeps: $0.30/hour

## Environment Variables

Required:
- `ADMIN_PASSWORD_HASH`: bcrypt hash of admin password (generate with `scripts/hash_admin_password.py`)

Optional (for Stripe):
- `STRIPE_SECRET_KEY`: Stripe API secret key (sk_live_xxx or sk_test_xxx)
- `STRIPE_WEBHOOK_SECRET`: Stripe webhook signing secret (whsec_xxx)

## Migration

Run the migration script to update existing data:

```bash
python3 migrations/001_add_auth_and_billing.py
```

This will:
1. Generate API keys for existing accounts (printed once - save them!)
2. Set default SLA/size for existing deployments
3. Initialize billing fields on agents

## Security Model (Signal-Inspired)

- **Privacy-First**: Accounts identified by API key only (no email/phone required)
- **One-Time Keys**: API keys shown once during account creation, never retrievable
- **Hash Storage**: All credentials stored as bcrypt hashes, never plaintext
- **Fast Lookup**: Indexed prefixes for quick authentication without scanning all hashes
- **Session Expiry**: Admin sessions expire after 24h
- **Audit Trail**: IP addresses logged for admin logins
- **Account Isolation**: Users can only access their own account data (403 for others)
- **Admin Oversight**: Admins can view all accounts (logged for audit)

## Testing

See `tests/test_auth.py`, `tests/test_pricing.py`, `tests/test_charging.py` for unit tests.

Example end-to-end test:

```bash
# 1. Create account
curl -X POST http://localhost:8080/api/v1/accounts \
  -H "Content-Type: application/json" \
  -d '{"name":"test-account","account_type":"deployer"}'
# Save the api_key from response

# 2. Create payment intent
curl -X POST http://localhost:8080/api/v1/accounts/{id}/payment-intent \
  -H "Authorization: Bearer ee_live_xxx" \
  -H "Content-Type: application/json" \
  -d '{"amount":100.0}'
# Complete payment with Stripe.js on frontend

# 3. Deploy with billing
curl -X POST http://localhost:8080/api/v1/apps/hello-tdx/versions/v1/deploy \
  -H "Authorization: Bearer ee_live_xxx" \
  -H "Content-Type: application/json" \
  -d '{
    "agent_id":"agent-uuid",
    "account_id":"account-uuid",
    "sla_class":"three_nines",
    "machine_size":"default",
    "cpu_vcpus":2.0,
    "memory_gb":4.0,
    "gpu_count":0
  }'

# 4. Check transactions after 1 hour
curl http://localhost:8080/api/v1/accounts/{id}/transactions \
  -H "Authorization: Bearer ee_live_xxx"
# Should show charge transaction
```

## Stripe Integration Setup

1. Create Stripe account at https://stripe.com
2. Get API keys from Dashboard > Developers > API keys
3. Set environment variables:
   ```bash
   export STRIPE_SECRET_KEY=sk_live_xxx   # or sk_test_xxx for test mode
   export STRIPE_WEBHOOK_SECRET=whsec_xxx # from Stripe webhook configuration
   ```
   If you're using `docker-compose.yml`, add these to `.env` (do not commit the file) and restart:
   ```bash
   echo "STRIPE_SECRET_KEY=sk_test_xxx" >> .env
   echo "STRIPE_WEBHOOK_SECRET=whsec_xxx" >> .env
   docker compose up -d --build
   ```
4. Configure webhook endpoint in Stripe Dashboard:
   - URL: `https://your-cp-domain/api/v1/webhooks/stripe`
   - Events: `payment_intent.succeeded`
5. Use Stripe.js on frontend to collect payment and confirm PaymentIntent

## Admin Password Setup

```bash
# Generate password hash
python3 scripts/hash_admin_password.py
# Enter your password when prompted

# Add to environment
export ADMIN_PASSWORD_HASH='$2b$12$...'

# Or add to .env file
echo "ADMIN_PASSWORD_HASH=\$2b\$12\$..." >> .env
```

## Files Changed/Added

### New Files
- `app/auth.py` - Authentication utilities (API key & session management)
- `app/billing.py` - Automated charging & Stripe integration
- `app/pricing.py` - Tiered pricing calculations
- `scripts/hash_admin_password.py` - Password hash generator
- `migrations/001_add_auth_and_billing.py` - Database migration script

### Modified Files
- `app/db_models.py` - Added auth/billing fields to Account, Agent, Deployment; added AdminSession table
- `app/storage.py` - Added AdminSessionStore, get_by_api_key_prefix method
- `app/models.py` - Added billing fields to DeployFromVersionRequest, added AdminLoginRequest/Response, CreatePaymentIntentRequest
- `app/main.py` - Protected billing endpoints, added admin login, added billing checks to deployment, added background tasks
- `requirements.txt` - Added bcrypt, stripe

## Next Steps

1. Run migration: `python3 migrations/001_add_auth_and_billing.py`
2. Set admin password: `python3 scripts/hash_admin_password.py`
3. Configure Stripe (optional): Set `STRIPE_SECRET_KEY` and `STRIPE_WEBHOOK_SECRET`
4. Restart control plane
5. Test authentication and billing flows
6. Update admin UI to show billing info (future work)
