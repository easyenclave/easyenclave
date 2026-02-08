# Fresh Setup Guide - Auth & Billing

Since you're starting with a clean database, the setup is much simpler!

## Quick Start

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Clear Database

```bash
# Delete existing database
rm -f easyenclave.db

# Or if using custom path
rm -f $EASYENCLAVE_DB_PATH
```

### 3. Set Admin Password

```bash
# Generate password hash
python3 scripts/hash_admin_password.py

# Copy the output and set environment variable
export ADMIN_PASSWORD_HASH='$2b$12$...'
```

### 4. (Optional) Configure Stripe

```bash
export STRIPE_SECRET_KEY=sk_test_xxx  # or sk_live_xxx for production
export STRIPE_WEBHOOK_SECRET=whsec_xxx
```

### 5. Start Control Plane

```bash
python3 -m uvicorn app.main:app --host 0.0.0.0 --port 8000
```

The database schema will be created automatically with all the new fields!

## First Steps After Startup

### Create Your First Account

```bash
curl -X POST http://localhost:8000/api/v1/accounts \
  -H "Content-Type: application/json" \
  -d '{
    "name": "my-deployer-account",
    "account_type": "deployer",
    "description": "Main deployment account"
  }'
```

**Important**: Save the `api_key` from the response - it's only shown once!

Example response:
```json
{
  "account_id": "550e8400-e29b-41d4-a716-446655440000",
  "name": "my-deployer-account",
  "account_type": "deployer",
  "balance": 0.0,
  "created_at": "2026-02-08T12:00:00Z",
  "api_key": "ee_live_AbCdEfGh12345678901234567890",
  "warning": "Save this API key now. It will never be shown again."
}
```

### Add Funds (Manual Deposit for Testing)

```bash
curl -X POST http://localhost:8000/api/v1/accounts/{account_id}/deposit \
  -H "Authorization: Bearer ee_live_xxx" \
  -H "Content-Type: application/json" \
  -d '{
    "amount": 100.0,
    "description": "Initial deposit"
  }'
```

### Deploy with Billing

```bash
curl -X POST http://localhost:8000/api/v1/apps/hello-tdx/versions/v1/deploy \
  -H "Content-Type: application/json" \
  -d '{
    "agent_id": "agent-uuid",
    "account_id": "550e8400-e29b-41d4-a716-446655440000",
    "sla_class": "adhoc",
    "machine_size": "default",
    "cpu_vcpus": 2.0,
    "memory_gb": 4.0,
    "gpu_count": 0
  }'
```

### Check Balance & Transactions

```bash
# View account
curl http://localhost:8000/api/v1/accounts/{account_id} \
  -H "Authorization: Bearer ee_live_xxx"

# List transactions
curl http://localhost:8000/api/v1/accounts/{account_id}/transactions \
  -H "Authorization: Bearer ee_live_xxx"
```

### Admin Login (for Admin UI)

```bash
curl -X POST http://localhost:8000/admin/login \
  -H "Content-Type: application/json" \
  -d '{
    "password": "your_admin_password"
  }'
```

Save the `token` from response and use it for admin endpoints:

```bash
# List all accounts (admin only)
curl http://localhost:8000/api/v1/accounts \
  -H "Authorization: Bearer <admin_session_token>"
```

## Environment Variables Summary

**Required:**
- `ADMIN_PASSWORD_HASH` - bcrypt hash from `scripts/hash_admin_password.py`

**Optional:**
- `EASYENCLAVE_DB_PATH` - Database path (defaults to `./easyenclave.db`)
- `STRIPE_SECRET_KEY` - For Stripe payment processing
- `STRIPE_WEBHOOK_SECRET` - For Stripe webhook verification
- `TRUSTED_AGENT_MRTDS` - Comma-separated trusted agent MRTDs
- `TRUSTED_PROXY_MRTDS` - Comma-separated trusted proxy MRTDs

## Testing the Full Flow

```bash
# 1. Create deployer account
RESPONSE=$(curl -s -X POST http://localhost:8000/api/v1/accounts \
  -H "Content-Type: application/json" \
  -d '{"name":"test-deployer","account_type":"deployer"}')

ACCOUNT_ID=$(echo $RESPONSE | jq -r '.account_id')
API_KEY=$(echo $RESPONSE | jq -r '.api_key')

echo "Account ID: $ACCOUNT_ID"
echo "API Key: $API_KEY"

# 2. Create agent account (for earnings)
AGENT_RESPONSE=$(curl -s -X POST http://localhost:8000/api/v1/accounts \
  -H "Content-Type: application/json" \
  -d '{"name":"test-agent","account_type":"agent"}')

AGENT_ACCOUNT_ID=$(echo $AGENT_RESPONSE | jq -r '.account_id')
echo "Agent Account ID: $AGENT_ACCOUNT_ID"

# 3. Add funds to deployer account
curl -X POST http://localhost:8000/api/v1/accounts/$ACCOUNT_ID/deposit \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"amount": 10.0, "description": "Test deposit"}'

# 4. Check balance
curl http://localhost:8000/api/v1/accounts/$ACCOUNT_ID \
  -H "Authorization: Bearer $API_KEY"

# 5. Deploy (will start hourly charging)
# Note: Replace agent_id with real agent after agent registration
curl -X POST http://localhost:8000/api/v1/apps/hello-tdx/versions/v1/deploy \
  -H "Content-Type: application/json" \
  -d "{
    \"agent_id\": \"your-agent-id\",
    \"account_id\": \"$ACCOUNT_ID\",
    \"sla_class\": \"adhoc\",
    \"machine_size\": \"default\",
    \"cpu_vcpus\": 2.0,
    \"memory_gb\": 4.0,
    \"gpu_count\": 0
  }"

# 6. Wait 1 hour and check transactions again to see automatic charge
```

## Pricing Examples

**Adhoc (development):**
- 2 vCPUs, 4GB RAM → $0.10/hour

**Three-nines SLA (production):**
- 4 vCPUs, 8GB RAM → $0.30/hour

**Five-nines SLA with H100 GPU:**
- 8 vCPUs, 32GB RAM, 1 GPU → $25.20/hour

## Background Tasks Active

Once the control plane starts, these tasks run automatically:
- ⏰ **Hourly charging** - Charges running deployments, pays agents 70%
- 🛑 **Insufficient funds terminator** - Stops deployments with no balance
- 🧹 **Session cleanup** - Removes expired admin sessions

## Troubleshooting

**"Invalid API key"**
- Make sure you saved the API key from account creation
- Check Authorization header format: `Bearer ee_live_xxx`

**"Insufficient funds"**
- Deposit funds before deploying: `POST /api/v1/accounts/{id}/deposit`
- Minimum balance = 1 hour of deployment cost

**"Admin password not configured"**
- Run `python3 scripts/hash_admin_password.py`
- Set `ADMIN_PASSWORD_HASH` environment variable
- Restart control plane

**Stripe not working**
- Check `STRIPE_SECRET_KEY` is set
- Verify webhook secret matches Stripe dashboard
- Check logs for Stripe API errors

## Next Steps

1. ✅ Start with fresh database
2. ✅ Create accounts and save API keys
3. ✅ Register agents and link to billing accounts
4. ✅ Deploy apps with billing enabled
5. ✅ Monitor transactions hourly

See `AUTH_AND_BILLING.md` for complete documentation.
