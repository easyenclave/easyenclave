# Deployment Checklist - Auth & Billing System

## ✅ Implementation Complete

All core features have been implemented and tested:

- ✅ API key authentication per account (Signal-inspired privacy)
- ✅ Admin session-based authentication (24h expiration)
- ✅ Tiered pricing system (adhoc, 3-nines, 4-nines, 5-nines)
- ✅ Machine size support (default, h100)
- ✅ Automated hourly charging with 70/30 revenue split
- ✅ Prepaid model with balance checks
- ✅ Insufficient funds handling & auto-termination
- ✅ Stripe payment integration (optional)
- ✅ Protected billing endpoints
- ✅ Background tasks for charging & cleanup

## 🚀 Quick Deploy Steps

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Clear Database (Fresh Start)
```bash
rm -f easyenclave.db
# Or: rm -f $EASYENCLAVE_DB_PATH
```

### 3. Set Admin Password
```bash
python3 scripts/hash_admin_password.py
# Copy output and set:
export ADMIN_PASSWORD_HASH='$2b$12$...'
```

### 4. Start Control Plane
```bash
python3 -m uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Done! The new schema will be created automatically.

## 📋 Post-Deployment Tasks

### Create Your First Account
```bash
curl -X POST http://localhost:8000/api/v1/accounts \
  -H "Content-Type: application/json" \
  -d '{"name":"main-deployer","account_type":"deployer"}'
```
**Save the `api_key` - it's shown only once!**

### Add Test Funds
```bash
curl -X POST http://localhost:8000/api/v1/accounts/{id}/deposit \
  -H "Authorization: Bearer ee_live_xxx" \
  -d '{"amount":10.0}'
```

### Deploy with Billing
```bash
curl -X POST http://localhost:8000/api/v1/apps/hello-tdx/versions/v1/deploy \
  -d '{
    "agent_id":"agent-uuid",
    "account_id":"account-uuid",
    "sla_class":"adhoc",
    "cpu_vcpus":2.0,
    "memory_gb":4.0
  }'
```

## 📊 Background Tasks

These run automatically:
- ⏰ **Hourly Charging** - Every 60 minutes, charges active deployments
- 🛑 **Fund Terminator** - Every minute, stops deployments with $0 balance
- 🧹 **Session Cleanup** - Every hour, removes expired admin sessions

## 🔐 Security Notes

- API keys are bcrypt hashed (never stored in plaintext)
- Sessions expire after 24 hours
- Users can only access their own account data
- Admin endpoints require separate authentication
- All credentials use bcrypt with salt

## 💳 Stripe Setup (Optional)

If you want payment processing:

```bash
export STRIPE_SECRET_KEY=sk_test_xxx
export STRIPE_WEBHOOK_SECRET=whsec_xxx
```

Configure webhook in Stripe Dashboard:
- URL: `https://your-domain/api/v1/webhooks/stripe`
- Event: `payment_intent.succeeded`

## 📈 Pricing Reference

| Configuration | Cost/Hour |
|---------------|-----------|
| Adhoc (2 vCPU, 4GB) | $0.10 |
| 3-nines (4 vCPU, 8GB) | $0.30 |
| 5-nines (8 vCPU, 32GB) | $2.52 |
| 5-nines H100 (8 vCPU, 32GB, 1 GPU) | $25.20 |

**Revenue Split:** 70% agent, 30% platform

## 📚 Documentation

- **`SETUP_FRESH.md`** - Detailed fresh start guide
- **`AUTH_AND_BILLING.md`** - Complete feature documentation
- **`migrations/001_add_auth_and_billing.py`** - Migration script (if needed later)
- **`scripts/hash_admin_password.py`** - Admin password generator

## 🧪 Testing

Test core functionality:
```bash
python3 -c "from app.auth import generate_api_key; print(generate_api_key('live'))"
```

Expected output: `ee_live_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`

## ⚠️ Important Notes

1. **Save API keys immediately** - They're only shown once during account creation
2. **Set ADMIN_PASSWORD_HASH** - Required for admin login
3. **Minimum balance** - Deployments require balance >= 1 hour cost
4. **Hourly charges** - First charge happens ~1 hour after deployment starts
5. **Auto-termination** - Deployments stop when balance reaches $0

## 🐛 Troubleshooting

**"Admin password not configured"**
→ Run `scripts/hash_admin_password.py` and set `ADMIN_PASSWORD_HASH`

**"Invalid API key"**
→ Check format: `Authorization: Bearer ee_live_xxx`

**"Insufficient funds"**
→ Deposit before deploying: `POST /accounts/{id}/deposit`

**Stripe not working**
→ Check `STRIPE_SECRET_KEY` is set, verify webhook secret

## ✨ Features Summary

**Authentication:**
- Per-account API keys (ee_live_xxx format)
- Admin sessions (24h expiration)
- bcrypt password hashing
- Fast prefix-based lookups

**Billing:**
- Tiered SLA pricing (1.0x to 3.0x multiplier)
- Machine sizes (1.0x to 10.0x multiplier)
- Hourly automated charging
- Agent revenue sharing (70/30 split)
- Prepaid model with auto-termination
- Stripe payment processing

**Endpoints:**
- `POST /admin/login` - Admin authentication
- `POST /api/v1/accounts` - Create account (returns API key once!)
- `GET /api/v1/accounts/{id}` - View account (auth required)
- `POST /api/v1/accounts/{id}/deposit` - Add funds (auth required)
- `POST /api/v1/accounts/{id}/payment-intent` - Stripe payment (auth required)
- `POST /api/v1/webhooks/stripe` - Stripe webhook
- `POST /api/v1/apps/{name}/versions/{version}/deploy` - Deploy with billing

## 🎯 Ready to Deploy!

All implementation is complete. Follow the Quick Deploy Steps above and you're ready to go! 🚀
