# GitHub Secrets Setup

## Required Secrets for CI/CD

### Authentication & Billing Secrets

#### ADMIN_PASSWORD_HASH (Required)
Bcrypt hash of the control plane admin password.

**To generate:**
```bash
python3 scripts/hash_admin_password.py
```

Then add the output to GitHub Secrets:
1. Go to repository Settings → Secrets and variables → Actions
2. Click "New repository secret"
3. Name: `ADMIN_PASSWORD_HASH`
4. Value: The bcrypt hash (e.g., `$2b$12$...`)

**For the default admin password "admin123":**
```
$2b$12$i.TKHTMMDM2EB9x86C67VuDsBHMwBxIekkNxj84L5vd0N2Tl6SSJK
```

**⚠️ Important:** Use a strong password for production!

### Existing Secrets (Already Configured)

The following secrets should already be set:
- `CLOUDFLARE_API_TOKEN` - Cloudflare API token for tunnel management
- `CLOUDFLARE_ACCOUNT_ID` - Cloudflare account ID
- `CLOUDFLARE_ZONE_ID` - Cloudflare zone ID
- `INTEL_API_KEY` - Intel Trust Authority API key
- `CONTROL_PLANE_ADMIN_PASSWORD` - Plaintext admin password (for login testing)

### Optional Secrets (For Payment Processing)

#### STRIPE_SECRET_KEY
Stripe API secret key for payment processing.

Add if you want to enable Stripe payments:
```
sk_live_xxx or sk_test_xxx
```

#### STRIPE_WEBHOOK_SECRET
Stripe webhook signing secret.

Get from Stripe Dashboard → Webhooks:
```
whsec_xxx
```

### Optional Secrets (For Admin Login)

#### GITHUB_OAUTH_CLIENT_ID
GitHub OAuth App client ID (used for admin login).

#### GITHUB_OAUTH_CLIENT_SECRET
GitHub OAuth App client secret (used for admin login).

#### GITHUB_OAUTH_REDIRECT_URI (Optional)
Override the redirect URI configured in the OAuth App.

If omitted, the control plane defaults to:
```
https://app.easyenclave.com/auth/github/callback
```

## Testing Secrets Setup

After adding `ADMIN_PASSWORD_HASH`, trigger a new workflow run:
```bash
git commit --allow-empty -m "Test admin auth"
git push
```

The CI should now pass the "Bootstrap measuring enclave" step.
