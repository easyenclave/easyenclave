# GitHub Secrets Setup

## VM Image Workflow Inputs

The VM image pipeline now has two distinct stages:
- Pull requests: build the VM image, publish a public `ee-smoke-admin` image to `ttl.sh`, and run a native integration test against a temporary GCP image.
- Pushes to `main`: build the VM image, publish a public `ee-smoke-admin` image to `ttl.sh`, smoke-test a release candidate with that native static workload, then publish the verified image in the EasyEnclave GCP project by default.

### Required for VM image publishing

- `GCP_PROJECT_ID` secret: default GCP project used for PR image tests if `TEST_GCP_PROJECT_ID` is not set.
- `GCS_BUCKET` secret: default bucket used to stage the raw disk tarball if `TEST_GCS_BUCKET` or `RELEASE_GCS_BUCKET` are not set.

The workflow now generates a default `ee-config` automatically around the public `ee-smoke-admin` image, so no smoke-test workload variable is required for the default path.

### Optional VM image variables

- `TEST_GCP_PROJECT_ID`: override the PR-test project instead of using `GCP_PROJECT_ID`.
- `TEST_GCS_BUCKET`: override the PR-test staging bucket instead of using `GCS_BUCKET`.
- `TEST_ZONE`: override the default PR-test zone (`us-central1-c`).
- `TEST_MACHINE_TYPE`: override the default PR-test machine type (`c3-standard-4`).
- `PR_TEST_EE_CONFIG_JSON`: override the PR integration test workload. If set, it must still include at least one `"native": true` workload image because the PR smoke test now exercises the native path.
- `RELEASE_GCP_PROJECT_ID`: override the release project instead of using `GCP_PROJECT_ID`.
- `RELEASE_GCS_BUCKET`: override the release staging bucket instead of using `GCS_BUCKET`.
- `RELEASE_ZONE`: override the default release smoke-test zone (`us-central1-c`).
- `RELEASE_MACHINE_TYPE`: override the default release smoke-test machine type (`c3-standard-4`).
- `RELEASE_TEST_EE_CONFIG_JSON`: override the default `ee-smoke-admin` release smoke-test workload. If set, it must include at least one `"native": true` workload image.
- `RELEASE_IMAGE_PREFIX`: override the final image name prefix. Default: `easyenclave-release`.
- `RELEASE_IMAGE_FAMILY`: override the final release image family. Default: `easyenclave-release`.
- `GCP_WORKLOAD_IDENTITY_PROVIDER`: override the default GitHub Actions workload identity provider.
- `GCP_SERVICE_ACCOUNT`: override the default GitHub Actions service account.

## Required Secrets for CI/CD

### Authentication & Billing Secrets

#### ADMIN_PASSWORD_HASH (Required)
Bcrypt hash of the control plane admin password.

**To generate:**
```bash
cargo run --bin ee-admin -- hash-admin-password
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
- `CP_MEASUREMENTS_SIGNING_KEY` - Base fallback signing key for CP measurement bundle signing
- `STAGING_CP_MEASUREMENTS_SIGNING_KEY` / `PRODUCTION_CP_MEASUREMENTS_SIGNING_KEY` - Env-specific overrides (recommended)
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

#### EE_GITHUB_OAUTH_CLIENT_ID
GitHub OAuth App client ID (used for admin login).

#### EE_GITHUB_OAUTH_CLIENT_SECRET
GitHub OAuth App client secret (used for admin login).

#### EE_GITHUB_OAUTH_REDIRECT_URI (Optional)
Override the redirect URI configured in the OAuth App.

If omitted, the control plane defaults to:
```
https://app.easyenclave.com/auth/github/callback
```

#### ADMIN_GITHUB_LOGINS (Recommended)
Comma-separated GitHub logins that should have **admin** access after GitHub OAuth login.

Example:
```
alice,bob
```

Note: GitHub Actions blocks repository secret names starting with `GITHUB_`, so we store OAuth
secrets with the `EE_GITHUB_...` prefix and map them into `GITHUB_OAUTH_...` env vars at runtime.

## Testing Secrets Setup

After adding `ADMIN_PASSWORD_HASH`, trigger a new workflow run:
```bash
git commit --allow-empty -m "Test admin auth"
git push
```

The CI should now pass the "Bootstrap measuring enclave" step.
