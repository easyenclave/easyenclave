# GitHub Secrets Setup (v2)

This guide covers secrets used by the Go rewrite workflows and production runtime.

## Required for Release/Deploy Automation

### Cloudflare
- `CLOUDFLARE_API_TOKEN`
- `CLOUDFLARE_ACCOUNT_ID`
- `CLOUDFLARE_ZONE_ID`

Used for control-plane tunnel and traffic routing automation.

### Intel Trust Authority
- `ITA_API_KEY`

Used for attestation flows where ITA token minting is enabled.

## Required for Auth/Admin in Production

### Admin Password Hash
- `ADMIN_PASSWORD_HASH`

Store a bcrypt hash (not plaintext).

Example generation (with apache2-utils):
```bash
htpasswd -bnBC 12 "" "<strong-password>" | tr -d ':\n'
```

### Optional GitHub OAuth (admin login)
- `EE_GITHUB_OAUTH_CLIENT_ID`
- `EE_GITHUB_OAUTH_CLIENT_SECRET`
- `EE_GITHUB_OAUTH_REDIRECT_URI` (optional override)
- `ADMIN_GITHUB_LOGINS` (comma-separated allowlist)

Note: `EE_GITHUB_*` naming is used because GitHub Actions restricts secret names beginning with `GITHUB_`.

## Optional Billing
- `STRIPE_SECRET_KEY`
- `STRIPE_WEBHOOK_SECRET`

## Optional Runtime/Provisioning
- `CONTROL_PLANE_IMAGE`
- `EASYENCLAVE_DOMAIN`
- `EASYENCLAVE_ENV`
- `EASYENCLAVE_NETWORK_NAME`

## Validation Checklist
1. Add/update secrets in repository Actions secrets.
2. Trigger workflows (`v2 CI`, `v2 E2E`, `v2 Release` as applicable).
3. Confirm workflows complete without secret-resolution failures.
4. Verify runtime env mapping in deployment manifests before production rollout.
