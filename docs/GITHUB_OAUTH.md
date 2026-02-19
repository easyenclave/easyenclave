# GitHub OAuth Authentication

EasyEnclave now supports GitHub OAuth for admin authentication, providing better security, audit trails, and user management compared to a single shared password.

## Benefits

- **Per-user identity**: Each admin has their own GitHub account (no shared passwords)
- **Built-in MFA**: Leverage GitHub's 2FA/security policies
- **Audit trail**: GitHub logs all OAuth approvals and token usage
- **Simpler onboarding**: No need to share passwords or manage API keys manually
- **Future extensibility**: Foundation for auto-provisioning accounts from GitHub org membership

## Setup

### 1. Create GitHub OAuth App

1. Go to https://github.com/settings/developers
2. Click "New OAuth App"
3. Fill in the details:
   - **Application name**: EasyEnclave Control Plane
   - **Homepage URL**: https://easyenclave.com
   - **Authorization callback URL**: https://app.easyenclave.com/auth/github/callback
4. Click "Register application"
5. Copy the **Client ID** and generate a new **Client Secret**

### 2. Configure Environment Variables

Add these environment variables to your deployment:

```bash
GITHUB_OAUTH_CLIENT_ID=your_client_id_here
GITHUB_OAUTH_CLIENT_SECRET=your_client_secret_here
GITHUB_OAUTH_REDIRECT_URI=https://app.easyenclave.com/auth/github/callback
```

For local development:
```bash
export GITHUB_OAUTH_CLIENT_ID=your_client_id_here
export GITHUB_OAUTH_CLIENT_SECRET=your_client_secret_here
export GITHUB_OAUTH_REDIRECT_URI=http://localhost:8000/auth/github/callback
```

### 3. Restart Control Plane

```bash
docker compose up -d --build
```

The control plane initializes schema directly at startup.

## Usage

### Admin Login

Visit `/admin` and click **"Sign in with GitHub"**. You'll be redirected to GitHub to authorize the application, then redirected back to the admin panel with an active session.

Password login can be used as a legacy fallback in non-production environments.
In production, password login is disabled by default and GitHub OAuth is expected.

### Session Management

- GitHub OAuth sessions expire after 24 hours (same as password-based sessions)
- Sessions are stored in the `admin_sessions` table with the following GitHub fields:
  - `github_id`: GitHub user ID
  - `github_login`: GitHub username
  - `github_email`: Verified email address
  - `github_avatar_url`: Profile picture URL
  - `auth_method`: "github_oauth" or "password"

### Audit Trail

All OAuth logins are logged with:
```
Admin logged in via GitHub: {github_login} from {ip_address}
```

This provides a clear audit trail of who accessed the admin panel and when.

## Architecture

### New Endpoints

- `GET /auth/github` - Initiates OAuth flow, returns authorization URL
- `GET /auth/github/callback` - Handles OAuth callback, creates session, redirects to admin UI
- `GET /auth/me` - Returns current user info (for future use)

### Database Schema Changes

**AdminSession table:**
- Added `github_id` (int, nullable)
- Added `github_login` (string, nullable)
- Added `github_email` (string, nullable)
- Added `github_avatar_url` (string, nullable)
- Added `auth_method` (string, default="password")

**Account table (for future auto-provisioning):**
- Added `github_id` (int, nullable, indexed)
- Added `github_login` (string, nullable)
- Added `github_org` (string, nullable)
- Added `linked_at` (datetime, nullable)

### CSRF Protection

OAuth state tokens are generated and verified to prevent CSRF attacks:
- State tokens are 32-byte URL-safe random strings
- Stored in memory with 10-minute expiration
- One-time use (consumed on verification)

### Frontend Changes

- Admin login page (`/admin`) now shows GitHub OAuth button
- OAuth callback extracts token from URL query param and stores in sessionStorage
- Password login remains available as a legacy fallback for non-production/self-hosted use

## Security Considerations

### OAuth Scope

Minimal scope requested:
- `read:user` - Read user profile
- `user:email` - Read verified email addresses

This is sufficient for authentication without requesting unnecessary permissions.

### Token Storage

- OAuth access tokens are NOT stored (only used during callback to fetch user info)
- Session tokens are bcrypt-hashed in the database
- Session tokens are stored in sessionStorage (not localStorage) for better security

### Rate Limiting

GitHub OAuth has rate limits:
- 5000 requests/hour for authenticated requests
- Consider caching user info for 1 hour after successful OAuth

## Future Enhancements

### Phase 2: GitHub App for CI/CD

Replace unauthenticated publish/deploy endpoints with GitHub App installation tokens:
- Install GitHub App in your repository
- Use `GITHUB_TOKEN` in GitHub Actions workflows
- Auto-rotating tokens with repository-scoped access

### Phase 3: Account Auto-Provisioning

Automatically create accounts for GitHub org members:
- Check org membership on first OAuth login
- Link existing accounts to GitHub users
- Support team-based permissions (e.g., @easyenclave/admins)

## Troubleshooting

### "GitHub OAuth not configured"

Ensure `GITHUB_OAUTH_CLIENT_ID` and `GITHUB_OAUTH_CLIENT_SECRET` are set in your environment.

### "Invalid or expired state token"

The OAuth state token expired (10 minutes) or was already used. Start the OAuth flow again.

### "GitHub authentication failed"

Check the server logs for detailed error messages. Common causes:
- Invalid client ID/secret
- Incorrect redirect URI in GitHub OAuth App settings
- Network connectivity issues

### Callback URL Mismatch

Ensure the callback URL in your GitHub OAuth App matches the `GITHUB_OAUTH_REDIRECT_URI` environment variable exactly.

## Testing

Run the OAuth tests:
```bash
python3 -m pytest tests/test_oauth.py -v
```

For integration testing, set up a test GitHub OAuth App with a localhost callback URL.

## Backward Compatibility

- Password-based admin login remains fully functional
- Existing API key authentication is unchanged
- No breaking changes to existing endpoints
- GitHub OAuth fields are nullable (existing sessions still work)

## Migration Path

1. **Set up GitHub OAuth** (this phase)
2. **Encourage admins to switch** to GitHub OAuth
3. **Use password auth only as legacy fallback** for self-hosted/air-gapped non-production deployments
4. **Optional**: Deprecate password auth in favor of OAuth-only in the future
