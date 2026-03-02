# GitHub OAuth for Admin Access

EasyEnclave supports GitHub OAuth for control-plane admin authentication.

## Required environment variables

```bash
GITHUB_OAUTH_CLIENT_ID=...
GITHUB_OAUTH_CLIENT_SECRET=...
GITHUB_OAUTH_REDIRECT_URI=https://app.easyenclave.com/auth/github/callback
```

## Endpoints

- `GET /auth/methods`
- `GET /auth/github`
- `GET /auth/github/callback`
- `GET /auth/me`

## Behavior

- OAuth is enabled only when all three environment variables are set.
- `/auth/methods` reports available methods (`password`, `github`).
- Sessions are stored in `admin_sessions` and track auth method + GitHub login.

## Production recommendation

- Keep GitHub OAuth enabled for production admin access.
- Restrict admin visibility/actions to approved GitHub logins via policy/config.

## Implementation references

- Route handlers: `crates/ee-cp/src/routes/auth.rs`
- Admin root UI: `crates/ee-cp/src/routes/ui_root.html`
- Session store: `crates/ee-cp/src/stores/session.rs`

## Validation

```bash
cargo test -p ee-cp auth
```
