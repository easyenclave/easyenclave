# Nonce Challenge Model

EasyEnclave uses a one-time nonce challenge to prevent replay during agent registration.

## Registration flow

1. Agent requests a challenge:

```http
GET /api/v1/agents/challenge
```

2. Control plane returns:

```json
{
  "nonce": "...",
  "expires_in_seconds": 300
}
```

3. Agent includes nonce in attestation flow and calls:

```http
POST /api/v1/agents/register
```

4. Control plane verifies nonce is present, unexpired, and unused.

If verification fails, registration is rejected.

## Security properties

- Single use: consumed nonces cannot be reused.
- TTL-bound: stale nonces are rejected.
- Fail-closed: missing/invalid nonce causes registration failure.

## Implementation references

- Route handlers: `crates/ee-cp/src/routes/agents.rs`
- Nonce service: `crates/ee-cp/src/services/nonce.rs`
- Config mapping: `crates/ee-cp/src/stores/setting.rs`

## Configuration

- `CP_NONCE_ENFORCEMENT_MODE` (`required` by default)

## Validation

```bash
cargo test -p ee-cp nonce
cargo test -p ee-cp register
```
