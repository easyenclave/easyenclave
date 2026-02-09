# Nonce Challenge Implementation

## Overview

EasyEnclave implements a nonce challenge flow to prevent replay attacks during agent registration. This ensures that captured attestation quotes cannot be reused by attackers to register malicious agents.

## How It Works

### 1. Agent Requests Challenge

Before generating its attestation quote, the agent requests a one-time-use nonce from the control plane:

```bash
GET /api/v1/agents/challenge?vm_name=tdx-agent-001
```

Response:
```json
{
  "nonce": "a1b2c3d4...",
  "ttl_seconds": 300,
  "issued_at": "2026-02-09T12:34:56Z"
}
```

### 2. Agent Includes Nonce in TDX Quote

The agent converts the hex nonce to bytes and includes it in the TDX quote's **REPORTDATA** field:

```python
nonce_bytes = bytes.fromhex(nonce)
quote_b64 = generate_tdx_quote(user_data=nonce_bytes)
```

The REPORTDATA field is a 64-byte field in the TDX quote that can hold arbitrary data. The nonce is left-padded with zeros.

### 3. Agent Submits Quote to Intel TA

The agent sends the TDX quote to Intel Trust Authority for verification:

```python
ita_response = call_intel_trust_authority(quote_b64, intel_api_key, intel_api_url)
intel_ta_token = ita_response.get("token")
```

Intel TA returns a signed JWT containing the quote measurements, including the nonce in the **attester_held_data** claim.

### 4. Agent Registers with Control Plane

The agent submits the Intel TA token during registration:

```bash
POST /api/v1/agents/register
{
  "attestation": {
    "tdx": {
      "quote_b64": "...",
      "intel_ta_token": "eyJ..."
    }
  },
  "vm_name": "tdx-agent-001",
  "version": "1.0.0"
}
```

### 5. Control Plane Verifies Nonce

The control plane:
1. Extracts the `attester_held_data` claim from the Intel TA JWT
2. Looks up the expected nonce for this vm_name
3. Verifies the nonce matches and hasn't expired
4. Marks the nonce as consumed (one-time use)

If verification succeeds, the agent is registered. If it fails, registration is rejected with HTTP 403.

## Security Properties

### Replay Attack Prevention

An attacker who captures an old attestation quote cannot reuse it because:
- Each nonce is unique and tied to a specific vm_name
- Nonces expire after 5 minutes (configurable)
- Nonces are consumed after one use
- Control plane rejects quotes with missing or invalid nonces (in required mode)

### Freshness Guarantee

The nonce challenge provides a freshness guarantee:
- Nonce timestamp proves the quote was generated recently
- Short TTL prevents long-term quote harvesting
- Control plane can enforce time-bound attestation

### Cryptographic Binding

The nonce is cryptographically bound to the TDX quote:
- Intel TA signs the entire quote including REPORTDATA
- Tampering with the nonce invalidates the signature
- Control plane verifies Intel TA signature before checking nonce

## Enforcement Modes

The control plane supports three enforcement modes via `NONCE_ENFORCEMENT_MODE`:

### `required` (default)
- Nonce is mandatory for registration
- Missing or invalid nonce → HTTP 400/403
- Provides maximum security against replay attacks
- Recommended for production deployments

### `optional`
- Nonce is verified if present
- Missing nonce logs warning but allows registration
- Useful for gradual rollout
- Allows mixed agent versions during migration

### `disabled`
- No nonce verification performed
- Backward compatible with old agents
- Not recommended for production

## Configuration

### Control Plane

```bash
# Enforcement mode
NONCE_ENFORCEMENT_MODE=required  # required | optional | disabled

# Nonce expiration time (seconds)
NONCE_TTL_SECONDS=300  # Default: 5 minutes

# Nonce length (hex characters)
NONCE_LENGTH=32  # Default: 32 chars = 128 bits entropy
```

### Agent

No configuration required - agents automatically request challenges when registering with a control plane that supports them.

## Implementation Details

### Control Plane

**File:** `app/nonce.py`
- `issue_challenge(vm_name)` - Generate and store nonce
- `verify_nonce(vm_name, nonce)` - Verify and consume nonce
- `cleanup_expired_nonces()` - Background cleanup (runs every 60s)

**File:** `app/main.py`
- `GET /api/v1/agents/challenge` - Issue challenge endpoint
- `POST /api/v1/agents/register` - Verify nonce during registration

### Agent

**File:** `infra/launcher/launcher.py`
- `request_nonce_challenge(vm_name)` - Request challenge from control plane
- `generate_initial_attestation(config, vm_name)` - Include nonce in quote
- `generate_tdx_quote(user_data)` - Generate quote with nonce in REPORTDATA

## Monitoring

### Control Plane Logs

```bash
# Nonce issued
INFO: Issued nonce challenge for tdx-agent-001: a1b2c3d4...

# Nonce verified
INFO: Nonce verified for tdx-agent-001

# Nonce expired
WARNING: Nonce expired for tdx-agent-001 (optional mode, allowing)

# Cleanup
INFO: Cleaned 3 expired nonces
```

### Agent Logs

```bash
# Challenge requested
INFO: Requesting nonce challenge from control plane...
INFO: Received nonce challenge (TTL: 300s): a1b2c3d4...

# Nonce included in quote
INFO: Including nonce in TDX quote: a1b2c3d4...
INFO: Nonce verified in TDX quote REPORTDATA

# Registration
INFO: Registered as agent: agent-abc123
```

## Testing

### Unit Tests

```bash
# Test nonce module
python3 -m pytest tests/test_nonce_challenge.py -v

# 14 tests covering:
# - Nonce generation
# - Challenge issuance
# - Verification (success, mismatch, missing, expired)
# - One-time use
# - Enforcement modes (required, optional, disabled)
# - Cleanup
```

### Integration Test

```bash
# Test full flow with mock control plane
python3 -m pytest tests/test_agent_registration.py -v -k nonce
```

## Troubleshooting

### Agent Registration Fails with "Nonce required"

**Symptom:** HTTP 400 error during registration

**Cause:** Control plane is in `required` mode but agent didn't request challenge

**Solution:**
1. Verify agent is using updated launcher code
2. Check agent logs for "Requesting nonce challenge"
3. Verify control plane is reachable from agent

### Agent Registration Fails with "Nonce verification failed"

**Symptom:** HTTP 403 error during registration

**Causes:**
1. Nonce expired (took >5 minutes to generate quote)
2. Nonce mismatch (wrong nonce or corrupted)
3. Nonce already used (duplicate registration attempt)

**Solutions:**
1. Increase `NONCE_TTL_SECONDS` if quote generation is slow
2. Check for network issues or clock skew
3. Ensure agent requests fresh challenge for each registration

### Nonce Not Found in REPORTDATA

**Symptom:** Warning in agent logs: "Nonce not found in REPORTDATA"

**Cause:** Nonce conversion or quote generation failed

**Solution:**
1. Verify nonce is valid hex string
2. Check TDX kernel interface is working
3. Review `generate_tdx_quote()` implementation

## Future Enhancements

### 1. Persistent Nonce Store
Currently nonces are in-memory only. For high-availability deployments:
- Use Redis or similar shared store
- Enables multi-instance control plane without nonce conflicts

### 2. Rate Limiting
Prevent nonce flooding attacks:
- Limit challenges per vm_name per time window
- Track failed verification attempts

### 3. Nonce Rotation
For long-running agents:
- Periodic nonce refresh during attestation refresh
- Extends freshness guarantee beyond initial registration

### 4. Metrics
Expose nonce statistics:
- Challenge requests per minute
- Verification success/failure rates
- Average time from challenge to registration
- Nonce store size and cleanup frequency
