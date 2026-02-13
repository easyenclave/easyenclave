# Noise Contacts Example

Demonstrates a real contacts flow over an encrypted Noise session with attestation-binding checks.

## What this tests

1. Noise XX handshake (`Noise_XX_25519_ChaChaPoly_BLAKE2s`)
2. Binding attestation claims to the Noise static key (`noise_static_pubkey` must match handshake identity)
3. Encrypted contact operations (`register`, `lookup`) over the established Noise transport

## Run locally

```bash
python3 examples/noise-contacts/test.py
```

Required env vars:
- `SERVICE_URL` (for deployed service URL)

Optional env vars:
- `TEST_MRTD` (attestation claim value used by the demo client)
