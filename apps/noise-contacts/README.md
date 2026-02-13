# Noise Contacts

`noise-contacts` is a real contacts lookup example that uses a Noise session for encrypted application traffic.

## What it demonstrates

- Noise XX handshake (`Noise_XX_25519_ChaChaPoly_BLAKE2s`)
- Binding attestation claims to Noise identity:
  - client claims `noise_static_pubkey` in attestation payload
  - server compares that to the remote static key proven by the Noise handshake
- Optional policy checks for attestation metadata:
  - `TRUSTED_MRTDS`
  - `TRUSTED_PEERS_JSON`

## Demo security notes

This example intentionally focuses on integration points and readability.
In production, attestation claims should be verified cryptographically against Intel TA / control-plane attestation APIs.

## API

- `GET /health`
- `POST /noise/handshake/init`
- `POST /noise/handshake/finalize`
- `POST /noise/request`

## Env vars

- `NOISE_ATTESTATION_MODE`: `strict` | `warn` | `disabled` (default: `warn`)
- `NOISE_STATIC_PRIVATE_KEY`: responder static private key (hex, 32 bytes)
- `TRUSTED_MRTDS`: comma-separated trusted MRTDs
- `TRUSTED_PEERS_JSON`: optional per-peer policy
