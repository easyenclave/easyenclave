# Run an Agent from a Blank TDX Host

Primary directories: `infra/`, `app/`

## Goal

Boot a TDX guest agent on your host and register it with an existing control plane.

## Prerequisites

- TDX-capable host (BIOS + kernel/KVM configured for TDX).
- Intel Trust Authority API key.
- Reachable control plane URL (for example `https://app.easyenclave.com`).

## Why the agent needs `ITA_API_KEY`

`ITA_API_KEY` is used by the launcher inside the guest to call Intel Trust
Authority and mint an attestation token from the TDX quote.

Registration flow:

1. Agent requests nonce challenge from CP.
2. Agent generates TDX quote.
3. Agent calls Intel Trust Authority using `ITA_API_KEY` and gets a signed token.
4. Agent sends token to CP at `/api/v1/agents/register`.
5. CP verifies Intel signature + nonce + trusted MRTD/RTMR policy.

Important:

- The key is required for the agent to obtain Intel-signed attestation.
- The key does not need to match the control plane's key.
- A different key proves quote validity, not ownership identity with CP.
- Without the key, registration fails because no valid Intel TA token can be produced.

## Steps

1. Clone repo and pin to the intended release/commit.

```bash
git clone https://github.com/easyenclave/easyenclave.git
cd easyenclave
git checkout v0.1.0
```

2. Build the verity image used for the guest.

```bash
cd infra/image
nix develop --command make build
cd ../..
```

3. Boot an agent VM from this host using `tdx_cli.py`.

```bash
export ITA_API_KEY="<intel-ta-api-key>"
python3 infra/tdx_cli.py vm new \
  --size tiny \
  --easyenclave-url "https://app.easyenclave.com" \
  --intel-api-key "$ITA_API_KEY" \
  --cloud-provider baremetal \
  --availability-zone site-a \
  --wait
```

4. Verify registration.

```bash
python3 infra/tdx_cli.py vm list
curl -s https://app.easyenclave.com/api/v1/agents | jq '.agents[] | {agent_id,vm_name,node_size,datacenter,status,verified,health_status}'
```

## Common Failures

- `Nonce required`: CP nonce policy is strict and challenge flow failed; retry and inspect agent logs.
- `MRTD not in trusted list`: control plane trust set does not include this guest baseline.
- Missing TDX quote path (`/sys/kernel/config/tsm/report`): you are not running in a TDX guest.
