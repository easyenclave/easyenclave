# Run an Agent from a Blank TDX Host

Primary directories: `infra/`, `app/`

## Goal

Boot a TDX guest agent on your host and register it with an existing control plane.

## Prerequisites

- TDX-capable host (BIOS + kernel/KVM configured for TDX).
- Intel Trust Authority API key.
- Reachable control plane URL (for example `https://app.easyenclave.com`).

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
