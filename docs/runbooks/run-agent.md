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

Optional: launch an `llm` agent with direct GPU passthrough (example H100 at `0000:0d:00.0`):

```bash
python3 infra/tdx_cli.py vm new \
  --size llm \
  --hostdev-pci 0000:0d:00.0 \
  --easyenclave-url "https://app.easyenclave.com" \
  --intel-api-key "$ITA_API_KEY" \
  --cloud-provider baremetal \
  --availability-zone site-a \
  --wait
```

Notes:
- The PCI device must already be bound to `vfio-pci`.
- Use `lspci -nnD | rg -i nvidia` to find the GPU BDF.

4. Verify registration.

```bash
python3 infra/tdx_cli.py vm list
curl -s https://app.easyenclave.com/api/v1/agents | jq '.agents[] | {agent_id,vm_name,node_size,datacenter,status,verified,health_status}'
```

## Common Failures

- `Nonce required`: CP nonce policy is strict and challenge flow failed; retry and inspect agent logs.
- `MRTD not in trusted list`: control plane trust set does not include this guest baseline.
- Missing TDX quote path (`/sys/kernel/config/tsm/report`): you are not running in a TDX guest.
- `Quote too short` / `MRTD: unknown` / Intel TA `400` on `/appraisal/v1/attest`:
  host QGS is running but cannot read provisioning device permissions correctly.

  Typical host-side signal:

  ```bash
  sudo journalctl -u qgsd.service -n 80 --no-pager
  # ... Enclave not authorized to run ...
  # ... SGXError:4004 ...
  ```

  Validate host prerequisites:

  ```bash
  systemctl is-active qgsd.service tdx-qgs-unix-bridge.service
  ss -A vsock -lnp | rg 4050
  ls -l /dev/sgx_provision /dev/sgx_enclave
  ```

  If `/dev/sgx_provision` is `root:root` (instead of an SGX/QGS-readable group), apply
  a persistent udev override and restart QGS:

  ```bash
  cat <<'EOF' | sudo tee /etc/udev/rules.d/95-sgx-provision-qgsd.rules >/dev/null
  SUBSYSTEM=="misc",KERNEL=="sgx_provision",GROUP="qgsd",MODE="0660"
  SUBSYSTEM=="misc",KERNEL=="provision",GROUP="qgsd",MODE="0660"
  EOF
  sudo udevadm control --reload-rules
  sudo udevadm trigger --name-match=sgx_provision --action=change
  sudo systemctl restart qgsd.service
  ```

  Re-check measurement before agent registration:

  ```bash
  python3 infra/tdx_cli.py vm measure --json
  ```
