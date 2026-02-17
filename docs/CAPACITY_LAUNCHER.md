# Capacity Launcher Worker

EasyEnclave now queues capacity launch orders in the control plane.
Launchers consume those orders using a **launcher API key**.

## Why

- Deployment and billing request capacity through CP APIs.
- CP creates launch orders for shortfall (`tiny`/`standard`/`llm`).
- Launcher workers claim and fulfill orders.
- This works for local bare-metal TDX and GCP without putting cloud logic in GitHub Actions.

## 1) Create a launcher account

```bash
curl -sS -X POST https://app.easyenclave.com/api/v1/accounts \
  -H 'Content-Type: application/json' \
  -d '{"name":"launcher-github-runner","account_type":"launcher"}'
```

Save the returned `api_key` (only shown once).

## 2) Run the worker (bare metal)

```bash
LAUNCHER_API_KEY='ee_live_...' \
INTEL_API_KEY='...' \
python3 scripts/capacity_launcher_worker.py \
  --cp-url https://app.easyenclave.com \
  --providers baremetal
```

The worker will:
1. `POST /api/v1/launchers/capacity/orders/claim`
2. Launch local TDX VM via `infra/tdx_cli.py vm new ... --wait`
3. `POST /api/v1/launchers/capacity/orders/{order_id}` with `fulfilled`

## 3) Optional GCP support

```bash
LAUNCHER_API_KEY='ee_live_...' \
INTEL_API_KEY='...' \
LAUNCHER_GCP_PROJECT='easyenclave' \
python3 scripts/capacity_launcher_worker.py \
  --cp-url https://app.easyenclave.com \
  --providers gcp
```

For GCP, the worker shells out to `scripts/cloud_provisioner.py provision --provider gcp ...`.

Optional machine type overrides:

- `LAUNCHER_GCP_MACHINE_TYPE_DEFAULT`
- `LAUNCHER_GCP_MACHINE_TYPE_TINY`
- `LAUNCHER_GCP_MACHINE_TYPE_STANDARD`
- `LAUNCHER_GCP_MACHINE_TYPE_LLM`

## Helpful flags

- `--one-shot`: claim/process at most one order
- `--max-orders N`: process N orders then exit
- `--datacenter gcp:us-central1-a`: claim filter
- `--node-size tiny`: claim filter

## API summary

- Admin list launch orders:
  - `GET /api/v1/admin/agents/capacity/orders`
- Launcher claim next:
  - `POST /api/v1/launchers/capacity/orders/claim`
- Launcher update status:
  - `POST /api/v1/launchers/capacity/orders/{order_id}`
