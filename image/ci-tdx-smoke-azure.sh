#!/bin/bash
# Azure real-TDX integration test.
#
# Spins up an EPHEMERAL Azure TDX CVM from the azure target's VHD,
# asserts the enclave boots + attests + serves a workload, tears it
# down.
#
# Flow:
#   1. Create an empty managed disk marked for-upload, with ConfidentialVM
#      security type (TDX requires VMGuestStateOnly encryption).
#   2. azcopy the VHD into that disk's write-SAS URL.
#   3. Revoke disk upload access.
#   4. Create a TDX-capable VM, attaching the disk as OS disk, with
#      customData = base64(ee-config lines). IMDS exposes customData to
#      the azure vendor stage inside the VM.
#   5. Poll Azure boot diagnostics serial log for the assertion patterns.
#   6. HTTP 200 check against the VM's public IP.
#   7. Delete VM + disk + NIC + PIP + NSG.
#
# Required env:
#   AZURE_RESOURCE_GROUP    pre-existing resource group for these resources
#   SHA12                   commit sha12 for naming
#
# Assumes: already authenticated via azure/login action.
#
# NOTE: several Azure CLI specifics in this script are best-effort and
# may need tweaking on first real run against the target subscription:
#   - `--sku Standard_LRS` on the ConfidentialVM disk — Premium_LRS /
#     StandardSSD_LRS may be required depending on region + subscription.
#   - `--for-upload true` + `--security-type ConfidentialVM_...` — these
#     may be mutually exclusive; if so, the path is Shared Image Gallery
#     with a ConfidentialVM-capable image definition + image version.
#   - `--attach-os-disk` + `--custom-data`: custom-data is provisioned
#     by the Linux VM agent; with an attached pre-existing OS disk the
#     agent may not run provisioning, breaking customData→IMDS. If so,
#     move config delivery to a data disk (iso9660 with /agent.env,
#     matching the qemu vendor stage).
#   - `--boot-diagnostics-storage ""` = managed; some CLI versions want
#     the flag omitted + enabled post-create.
# The surrounding workflow runs this with `continue-on-error: true`
# (for matrix.target=='azure') until first green run, so iteration
# doesn't block gcp / local-tdx releases.
set -euo pipefail

: "${AZURE_RESOURCE_GROUP:?}"
: "${SHA12:?}"

REGION="${AZURE_REGION:-eastus2}"
VM_SIZE="${AZURE_VM_SIZE:-Standard_DC2es_v5}"
VHD="image/output/azure/easyenclave-${SHA12}-azure.vhd"
[ -f "$VHD" ] || { echo "missing $VHD" >&2; exit 2; }

STAMP=$(date +%s)
PREFIX="ee-smoke-${SHA12}-${STAMP}"
DISK_NAME="${PREFIX}-disk"
VM_NAME="${PREFIX}-vm"
NIC_NAME="${PREFIX}-nic"
PIP_NAME="${PREFIX}-pip"
NSG_NAME="${PREFIX}-nsg"
VNET_NAME="${PREFIX}-vnet"

cleanup() {
    set +e
    echo "smoke:azure: cleanup"
    # Order matters: VM first (frees the NIC + disk), then NIC/disk, then network.
    az vm delete --resource-group "$AZURE_RESOURCE_GROUP" --name "$VM_NAME" --yes --no-wait 2>/dev/null || true
    sleep 10
    az disk delete --resource-group "$AZURE_RESOURCE_GROUP" --name "$DISK_NAME" --yes --no-wait 2>/dev/null || true
    az network nic delete --resource-group "$AZURE_RESOURCE_GROUP" --name "$NIC_NAME" --no-wait 2>/dev/null || true
    az network public-ip delete --resource-group "$AZURE_RESOURCE_GROUP" --name "$PIP_NAME" --no-wait 2>/dev/null || true
    az network nsg delete --resource-group "$AZURE_RESOURCE_GROUP" --name "$NSG_NAME" --no-wait 2>/dev/null || true
    az network vnet delete --resource-group "$AZURE_RESOURCE_GROUP" --name "$VNET_NAME" --no-wait 2>/dev/null || true
}
trap cleanup EXIT

echo "smoke:azure: upload VHD to managed disk $DISK_NAME"
SIZE=$(stat -c %s "$VHD")

# Confidential-VM-supported OS disk. `VMGuestStateOnlyEncryptedWithPlatformKey`
# is the TDX-compatible mode (no guest-state encryption of the disk itself;
# the memory is what's encrypted at runtime by TDX).
az disk create \
    --resource-group "$AZURE_RESOURCE_GROUP" --name "$DISK_NAME" \
    --location "$REGION" \
    --hyper-v-generation V2 \
    --security-type ConfidentialVM_VMGuestStateOnlyEncryptedWithPlatformKey \
    --os-type Linux \
    --for-upload true --upload-size-bytes "$SIZE" \
    --sku Standard_LRS >/dev/null

SAS_URI=$(az disk grant-access \
    --resource-group "$AZURE_RESOURCE_GROUP" --name "$DISK_NAME" \
    --duration-in-seconds 3600 --access-level Write \
    --query accessSas -o tsv)

# azcopy is present on Azure CLI installs via `az storage blob upload`, but
# for raw VHD → disk blob the supported tool is AzCopy. The workflow installs
# it before invoking this script.
azcopy copy "$VHD" "$SAS_URI" --blob-type PageBlob

az disk revoke-access --resource-group "$AZURE_RESOURCE_GROUP" --name "$DISK_NAME" >/dev/null

# Networking scaffolding. NSG opens port 80 for the HTTP workload check.
az network vnet create \
    --resource-group "$AZURE_RESOURCE_GROUP" --name "$VNET_NAME" \
    --location "$REGION" \
    --subnet-name default --subnet-prefix 10.0.0.0/24 \
    --address-prefix 10.0.0.0/16 >/dev/null
az network nsg create \
    --resource-group "$AZURE_RESOURCE_GROUP" --name "$NSG_NAME" \
    --location "$REGION" >/dev/null
az network nsg rule create \
    --resource-group "$AZURE_RESOURCE_GROUP" --nsg-name "$NSG_NAME" \
    --name allow-http --priority 100 --protocol Tcp \
    --destination-port-ranges 80 --access Allow >/dev/null
az network public-ip create \
    --resource-group "$AZURE_RESOURCE_GROUP" --name "$PIP_NAME" \
    --location "$REGION" --sku Basic >/dev/null
az network nic create \
    --resource-group "$AZURE_RESOURCE_GROUP" --name "$NIC_NAME" \
    --location "$REGION" \
    --vnet-name "$VNET_NAME" --subnet default \
    --public-ip-address "$PIP_NAME" --network-security-group "$NSG_NAME" >/dev/null

# customData: the azure vendor stage reads IMDS customData and base64-decodes.
# Using KEY=VALUE here; the _lib.sh ee_append_config helper also accepts the
# legacy JSON form (gcp test exercises the JSON path).
cat > /tmp/ee-config.env <<'EECONF'
EE_OWNER=ci-smoke-azure
EE_BOOT_WORKLOADS=[{"cmd":["sh","-c","echo ok > /tmp/index.html"],"app_name":"seed"},{"cmd":["busybox","httpd","-f","-p","80","-h","/tmp"],"app_name":"http"}]
EECONF

echo "smoke:azure: create TDX VM $VM_NAME ($VM_SIZE in $REGION)"
# --attach-os-disk: boot directly from the uploaded disk.
# --security-type ConfidentialVM + vTPM + secure boot: TDX CVM requirements.
# --boot-diagnostics-storage "" : managed (Azure-provided) storage for the
#   serial log. Avoids the need to pre-create a storage account.
az vm create \
    --resource-group "$AZURE_RESOURCE_GROUP" --name "$VM_NAME" \
    --location "$REGION" \
    --size "$VM_SIZE" \
    --security-type ConfidentialVM \
    --os-disk-security-encryption-type VMGuestStateOnly \
    --enable-vtpm true --enable-secure-boot true \
    --attach-os-disk "$DISK_NAME" --os-type Linux \
    --nics "$NIC_NAME" \
    --boot-diagnostics-storage "" \
    --custom-data /tmp/ee-config.env >/dev/null

# Assertions — same shape as gcp, different label. metadata_merged
# becomes vendor:azure: since the azure vendor stage is the one that
# fetches customData and merges.
CHECKS=(
    "pid1|easyenclave: running as PID 1"
    "vendor_merged|vendor:azure: merged .* config into"
    "attestation_tdx|attestation backend: tdx"
    "listening|easyenclave: listening on"
    "deployment_running|deployment .* running"
)
FATAL_PATTERNS="FATAL|Kernel panic|switch_root: can|Invalid ELF header"

declare -A PASSED
ALL_DONE=false
for i in $(seq 1 36); do
    # boot-diagnostics-log returns the full serial each call. Stream the
    # whole thing every 10s — simpler than diffing, slightly noisier output.
    out=$(az vm boot-diagnostics get-boot-log \
        --resource-group "$AZURE_RESOURCE_GROUP" --name "$VM_NAME" 2>/dev/null || true)
    if [ -n "$out" ] && [ "$i" -eq 1 -o $((i % 3)) -eq 0 ]; then
        echo "$out" | tail -n 60 | sed 's/^/[serial] /'
    fi
    if echo "$out" | grep -qE "$FATAL_PATTERNS"; then
        echo "::error::smoke:azure: fatal pattern in serial"
        break
    fi
    for check in "${CHECKS[@]}"; do
        IFS="|" read -r name pattern <<< "$check"
        [ -n "${PASSED[$name]:-}" ] && continue
        if echo "$out" | grep -qE "$pattern"; then
            PASSED[$name]=1
            echo "smoke:azure:   ✓ $name"
        fi
    done
    ALL_DONE=true
    for check in "${CHECKS[@]}"; do
        IFS="|" read -r name _pat <<< "$check"
        [ -z "${PASSED[$name]:-}" ] && ALL_DONE=false && break
    done
    $ALL_DONE && break
    echo "smoke:azure: waiting... ($i/36)"
    sleep 10
done

HTTP_OK=false
if $ALL_DONE; then
    VM_IP=$(az network public-ip show \
        --resource-group "$AZURE_RESOURCE_GROUP" --name "$PIP_NAME" \
        --query ipAddress -o tsv)
    echo "smoke:azure: probing http://$VM_IP:80/"
    for i in $(seq 1 12); do
        code=$(curl -sS -o /dev/null -w '%{http_code}' \
            --connect-timeout 5 "http://$VM_IP:80/" 2>/dev/null || echo 000)
        if [ "$code" = "200" ]; then
            echo "smoke:azure:   ✓ workload_http (200)"
            HTTP_OK=true
            break
        fi
        echo "smoke:azure: http $code, retrying... ($i/12)"
        sleep 5
    done
fi

echo ""
echo "smoke:azure: === summary ==="
PASS=0; TOTAL=0
for check in "${CHECKS[@]}"; do
    IFS="|" read -r name _pat <<< "$check"
    TOTAL=$((TOTAL + 1))
    if [ -n "${PASSED[$name]:-}" ]; then
        echo "smoke:azure:   ✓ $name"; PASS=$((PASS + 1))
    else
        echo "smoke:azure:   ✗ $name"
    fi
done
TOTAL=$((TOTAL + 1))
if $HTTP_OK; then
    echo "smoke:azure:   ✓ workload_http"; PASS=$((PASS + 1))
else
    echo "smoke:azure:   ✗ workload_http"
fi
echo "smoke:azure: $PASS/$TOTAL passed"

if $ALL_DONE && $HTTP_OK; then
    exit 0
fi
echo "::error::smoke:azure failed ($PASS/$TOTAL)"
exit 1
