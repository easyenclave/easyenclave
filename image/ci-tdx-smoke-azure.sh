#!/bin/bash
# Azure real-TDX integration test.
#
# Spins up an EPHEMERAL Azure TDX CVM from the azure target's VHD,
# asserts the enclave boots + attests + serves a workload, tears it
# down.
#
# Flow:
#   1. Bootstrap (idempotent): a Shared Image Gallery + image-definition
#      with features=SecurityType=ConfidentialVmSupported. Both are
#      created on first run, reused thereafter.
#   2. Upload VHD to a Standard (non-CVM) managed disk via azcopy + a
#      write-SAS URL. The CVM security type is rejected on Upload
#      CreateOption, so we stage through plain-disk → SIG image version
#      instead of trying to create a CVM disk directly.
#   3. Create an image-version in the SIG from the uploaded disk.
#   4. Create a TDX CVM from the image-version. Provisioning agent runs
#      from scratch so customData lands in IMDS correctly.
#   5. Poll Azure boot diagnostics serial log for assertion patterns.
#   6. HTTP 200 check against the VM's public IP.
#   7. Delete VM + image version + disk + NIC + PIP + NSG + VNet.
#
# Required env:
#   AZURE_RESOURCE_GROUP    pre-existing resource group for these resources
#   SHA12                   commit sha12 for naming
#
# Optional env (override defaults):
#   AZURE_REGION            default eastus2
#   AZURE_VM_SIZE           default Standard_DC2es_v5 (TDX SKU)
#   AZURE_GALLERY           default easyenclaveGallery
#   AZURE_IMG_DEF           default easyenclave-x64
#
# Assumes: already authenticated via azure/login action. The surrounding
# workflow runs this with `continue-on-error: true` (for matrix.target ==
# 'azure') as a belt until first green run.
set -euo pipefail

: "${AZURE_RESOURCE_GROUP:?}"
: "${SHA12:?}"

# Default to westus3 + DC2es_v6 (Intel TDX v6). The DCEDV5/DCEV5
# families showed "quota approved" in eastus2/centralus but the SKUs
# never actually shipped in those regions (az vm list-skus returns
# zero matches). DC*_v6 is the GA Intel TDX SKU line, available in
# westus3 with 10 vCPUs of approved quota on this subscription.
# Override via env if a different region has quota.
REGION="${AZURE_REGION:-westus3}"
VM_SIZE="${AZURE_VM_SIZE:-Standard_DC2es_v6}"
VHD="image/output/azure/easyenclave-${SHA12}-azure.vhd"
[ -f "$VHD" ] || { echo "missing $VHD" >&2; exit 2; }

STAMP=$(date +%s)
PREFIX="ee-smoke-${SHA12}-${STAMP}"
VM_NAME="${PREFIX}-vm"
NIC_NAME="${PREFIX}-nic"
PIP_NAME="${PREFIX}-pip"
NSG_NAME="${PREFIX}-nsg"
VNET_NAME="${PREFIX}-vnet"

# Shared Image Gallery state. The gallery + image-definition are
# idempotent (created if missing, reused otherwise); only the image
# VERSION is per-run and torn down after the test.
GALLERY_NAME="${AZURE_GALLERY:-easyenclaveGallery}"
IMG_DEF_NAME="${AZURE_IMG_DEF:-easyenclave-x64}"
IMG_VERSION="0.0.$(date +%s)"

# Storage account for staging the VHD as a page blob. ConfidentialVmSupported
# SIG images reject managed-disk sources ("Currently only Vhd Blob, User
# Image and Gallery Image Version sources are supported"), so we bypass the
# managed-disk intermediate entirely and go blob → image-version.
# Account names must be 3-24 chars, lowercase alphanumeric only, globally
# unique. Derive from RG + region so runs in different regions don't
# collide on a pinned-region account (storage accounts are single-region).
STORAGE_ACCT="${AZURE_STORAGE_ACCT:-eeci$(echo -n "${AZURE_RESOURCE_GROUP}-${REGION}" | sha256sum | cut -c1-16)}"
STORAGE_CONTAINER="${AZURE_STORAGE_CONTAINER:-vhds}"
BLOB_NAME="${PREFIX}.vhd"

cleanup() {
    set +e
    echo "smoke:azure: cleanup"
    az vm delete --resource-group "$AZURE_RESOURCE_GROUP" --name "$VM_NAME" --yes --no-wait 2>/dev/null || true
    sleep 10
    az sig image-version delete --resource-group "$AZURE_RESOURCE_GROUP" \
        --gallery-name "$GALLERY_NAME" --gallery-image-definition "$IMG_DEF_NAME" \
        --gallery-image-version "$IMG_VERSION" --no-wait 2>/dev/null || true
    # ACCT_KEY may be unset if we exited before fetching it; fetch again
    # (cheap: az handles the no-op case), fall back to nothing if the
    # account itself is gone.
    CLEANUP_KEY=$(az storage account keys list \
        --resource-group "$AZURE_RESOURCE_GROUP" --account-name "$STORAGE_ACCT" \
        --query '[0].value' -o tsv 2>/dev/null || true)
    if [ -n "$CLEANUP_KEY" ]; then
        az storage blob delete --account-name "$STORAGE_ACCT" --container-name "$STORAGE_CONTAINER" \
            --name "$BLOB_NAME" --account-key "$CLEANUP_KEY" 2>/dev/null || true
    fi
    az network nic delete --resource-group "$AZURE_RESOURCE_GROUP" --name "$NIC_NAME" --no-wait 2>/dev/null || true
    az network public-ip delete --resource-group "$AZURE_RESOURCE_GROUP" --name "$PIP_NAME" --no-wait 2>/dev/null || true
    az network nsg delete --resource-group "$AZURE_RESOURCE_GROUP" --name "$NSG_NAME" --no-wait 2>/dev/null || true
    az network vnet delete --resource-group "$AZURE_RESOURCE_GROUP" --name "$VNET_NAME" --no-wait 2>/dev/null || true
}
trap cleanup EXIT

# ── Shared Image Gallery bootstrap (idempotent) ─────────────────────
# `az sig show` / `image-definition show` return non-zero if missing;
# we create on the first run and reuse on every subsequent one.
if ! az sig show --resource-group "$AZURE_RESOURCE_GROUP" --gallery-name "$GALLERY_NAME" >/dev/null 2>&1; then
    echo "smoke:azure: create Shared Image Gallery $GALLERY_NAME"
    az sig create --resource-group "$AZURE_RESOURCE_GROUP" \
        --gallery-name "$GALLERY_NAME" --location "$REGION" >/dev/null
fi
if ! az sig image-definition show --resource-group "$AZURE_RESOURCE_GROUP" \
        --gallery-name "$GALLERY_NAME" --gallery-image-definition "$IMG_DEF_NAME" >/dev/null 2>&1; then
    echo "smoke:azure: create image definition $IMG_DEF_NAME (ConfidentialVmSupported)"
    az sig image-definition create --resource-group "$AZURE_RESOURCE_GROUP" \
        --gallery-name "$GALLERY_NAME" --gallery-image-definition "$IMG_DEF_NAME" \
        --location "$REGION" \
        --os-type Linux --os-state Generalized \
        --hyper-v-generation V2 \
        --features SecurityType=ConfidentialVmSupported \
        --publisher easyenclave --offer easyenclave --sku linux-x64 >/dev/null
fi

# ── Upload VHD to a storage-account page blob ──────────────────────
# Direct blob upload avoids the managed-disk intermediate entirely. The
# CVM-capable SIG image-version explicitly rejects disk sources
# ("Currently only Vhd Blob, User Image and Gallery Image Version
# sources are supported for 'ConfidentialVmSupported' images"), but
# blob sources work directly via --os-vhd-uri.
if ! az storage account show --resource-group "$AZURE_RESOURCE_GROUP" --name "$STORAGE_ACCT" >/dev/null 2>&1; then
    echo "smoke:azure: create storage account $STORAGE_ACCT"
    az storage account create \
        --resource-group "$AZURE_RESOURCE_GROUP" --name "$STORAGE_ACCT" \
        --location "$REGION" --sku Standard_LRS --kind StorageV2 \
        --allow-blob-public-access false >/dev/null
fi

# Use the account key for data-plane operations. AZURE_CREDENTIALS has
# RG-level Contributor (ARM plane) but no Storage Blob Data Contributor
# by default; user-delegation SAS fails with AuthorizationPermissionMismatch.
# Account key works because it's fetched via ARM and doesn't require
# data-plane RBAC. The key is only in-memory for the run.
ACCT_KEY=$(az storage account keys list \
    --resource-group "$AZURE_RESOURCE_GROUP" --account-name "$STORAGE_ACCT" \
    --query '[0].value' -o tsv)
[ -n "$ACCT_KEY" ] || { echo "::error::smoke:azure: empty storage account key" >&2; exit 1; }

az storage container create \
    --account-name "$STORAGE_ACCT" --name "$STORAGE_CONTAINER" \
    --account-key "$ACCT_KEY" --public-access off >/dev/null 2>&1 || true

echo "smoke:azure: upload VHD to blob $STORAGE_ACCT/$STORAGE_CONTAINER/$BLOB_NAME"
EXPIRY=$(date -u -d '+1 hour' '+%Y-%m-%dT%H:%MZ')
SAS=$(az storage container generate-sas \
    --account-name "$STORAGE_ACCT" --name "$STORAGE_CONTAINER" \
    --account-key "$ACCT_KEY" \
    --permissions cw --expiry "$EXPIRY" -o tsv)
[ -n "$SAS" ] || { echo "::error::smoke:azure: empty SAS from generate-sas" >&2; exit 1; }

BLOB_URL="https://${STORAGE_ACCT}.blob.core.windows.net/${STORAGE_CONTAINER}/${BLOB_NAME}"
azcopy copy "$VHD" "${BLOB_URL}?${SAS}" --blob-type PageBlob

# ── Publish image-version pointing at the blob ──────────────────────
STORAGE_ACCT_ID=$(az storage account show \
    --resource-group "$AZURE_RESOURCE_GROUP" --name "$STORAGE_ACCT" \
    --query id -o tsv)
echo "smoke:azure: create image version $IMG_VERSION from blob"
az sig image-version create \
    --resource-group "$AZURE_RESOURCE_GROUP" \
    --gallery-name "$GALLERY_NAME" --gallery-image-definition "$IMG_DEF_NAME" \
    --gallery-image-version "$IMG_VERSION" \
    --os-vhd-uri "$BLOB_URL" \
    --os-vhd-storage-account "$STORAGE_ACCT_ID" \
    --target-regions "$REGION" \
    --replica-count 1 >/dev/null
IMG_VERSION_ID=$(az sig image-version show \
    --resource-group "$AZURE_RESOURCE_GROUP" \
    --gallery-name "$GALLERY_NAME" --gallery-image-definition "$IMG_DEF_NAME" \
    --gallery-image-version "$IMG_VERSION" --query id -o tsv)

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
    --location "$REGION" --sku Standard --allocation-method Static >/dev/null
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
# --image = SIG image-version resource ID (the CVM-capable image we just
#   published). Provisioning agent runs from scratch → customData lands
#   in IMDS correctly (unlike --attach-os-disk which skips provisioning).
# --security-type ConfidentialVM + vTPM + secure boot: TDX CVM requirements.
# --os-disk-security-encryption-type VMGuestStateOnly: TDX-appropriate
#   (no disk encryption; memory is what TDX protects).
# --boot-diagnostics-storage "" : managed (Azure-provided) storage.
az vm create \
    --resource-group "$AZURE_RESOURCE_GROUP" --name "$VM_NAME" \
    --location "$REGION" \
    --size "$VM_SIZE" \
    --security-type ConfidentialVM \
    --os-disk-security-encryption-type VMGuestStateOnly \
    --enable-vtpm true --enable-secure-boot true \
    --image "$IMG_VERSION_ID" \
    --nics "$NIC_NAME" \
    --boot-diagnostics-storage "" \
    --admin-username eeci \
    --generate-ssh-keys \
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
