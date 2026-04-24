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

# Regions are split into two concerns because the RG and the TDX-
# SKU-quota don't line up for this subscription:
#   - STORAGE_REGION = where the blob + gallery + image-version HOME
#     live. Pinned to the RG's location because Azure's image-version
#     import uses an internal staging disk rooted in the RG region,
#     and rejects cross-region blob sources with "source blob does
#     not belong to the same region as the disk."
#   - VM_REGION = where the TDX VM actually boots. $REGION is the
#     user-facing knob; defaults to westus3 where DCe_v6 quota exists.
# The image-version replicates from STORAGE_REGION into VM_REGION so
# the VM provision step pulls a local-region replica.
REGION="${AZURE_REGION:-westus3}"
VM_SIZE="${AZURE_VM_SIZE:-Standard_DC2es_v6}"
STORAGE_REGION="$(az group show --name "$AZURE_RESOURCE_GROUP" --query location -o tsv)"
[ -n "$STORAGE_REGION" ] || { echo "::error::smoke:azure: couldn't resolve RG location" >&2; exit 1; }
VHD="image/output/azure/easyenclave-${SHA12}-azure.vhd"
[ -f "$VHD" ] || { echo "missing $VHD" >&2; exit 2; }

STAMP=$(date +%s)
PREFIX="ee-smoke-${SHA12}-${STAMP}"
VM_NAME="${PREFIX}-vm"
NIC_NAME="${PREFIX}-nic"
PIP_NAME="${PREFIX}-pip"
NSG_NAME="${PREFIX}-nsg"
VNET_NAME="${PREFIX}-vnet"

# Shared Image Gallery state. Gallery + image-def live in STORAGE_REGION
# (the RG's location) so Azure's internal staging pipeline is happy.
# Only the image VERSION is per-run and torn down after the test.
GALLERY_NAME="${AZURE_GALLERY:-easyenclaveGallery}"
IMG_DEF_NAME="${AZURE_IMG_DEF:-easyenclave-x64}"
IMG_VERSION="0.0.$(date +%s)"

# Storage account for staging the VHD as a page blob. Pinned to
# STORAGE_REGION (= RG location). One account per RG.
STORAGE_ACCT="${AZURE_STORAGE_ACCT:-eeci$(echo -n "${AZURE_RESOURCE_GROUP}" | sha256sum | cut -c1-16)}"
STORAGE_CONTAINER="${AZURE_STORAGE_CONTAINER:-vhds}"
BLOB_NAME="${PREFIX}.vhd"

cleanup() {
    set +e
    # Guard against a pre-PREFIX exit (e.g. someone rearranges the script
    # and moves the trap above PREFIX=). Without this, `az ... --name ""`
    # could match unintended resources or produce confusing errors.
    [ -n "${PREFIX:-}" ] || return 0
    echo "smoke:azure: cleanup"
    # VM delete WITHOUT --no-wait: we need Azure to at least ACK the
    # delete request before this script exits. Previously --no-wait +
    # runner-kill could leave the DELETE un-posted, orphaning the VM
    # (and its cores). The wait is ~30-60s, well within budget.
    # Dropped 2>/dev/null on every cleanup line (keeping || true) so
    # real cleanup failures surface in the CI log — the earlier silent
    # swallow masked the managed-disk + NIC orphans that eventually
    # filled the WestUS3 cores quota.
    az vm delete --resource-group "$AZURE_RESOURCE_GROUP" --name "$VM_NAME" --yes || true
    az sig image-version delete --resource-group "$AZURE_RESOURCE_GROUP" \
        --gallery-name "$GALLERY_NAME" --gallery-image-definition "$IMG_DEF_NAME" \
        --gallery-image-version "$IMG_VERSION" --no-wait || true
    # ACCT_KEY may be unset if we exited before fetching it; fetch again
    # (cheap: az handles the no-op case), fall back to nothing if the
    # account itself is gone.
    CLEANUP_KEY=$(az storage account keys list \
        --resource-group "$AZURE_RESOURCE_GROUP" --account-name "$STORAGE_ACCT" \
        --query '[0].value' -o tsv 2>/dev/null || true)
    if [ -n "$CLEANUP_KEY" ]; then
        az storage blob delete --account-name "$STORAGE_ACCT" --container-name "$STORAGE_CONTAINER" \
            --name "$BLOB_NAME" --account-key "$CLEANUP_KEY" || true
    fi
    az network nic delete --resource-group "$AZURE_RESOURCE_GROUP" --name "$NIC_NAME" --no-wait || true
    az network public-ip delete --resource-group "$AZURE_RESOURCE_GROUP" --name "$PIP_NAME" --no-wait || true
    az network nsg delete --resource-group "$AZURE_RESOURCE_GROUP" --name "$NSG_NAME" --no-wait || true
    az network vnet delete --resource-group "$AZURE_RESOURCE_GROUP" --name "$VNET_NAME" --no-wait || true

    # Belt-and-suspenders: any resource whose name starts with our
    # per-run PREFIX that the named deletes above missed (future
    # naming drift, partial writes, resource types added to the
    # script without a matching cleanup line). --no-wait so runner
    # timeout doesn't kill mid-sweep.
    echo "smoke:azure: prefix sweep for ${PREFIX}-*"
    az resource list --resource-group "$AZURE_RESOURCE_GROUP" \
        --query "[?starts_with(name, '${PREFIX}')].id" -o tsv 2>/dev/null \
      | xargs -r az resource delete --ids --verbose || true
}
trap cleanup EXIT

# ── Shared Image Gallery bootstrap (idempotent) ─────────────────────
# `az sig show` / `image-definition show` return non-zero if missing;
# we create on the first run and reuse on every subsequent one.
if ! az sig show --resource-group "$AZURE_RESOURCE_GROUP" --gallery-name "$GALLERY_NAME" >/dev/null 2>&1; then
    echo "smoke:azure: create Shared Image Gallery $GALLERY_NAME"
    az sig create --resource-group "$AZURE_RESOURCE_GROUP" \
        --gallery-name "$GALLERY_NAME" --location "$STORAGE_REGION" >/dev/null
fi
if ! az sig image-definition show --resource-group "$AZURE_RESOURCE_GROUP" \
        --gallery-name "$GALLERY_NAME" --gallery-image-definition "$IMG_DEF_NAME" >/dev/null 2>&1; then
    echo "smoke:azure: create image definition $IMG_DEF_NAME (ConfidentialVmSupported)"
    az sig image-definition create --resource-group "$AZURE_RESOURCE_GROUP" \
        --gallery-name "$GALLERY_NAME" --gallery-image-definition "$IMG_DEF_NAME" \
        --location "$STORAGE_REGION" \
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
        --location "$STORAGE_REGION" --sku Standard_LRS --kind StorageV2 \
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
# Home region (STORAGE_REGION) is the first target so the staging
# disk matches the blob's region. Include $REGION too so the image-
# version is replicated to where the VM will boot.
if [ "$STORAGE_REGION" = "$REGION" ]; then
    TARGET_REGIONS="$REGION"
else
    TARGET_REGIONS="$STORAGE_REGION $REGION"
fi
echo "smoke:azure: create image version $IMG_VERSION from blob (target-regions: $TARGET_REGIONS)"
# `az sig image-version create` without --no-wait blocks ~7-9 minutes
# on ConfidentialVmSupported image-versions. The image-version itself
# is 322MB — the wait isn't network; it's Azure's internal pipeline
# (CVM metadata seal → replica copy → catalog index → validate).
# Submit async, poll provisioningState + replicationStatus every 20s
# so CI logs show progress instead of silent 8-min hang.
VERSION_START=$(date +%s)
# shellcheck disable=SC2086
az sig image-version create \
    --resource-group "$AZURE_RESOURCE_GROUP" \
    --gallery-name "$GALLERY_NAME" --gallery-image-definition "$IMG_DEF_NAME" \
    --gallery-image-version "$IMG_VERSION" \
    --os-vhd-uri "$BLOB_URL" \
    --os-vhd-storage-account "$STORAGE_ACCT_ID" \
    --target-regions $TARGET_REGIONS \
    --replica-count 1 \
    --no-wait >/dev/null

for attempt in $(seq 1 60); do
    # provisioningState: Creating / Succeeded / Failed
    # replicationStatus.regionalReplicationStatus: per-region progress (0-100)
    info=$(az sig image-version show \
        --resource-group "$AZURE_RESOURCE_GROUP" \
        --gallery-name "$GALLERY_NAME" --gallery-image-definition "$IMG_DEF_NAME" \
        --gallery-image-version "$IMG_VERSION" \
        --query "{p: provisioningState, r: replicationStatus}" \
        -o json 2>/dev/null || echo '{"p":"?","r":null}')
    state=$(echo "$info" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('p','?'))")
    reps=$(echo "$info" | python3 -c "
import json, sys
d = json.load(sys.stdin)
r = d.get('r') or {}
regs = r.get('regionalReplicationStatus') or []
parts = []
for rg in regs:
    name = rg.get('region', '?')
    state = rg.get('state', '?')
    prog = rg.get('progress', 0)
    parts.append(f'{name}:{state}[{prog}%]')
print(' '.join(parts) if parts else 'no-replica-info')
" 2>/dev/null || echo "?")
    elapsed=$(( $(date +%s) - VERSION_START ))
    printf 'smoke:azure: [%3ds] provisioning=%s replicas=%s\n' "$elapsed" "$state" "$reps"
    case "$state" in
        Succeeded) break ;;
        Failed|Canceled) echo "::error::smoke:azure: image-version create $state" >&2; exit 1 ;;
    esac
    sleep 20
done

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
# --security-type ConfidentialVM + vTPM: TDX CVM requirements.
# --enable-secure-boot false: EasyEnclave's UKI is unsigned. Azure's
#   Secure Boot (UEFI-level signature check) is distinct from TDX
#   attestation (measured-boot via configfs-tsm) — we rely on the
#   latter, not the former. Signing UKIs is a production cert-mgmt
#   concern we're not taking on for CI smoke.
# --os-disk-security-encryption-type VMGuestStateOnly: TDX-appropriate
#   (no disk encryption; memory is what TDX protects).
# --boot-diagnostics-storage "" : managed (Azure-provided) storage.
# Boot-diagnostics storage: pass a concrete unmanaged storage URL so
# boot-diag writes directly to our storage account without needing
# the guest agent (waagent) to confirm. Both the "managed" path
# (`--boot-diagnostics-storage ""` on create OR post-create
# `az vm boot-diagnostics enable`) require waagent inside the guest
# to complete — easyenclave doesn't ship waagent, so those commands
# time out after ~20min with OSProvisioningTimedOut. Unmanaged-storage
# path is purely an ARM-layer attachment and works fine on agent-less
# images.
az vm create \
    --resource-group "$AZURE_RESOURCE_GROUP" --name "$VM_NAME" \
    --location "$REGION" \
    --size "$VM_SIZE" \
    --security-type ConfidentialVM \
    --os-disk-security-encryption-type VMGuestStateOnly \
    --enable-vtpm true --enable-secure-boot false \
    --image "$IMG_VERSION_ID" \
    --nics "$NIC_NAME" \
    --os-disk-delete-option Delete \
    --nic-delete-option Delete \
    --boot-diagnostics-storage "https://${STORAGE_ACCT}.blob.core.windows.net/" \
    --admin-username eeci \
    --generate-ssh-keys \
    --user-data /tmp/ee-config.env \
    --no-wait >/dev/null
# EasyEnclave has no Azure VM agent inside the sealed image. That means
# provisioningState/powerState won't follow the agent-driven happy path.
# But the deployment layer (ARM → VM object + disk + NIC) DOES complete
# independently — once that lands, boot-diag captures hypervisor-level
# serial. Poll for deployment-layer ready (NIC provisioned + VM in one
# of the reachable states) before jumping to serial.
echo "smoke:azure: VM create submitted — waiting for deployment layer ready..."
for i in $(seq 1 60); do
    info=$(az vm show -d -g "$AZURE_RESOURCE_GROUP" -n "$VM_NAME" \
        --query "{ps: provisioningState, power: powerState, diag: diagnosticsProfile}" \
        -o json 2>/dev/null || echo '{}')
    ps=$(echo "$info" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('ps','?'))")
    power=$(echo "$info" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('power','?'))")
    echo "smoke:azure: vm state=$ps power=$power ($i/60)"
    # powerState goes "VM starting" → "VM running" as ARM brings it up
    # provisioningState may stay Updating/Creating forever without agent
    case "$power" in
        "VM running"|"VM stopped"|"VM deallocated") break ;;
    esac
    # explicit deployment failure
    case "$ps" in
        Failed|Canceled) echo "::error::smoke:azure: VM provisioning $ps" >&2; exit 1 ;;
    esac
    sleep 10
done

# One-off probe so the CI log shows whether boot-diag is actually
# attached before we start polling. If the attachment worked via the
# --boot-diagnostics-storage arg, this returns a valid blob URI.
echo "smoke:azure: probe boot-diag endpoint..."
diag_uris=$(az vm boot-diagnostics get-boot-log-uris \
    -g "$AZURE_RESOURCE_GROUP" -n "$VM_NAME" 2>&1 | head -5 || true)
echo "smoke:azure: boot-diag-uris: $diag_uris"

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
LAST_LINES=0
# 72 × 10s = 12 min. Budget covers VM hypervisor-level boot (~1-3min
# before first serial output) + enclave boot + workload spawn. Azure
# CVM provisioning is typically ready at the serial-output level in
# ~90s, but allow headroom for slow sub-region capacity.
for i in $(seq 1 72); do
    # boot-diagnostics-log returns the full serial each call. Diff against
    # last poll and stream only new lines (same pattern gcp's get-serial-
    # port-output uses), so CI logs show boot progress live.
    out=$(az vm boot-diagnostics get-boot-log \
        --resource-group "$AZURE_RESOURCE_GROUP" --name "$VM_NAME" 2>/dev/null || true)
    if [ -n "$out" ]; then
        TOTAL=$(echo "$out" | wc -l)
        if [ "$TOTAL" -gt "$LAST_LINES" ]; then
            echo "$out" | tail -n +$((LAST_LINES + 1)) | sed 's/^/[serial] /'
            LAST_LINES=$TOTAL
        fi
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
    echo "smoke:azure: waiting... ($i/72)"
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
