#!/bin/bash
# llm-cuda real-TDX integration test — hosted-side driver.
#
# GitHub-hosted runners don't have TDX or an H100. SSH into tdx2 (real
# TDX via EE_LOCAL_HOST + EE_LOCAL_SSH_KEY_PATH), scp the qcow2
# artifact there, invoke the local runner which boots it under real
# OVMF.inteltdx.fd + kvm_intel.tdx=Y, optionally attaching the host's
# H100 if one is bound to vfio-pci. Mirrors the pattern used by every
# other real-TDX smoke (gcp/azure/local-tdx-qcow2 → SSH-and-go).
#
# Why the llm-cuda image as the smoke target: it's a strict superset
# of the previous local-tdx-qcow2 image (same TDX boot path, same
# qemu vendor stage, plus dm-verity + the NVIDIA stack). One smoke
# job covers everything the local-tdx-qcow2 smoke covered.
#
# Required env:
#   SHA12                    commit sha12 (for artifact name)
#   GITHUB_SHA               full commit sha (for remote checkout)
#   EE_LOCAL_HOST            tdx2 hostname or IP
#   EE_LOCAL_SSH_KEY_PATH    path to the private key file
set -euo pipefail

: "${SHA12:?}"
: "${GITHUB_SHA:?}"
: "${EE_LOCAL_HOST:?}"
: "${EE_LOCAL_SSH_KEY_PATH:?}"

QCOW2="image/output/llm-cuda/easyenclave-${SHA12}-llm-cuda.qcow2"
[ -f "$QCOW2" ] || { echo "missing $QCOW2" >&2; exit 2; }

SSH_OPTS=(-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -i "$EE_LOCAL_SSH_KEY_PATH")
REMOTE_QCOW2="/tmp/easyenclave-smoke-${SHA12}.qcow2"

cleanup() {
    set +e
    echo "smoke:llm-cuda: cleanup remote qcow2"
    ssh "${SSH_OPTS[@]}" "tdx2@${EE_LOCAL_HOST}" "rm -f '${REMOTE_QCOW2}'" 2>/dev/null || true
}
trap cleanup EXIT

# llm-cuda qcow2 is ~7GB (CUDA + PyTorch + vLLM bake), so this scp
# is several minutes on a normal GHA runner uplink. Worth it: the
# alternative is hosting the artifact in object storage and having
# tdx2 pull it, which adds an auth surface for no real win.
echo "smoke:llm-cuda: scp $QCOW2 → tdx2@${EE_LOCAL_HOST}:${REMOTE_QCOW2}"
scp "${SSH_OPTS[@]}" "$QCOW2" "tdx2@${EE_LOCAL_HOST}:${REMOTE_QCOW2}"

echo "smoke:llm-cuda: ssh + run runner"
ssh "${SSH_OPTS[@]}" "tdx2@${EE_LOCAL_HOST}" "bash -s" <<REMOTE_SCRIPT
set -euo pipefail
cd /home/tdx2/src/easyenclave
# CI workspace, not a dev checkout — force-reset to the SHA under test
# so the runner script we invoke matches the commit.
git fetch --quiet origin ${GITHUB_SHA}
git reset --quiet --hard ${GITHUB_SHA}
git clean -qfd
actual=\$(git rev-parse HEAD)
if [ "\$actual" != "${GITHUB_SHA}" ]; then
    echo "remote HEAD \$actual != expected ${GITHUB_SHA}" >&2
    exit 2
fi
exec bash image/ci-tdx-smoke-llm-cuda-runner.sh "${REMOTE_QCOW2}" "${SHA12}"
REMOTE_SCRIPT
