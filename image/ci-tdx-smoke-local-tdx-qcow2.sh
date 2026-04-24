#!/bin/bash
# Local-TDX-qcow2 real-TDX integration test — hosted-side driver.
#
# GitHub-hosted runners don't have TDX. SSH into tdx2 (real TDX via
# EE_LOCAL_HOST + EE_LOCAL_SSH_KEY_PATH), scp the qcow2 artifact there,
# invoke the local runner which boots it under real OVMF.inteltdx.fd +
# kvm_intel.tdx=Y. Mirrors the pattern dd's relaunch-* actions use.
#
# Why qcow2 (not ISO): dd's production path is libvirt with qcow2 as a
# COW backing file. This test validates the same artifact shape dd
# consumes on every release, not a dev-only ISO.
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

QCOW2="image/output/local-tdx-qcow2/easyenclave-${SHA12}-local-tdx-qcow2.qcow2"
[ -f "$QCOW2" ] || { echo "missing $QCOW2" >&2; exit 2; }

SSH_OPTS=(-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -i "$EE_LOCAL_SSH_KEY_PATH")
REMOTE_QCOW2="/tmp/easyenclave-smoke-${SHA12}.qcow2"

cleanup() {
    set +e
    echo "smoke:local-tdx-qcow2: cleanup remote qcow2"
    ssh "${SSH_OPTS[@]}" "tdx2@${EE_LOCAL_HOST}" "rm -f '${REMOTE_QCOW2}'" 2>/dev/null || true
}
trap cleanup EXIT

echo "smoke:local-tdx-qcow2: scp $QCOW2 → tdx2@${EE_LOCAL_HOST}:${REMOTE_QCOW2}"
scp "${SSH_OPTS[@]}" "$QCOW2" "tdx2@${EE_LOCAL_HOST}:${REMOTE_QCOW2}"

echo "smoke:local-tdx-qcow2: ssh + run runner"
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
exec bash image/ci-tdx-smoke-local-tdx-qcow2-runner.sh "${REMOTE_QCOW2}" "${SHA12}"
REMOTE_SCRIPT
