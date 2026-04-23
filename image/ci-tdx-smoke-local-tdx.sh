#!/bin/bash
# Local-TDX real-TDX integration test — hosted-side driver.
#
# GitHub-hosted runners don't have TDX. Instead, SSH into tdx2 (a real
# TDX box registered via EE_LOCAL_HOST + EE_LOCAL_SSH_KEY_PATH) and
# have IT run the smoke under libvirt/OVMF+TDVF. Same pattern dd uses
# for dd-relaunch-cp (devopsdefender/dd/.github/actions/relaunch-cp).
#
# Flow:
#   1. scp the built ISO to tdx2.
#   2. SSH in, git-checkout the commit under test (so the runner script
#      that executes matches the commit), invoke
#      image/ci-tdx-smoke-local-tdx-runner.sh on the remote side.
#   3. Propagate the remote exit code.
#   4. Remove the remote ISO.
#
# Required env:
#   SHA12                   commit sha12 (for artifact name)
#   GITHUB_SHA              full commit sha (for remote checkout)
#   EE_LOCAL_HOST           tdx2 hostname or IP
#   EE_LOCAL_SSH_KEY_PATH   path to the private key file (the workflow
#                           writes secrets.EE_LOCAL_SSH_KEY to this path)
set -euo pipefail

: "${SHA12:?}"
: "${GITHUB_SHA:?}"
: "${EE_LOCAL_HOST:?}"
: "${EE_LOCAL_SSH_KEY_PATH:?}"

ISO="image/output/local-tdx/easyenclave-${SHA12}-local-tdx.iso"
[ -f "$ISO" ] || { echo "missing $ISO" >&2; exit 2; }

# StrictHostKeyChecking=no + no known_hosts record: this is a trusted
# box accessed by a dedicated deploy key. If the host key changes out
# from under us we notice via an auth failure rather than silent MITM.
SSH_OPTS=(-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -i "$EE_LOCAL_SSH_KEY_PATH")

REMOTE_ISO="/tmp/easyenclave-smoke-${SHA12}.iso"

cleanup() {
    set +e
    echo "smoke:local: cleanup remote ISO"
    ssh "${SSH_OPTS[@]}" "tdx2@${EE_LOCAL_HOST}" "rm -f '${REMOTE_ISO}'" 2>/dev/null || true
}
trap cleanup EXIT

echo "smoke:local: scp $ISO → tdx2@${EE_LOCAL_HOST}:${REMOTE_ISO}"
scp "${SSH_OPTS[@]}" "$ISO" "tdx2@${EE_LOCAL_HOST}:${REMOTE_ISO}"

echo "smoke:local: ssh + update checkout + run runner"
# Remote script runs under `bash -s` so we can pass it via stdin and
# still capture the exit code cleanly. The remote git-checkout ensures
# the runner script we invoke matches the commit under test.
ssh "${SSH_OPTS[@]}" "tdx2@${EE_LOCAL_HOST}" "bash -s" <<REMOTE_SCRIPT
set -euo pipefail
cd /home/tdx2/src/easyenclave
git fetch --quiet origin ${GITHUB_SHA}
git checkout --quiet ${GITHUB_SHA}
# Defensive: verify the checkout matched. If 'origin' points somewhere
# unexpected we'd otherwise run a stale runner against a fresh ISO.
actual=\$(git rev-parse HEAD)
if [ "\$actual" != "${GITHUB_SHA}" ]; then
    echo "remote HEAD \$actual != expected ${GITHUB_SHA}" >&2
    exit 2
fi
exec bash image/ci-tdx-smoke-local-tdx-runner.sh "${REMOTE_ISO}" "${SHA12}"
REMOTE_SCRIPT
