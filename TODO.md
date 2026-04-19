# TODO

## TDX measurement tracking
Build-time: capture MRTD + RTMR values for each release artifact, target profile, and launch topology. Registration-time: verify agent quotes against expected measurements. Sealing: encrypt secrets to measured state.

## Canonical local launch workflow
The README now points at build artifacts, but the current working tree has no local launcher script. Decide whether to restore a QEMU/libvirt helper or document exact external launch commands for `gcp` qcow2 and `local-tdx` ISO, including config-disk handling.

## GPU passthrough image packaging
NVIDIA module and firmware staging is currently image-local and kernel-version specific. Profile-gate it, avoid hard-coded host kernel paths, and document attestation/measurement impact before treating GPU images as release artifacts.

## Workload restart policy
Process workloads don't auto-restart on crash. Add a configurable restart policy (always, on-failure, never) in `workload.rs` that supervises spawned children.

## Health check for workloads
Per-workload health check config (cmd, interval, retries). Mark workload unhealthy/restart on failure. Currently only tracks running/stopped/failed.
