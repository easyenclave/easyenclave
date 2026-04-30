# TODO

## TDX measurement tracking
Build-time: capture MRTD + RTMR values for each release artifact, target profile, and launch topology. Registration-time: verify agent quotes against expected measurements. Sealing: encrypt secrets to measured state.

## Canonical local launch workflow
The README now points at build artifacts, but the current working tree has no local launcher script. Decide whether to restore a QEMU/libvirt helper or document exact external launch commands for `gcp` qcow2 and `local-tdx` ISO, including config-disk handling.

## GPU passthrough image packaging
NVIDIA module and firmware staging is currently image-local and kernel-version specific. Profile-gate it, avoid hard-coded host kernel paths, and document attestation/measurement impact before treating GPU images as release artifacts.

## ee-gpu-evidence helper (real Python implementation)
The runtime-side GPU evidence path is wired (see `src/attestation/nvgpu.rs` + `docs/gpu-attestation.md`). The image ships a stub `/usr/local/bin/ee-gpu-evidence` that exits non-zero with "nv-attestation-sdk venv not installed". Replace with a real Python helper backed by `/opt/venv-attestation` (`nv-attestation-sdk==2.6.3`, `nv-local-gpu-verifier==2.6.3`), emitting the length-prefixed `(gpu_report, switch_report)` frame on stdout. Depends on the GPU passthrough image-packaging item above — the venv has to land in the rootfs, which itself blocks on the deferred CUDA/driver bake in `image/mkosi.profiles/llm-cuda/mkosi.conf`.

## Workload restart policy
Process workloads don't auto-restart on crash. Add a configurable restart policy (always, on-failure, never) in `workload.rs` that supervises spawned children.

## Health check for workloads
Per-workload health check config (cmd, interval, retries). Mark workload unhealthy/restart on failure. Currently only tracks running/stopped/failed.
