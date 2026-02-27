# Phase 14 - ee-launcher

Status: Not started

## Goal

Build host-side CLI for launching and managing TDX VMs.

## Deliverables

- CLI commands: launch, stop, list, logs
- QEMU helpers
- OCI extraction helpers
- Preflight checks
- Config injection via kernel cmdline

## Test Gates

- CLI argument validation
- Node-size parsing
- Config injection round-trip

## Definition Of Done

- [ ] Launcher can boot a VM with expected config
- [ ] Preflight checks fail clearly when infra is missing
- [ ] CLI UX is stable and scriptable

## PR Checklist

- [ ] Command handlers implemented
- [ ] QEMU/OCI modules implemented
- [ ] CLI tests added
