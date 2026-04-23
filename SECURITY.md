# Security policy

## Reporting a vulnerability

Report privately through GitHub's security advisory form:
https://github.com/easyenclave/easyenclave/security/advisories/new

Do not open a public issue for security bugs.

## Scope

EasyEnclave is a runtime that boots inside an Intel TDX confidential VM
and exposes a unix-socket API for workload management. The highest-priority
classes of issue:

- **Attestation integrity** — paths that fabricate or bypass a TDX quote,
  skip `configfs-tsm`, or allow a non-TDX host to answer as if attested.
- **Boot-chain integrity** — anything that weakens the measured-boot
  chain (UKI, initrd, dm-verity) or lets the sealed rootfs be modified
  between measurement and execution.
- **Socket authorization** — bypasses of the `EE_TOKEN` gate on the
  agent socket, or escalation from a compromised workload to socket
  authority it wasn't granted.
- **Metadata-plane injection** — paths where cloud metadata (`ee-config`,
  customData) or the secondary config disk can push arbitrary env into
  PID 1 in a way the platform's trust model didn't intend.

## What to include

- Commit / release tag affected
- Minimal reproduction (serial log, quote payload, or test commit)
- Threat model you're operating under (what the attacker can/can't do)

## Non-scope

- Crashes during boot on non-TDX hardware — intentional (`detect()`
  refuses to proceed without TDX)
- DoS from an authorized workload misbehaving — workloads are trusted
  code running inside the enclave

## Response

Acknowledgement within 72 hours, triage within a week.
