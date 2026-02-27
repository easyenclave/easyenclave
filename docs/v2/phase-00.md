# Phase 00 - Security Contract + Test Gates

Status: Not started

## Goal

Define and lock the attestation security contract so all later implementation phases inherit consistent, testable behavior.

## Deliverables

- `docs/security-attestation-model.md`
- `docs/enclave-test-matrix.md`
- Error taxonomy for attestation and policy decisions
- Canonical reason codes for registration rejection paths

## Test Gates

- Nonce reuse is rejected
- Expired nonce is rejected
- Invalid Intel TA JWT signature is rejected
- Invalid claims (`iss`, `aud`, `exp`, `nbf`) are rejected
- Untrusted `MRTD` is rejected
- `TCB` policy matrix behaves as configured
- `RTMR` policy matrix behaves as configured

## Definition Of Done

- [ ] Security invariants documented and reviewed
- [ ] All failure modes have explicit reason codes
- [ ] Automated tests cover success and rejection matrix
- [ ] Registration behavior is fail-closed by default

## PR Checklist

- [ ] Docs updated
- [ ] Unit tests added
- [ ] Integration tests added
- [ ] Logging/audit fields validated
