# Phase 06 - Nonce + Agent Registration

Status: Not started

## Goal

Ship secure challenge-response registration and core agent lifecycle routes.

## Deliverables

- Nonce service with TTL and single-use semantics
- Attestation service with MRTD/TCB/RTMR policy checks
- Agent routes: challenge, register, heartbeat, status, deployed, list/get/delete/reset, owner patch, console token

## Test Gates

- Nonce lifecycle correctness
- Registration happy path
- Registration rejection matrix from Phase 00
- Heartbeat updates agent state

## Definition Of Done

- [ ] Registration is secure and fail-closed
- [ ] Lifecycle routes persist expected state
- [ ] Audit logs capture decisions and failures

## PR Checklist

- [ ] Nonce store implemented
- [ ] Registration handler implemented
- [ ] Attestation-policy tests added
- [ ] Route-level tests added
