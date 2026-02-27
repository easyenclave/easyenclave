# Enclave Attestation Test Matrix (Phase 00)

Status: Draft for Phase 00

## Purpose

Define mandatory tests for registration attestation behavior.
Each test maps to explicit rejection or warning reason codes.

## Coverage Levels

- Unit: parsing, claim validation, nonce store semantics
- Integration: register route with mocked ITA/JWKS and policy store
- End-to-end: agent-like request flow against running CP with mocks

## Fixtures and Harness Requirements

- Valid quote fixture with deterministic `MRTD`, `RTMR`, and nonce payload
- Tampered quote fixture (bad offsets or malformed payload)
- Valid ITA JWT fixture and keypair
- Invalid ITA JWT fixtures (bad signature, wrong `iss`, wrong `aud`, expired, future `nbf`)
- Trusted `MRTD` list with at least one allowed and one disallowed digest
- Policy fixtures for `strict`, `warn`, `disabled`

## Core Registration Matrix

| Test ID | Scenario | Policy Mode | Expected Result | Reason Code |
|---|---|---|---|---|
| REG-001 | Valid nonce + valid JWT + trusted MRTD + acceptable TCB/RTMR | strict/strict/required | accept | OK |
| REG-002 | Missing nonce in request | any/any/required | reject | EE-ATT-001 |
| REG-003 | Nonce not issued by CP | any/any/required | reject | EE-ATT-002 |
| REG-004 | Nonce expired | any/any/required | reject | EE-ATT-003 |
| REG-005 | Nonce replay (reuse consumed nonce) | any/any/required | reject | EE-ATT-004 |
| REG-006 | Nonce mismatch vs quote report_data | any/any/required | reject | EE-ATT-005 |
| REG-007 | Missing ITA token | any/any/any | reject | EE-ATT-006 |
| REG-008 | Invalid JWT signature | any/any/any | reject | EE-ATT-007 |
| REG-009 | Expired JWT (`exp`) | any/any/any | reject | EE-ATT-008 |
| REG-010 | JWT not yet valid (`nbf`) | any/any/any | reject | EE-ATT-009 |
| REG-011 | Invalid JWT issuer | any/any/any | reject | EE-ATT-010 |
| REG-012 | Invalid JWT audience | any/any/any | reject | EE-ATT-011 |
| REG-013 | Malformed quote payload | any/any/any | reject | EE-ATT-012 |
| REG-014 | Missing MRTD claim/extract | any/any/any | reject | EE-ATT-013 |
| REG-015 | MRTD not in trusted set | any/any/any | reject | EE-ATT-014 |
| REG-016 | Verification dependency timeout/unavailable | any/any/any | reject | EE-ATT-018 |
| REG-017 | Internal verifier error path | any/any/any | reject | EE-ATT-019 |

## TCB Policy Matrix

Precondition: non-acceptable `TCB` status with otherwise valid registration payload.

| Test ID | `tcb_enforcement_mode` | Expected Result | Reason Code |
|---|---|---|---|
| TCB-001 | strict | reject | EE-ATT-015 |
| TCB-002 | warn | accept + warning audit | EE-ATT-W01 |
| TCB-003 | disabled | accept + bypass audit | EE-ATT-W01 |

## RTMR Policy Matrix

Precondition: `RTMR` mismatch with otherwise valid registration payload.

| Test ID | `rtmr_enforcement_mode` | Expected Result | Reason Code |
|---|---|---|---|
| RTMR-001 | strict | reject | EE-ATT-016 |
| RTMR-002 | warn | accept + warning audit | EE-ATT-W02 |
| RTMR-003 | disabled | accept + bypass audit | EE-ATT-W02 |

## Nonce Policy Matrix

Precondition: nonce failure condition with otherwise valid registration payload.

| Test ID | `nonce_enforcement_mode` | Expected Result | Reason Code |
|---|---|---|---|
| NONCE-001 | required | reject | EE-ATT-001..EE-ATT-005 |
| NONCE-002 | optional | accept + warning audit | EE-ATT-W03 |
| NONCE-003 | disabled | accept + bypass audit | EE-ATT-W03 |

## Audit and Logging Tests

| Test ID | Scenario | Expected Result |
|---|---|---|
| AUD-001 | Rejected registration | terminal event `registration_attestation_rejected` with reason code |
| AUD-002 | Accepted registration | terminal event `registration_attestation_accepted` with `OK` |
| AUD-003 | Warn-mode acceptance | accepted event includes warning reason code |
| AUD-004 | Sensitive data guard | logs contain no raw JWT, nonce bytes, tunnel token, or agent secret |
| AUD-005 | Policy snapshot | every terminal event includes nonce/tcb/rtmr modes |

## Idempotency and Concurrency Tests

| Test ID | Scenario | Expected Result |
|---|---|---|
| CON-001 | Concurrent registrations attempt same nonce | exactly one succeeds, others fail `EE-ATT-004` |
| CON-002 | JWKS cache refresh under concurrent verify | no data race; deterministic success/failure behavior |
| CON-003 | Concurrent challenge issuance | unique nonce values, no collisions |

## API Contract Tests

| Test ID | Scenario | Expected Result |
|---|---|---|
| API-001 | Rejection response schema | includes stable `reason_code` and safe message |
| API-002 | Success response schema | includes expected registration payload fields only |
| API-003 | Unknown policy mode value | deterministic reject `EE-ATT-017` |

## CI Gate For Phase 00

Required in CI before Phase 00 is marked complete:
- Unit and integration tests from this matrix are automated
- All strict-mode rejection cases pass
- Warning-mode acceptance cases pass with warning audit assertions
- Sensitive-log guard tests pass

## Completion Checklist

- [ ] Every matrix row is implemented as a test case
- [ ] Test IDs are traceable in CI output or test names
- [ ] Reason codes in test assertions match `security-attestation-model.md`
- [ ] Phase 00 checklist in `docs/v2/phase-00.md` is updated
