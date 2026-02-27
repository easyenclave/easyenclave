# Attestation Security Model (v2)

Status: Draft for Phase 00

## Purpose

This document defines the minimum security contract for agent registration attestation in easyenclave v2.
The contract is normative for implementation and tests.

## Scope

In scope:
- CP-side verification for `GET /api/v1/agents/challenge` and `POST /api/v1/agents/register`
- Nonce issuance, binding, replay protection, and expiry handling
- Intel Trust Authority (ITA) JWT verification
- `MRTD`, `RTMR`, and `TCB` policy enforcement
- Registration audit logging and rejection semantics

Out of scope:
- Runtime workload isolation details
- Full network hardening and DDoS controls
- Post-registration business rules unrelated to attestation

## Trust Boundaries

Actors:
- Agent VM: untrusted until registration succeeds
- Control Plane (CP): policy enforcement authority
- Intel Trust Authority: external attestation token signer
- Configuration/Store layer: trusted source of enforcement policy and trusted `MRTD` set

Boundary assumptions:
- ITA signing keys are trusted only if fetched from configured JWKS and verified by TLS
- Agent-supplied fields are untrusted until validated
- CP clocks are authoritative for token/nonce expiry checks

## Registration Contract

Registration is valid only if all checks pass in this order:
1. Challenge nonce exists and is unexpired.
2. Nonce is bound to quote `report_data` and matches exactly.
3. Nonce has not been previously consumed.
4. ITA JWT signature is valid against current JWKS cache or refreshed JWKS.
5. JWT claims are valid: `iss`, `aud`, `exp`, `nbf`.
6. Extracted `MRTD` is present in trusted baseline store.
7. `TCB` status policy passes configured enforcement mode.
8. `RTMR` values/policy pass configured enforcement mode.

Any failed check rejects registration. No partial success is allowed.

## Security Invariants

1. Nonce is single-use and TTL-limited.
2. Nonce must be quote-bound via `report_data`; transport-only nonce is insufficient.
3. All verification failures are fail-closed.
4. Policy modes are explicit and never inferred.
5. Verification decisions are audit-logged with stable reason codes.
6. Successful registration emits a success audit event containing policy mode snapshot.

## Policy Modes

`tcb_enforcement_mode`:
- `strict`: non-acceptable TCB rejects registration
- `warn`: non-acceptable TCB allows registration with warning audit
- `disabled`: TCB check skipped; explicit audit marker required

`rtmr_enforcement_mode`:
- `strict`: mismatch rejects registration
- `warn`: mismatch allows registration with warning audit
- `disabled`: RTMR check skipped; explicit audit marker required

`nonce_enforcement_mode`:
- `required`: missing/invalid nonce rejects registration
- `optional`: nonce failures warn but do not reject (for controlled testing only)
- `disabled`: nonce path skipped; explicit audit marker required

Default expectation for production-like deployments:
- `tcb_enforcement_mode=strict`
- `rtmr_enforcement_mode=strict`
- `nonce_enforcement_mode=required`

## Rejection Reason Codes

Use these stable codes in API errors and audit logs.

- `EE-ATT-001` nonce missing
- `EE-ATT-002` nonce not found
- `EE-ATT-003` nonce expired
- `EE-ATT-004` nonce replay (already consumed)
- `EE-ATT-005` nonce does not match quote `report_data`
- `EE-ATT-006` ITA token missing
- `EE-ATT-007` ITA signature invalid
- `EE-ATT-008` ITA token expired
- `EE-ATT-009` ITA token not yet valid (`nbf`)
- `EE-ATT-010` ITA issuer invalid
- `EE-ATT-011` ITA audience invalid
- `EE-ATT-012` quote parse failure
- `EE-ATT-013` `MRTD` missing from token/quote claims
- `EE-ATT-014` untrusted `MRTD`
- `EE-ATT-015` `TCB` not acceptable under strict mode
- `EE-ATT-016` `RTMR` mismatch under strict mode
- `EE-ATT-017` policy configuration invalid
- `EE-ATT-018` verification dependency unavailable (JWKS fetch/service timeout)
- `EE-ATT-019` internal verification error

Warning-only (non-fatal) reason codes:
- `EE-ATT-W01` `TCB` warn-mode bypass
- `EE-ATT-W02` `RTMR` warn-mode bypass
- `EE-ATT-W03` nonce optional/disabled bypass

## Audit Event Requirements

Each registration attempt must emit one terminal event:
- `registration_attestation_accepted`
- `registration_attestation_rejected`

Required fields:
- `event_name`
- `timestamp`
- `request_id`
- `agent_vm_name` (if present)
- `reason_code` (or `OK`)
- `policy_snapshot` (`nonce`, `tcb`, `rtmr` modes)
- `mrtd`
- `tcb_status`
- `nonce_id` (hash/prefix only; no raw secret logging)
- `result` (`accepted` or `rejected`)

Logging constraints:
- Never log raw JWTs.
- Never log raw nonce bytes.
- Never log tunnel token or agent control secret.

## Failure Behavior

On verification dependency failures (JWKS, timeout, parse errors), registration rejects by default.

CP response behavior:
- Return deterministic error payload with reason code.
- Use client-safe message; avoid sensitive internals.
- Increment security failure metrics by reason code.

## Metrics (Minimum)

- `attestation_registration_attempt_total{result}`
- `attestation_registration_reject_total{reason_code}`
- `attestation_nonce_issued_total`
- `attestation_nonce_consumed_total`
- `attestation_nonce_expired_total`
- `attestation_jwks_refresh_total{result}`

## Phase 00 Exit Checklist

- [ ] Reason codes implemented as stable enum/constants
- [ ] API error payload includes reason code
- [ ] Audit events include required fields
- [ ] Registration flow enforces invariant check ordering
- [ ] Warn/disabled modes are explicitly logged
- [ ] All matrix tests in `docs/enclave-test-matrix.md` are automated
