# Phase 03 - ee-attestation Intel TA Verification

Status: Not started

## Goal

Verify Intel Trust Authority attestation JWTs with strict claim and signature validation.

## Deliverables

- `crates/ee-attestation/src/ita.rs`
- JWKS client with caching
- Verification API for signature + claims
- Parsed claim structure for downstream policy checks

## Test Gates

- Valid token accepted
- Expired token rejected
- Signature mismatch rejected
- Invalid issuer/audience rejected

## Definition Of Done

- [ ] Verification is fail-closed
- [ ] Claim validation is strict and explicit
- [ ] JWKS cache behavior is tested

## PR Checklist

- [ ] JWKS mock tests added
- [ ] Claim validation tests added
- [ ] Negative-path tests added
