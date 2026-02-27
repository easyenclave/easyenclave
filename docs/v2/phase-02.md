# Phase 02 - ee-attestation TDX Quote Parsing

Status: Not started

## Goal

Implement trusted parsing and extraction for TDX quote artifacts.

## Deliverables

- `crates/ee-attestation/src/tsm.rs`
- Quote parse API
- Extraction for `MRTD`, `RTMRs`, and `report_data`
- Quote generation helper for CP/agent integration

## Test Gates

- Quote fixtures parse successfully
- Field offsets validated for `MRTD` and `RTMRs`
- Nonce recoverable from `report_data`

## Definition Of Done

- [ ] Parser handles valid fixtures
- [ ] Parser rejects malformed data safely
- [ ] Public API is documented and tested

## PR Checklist

- [ ] Fixture-based tests added
- [ ] Malformed-input tests added
- [ ] Extraction correctness tests added
