# Phase 13 - ee-agent

Status: Not started

## Goal

Build the in-VM agent binary for registration, tunnel runtime, and workload lifecycle.

## Deliverables

- Agent mode implementation
- CP-bootstrap mode implementation
- Registration and heartbeat clients
- Workload deploy/undeploy execution
- Local log/stats endpoints and buffering

## Test Gates

- Registration retry behavior
- Heartbeat cadence and payload validation
- Deploy/undeploy process management tests
- Log buffer behavior tests
- CP-bootstrap subprocess start test

## Definition Of Done

- [ ] Agent can register and heartbeat against CP
- [ ] Workload lifecycle is stable
- [ ] Mode selection works via config

## PR Checklist

- [ ] Agent runtime implemented
- [ ] HTTP server endpoints implemented
- [ ] Process supervision logic tested
