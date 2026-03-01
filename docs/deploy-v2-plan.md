# Deploy V2 Plan (Reset)

_Last updated: March 1, 2026_

## Purpose

This is the new source of truth for deployment rollout work.

It replaces the previous multi-workflow rollout path that became too large and hard to debug.

## Ground Rules

- Build from scratch, step-by-step.
- Keep workflows explicit and short.

## Fixed Decisions (Already Made)

- Greenfield rollout.
- Staging and production run on GCP.
- Use real TDX nodes.

## Success Criteria

- A PR to `main` performs a clear staging rollout with readable logs.
- A merge/push to `main` performs a clear production rollout with readable logs.
- Each rollout has a short, deterministic set of steps.
- Failures show exact failing command and reason without deep log archaeology.
- As we launch agents lets see if we can get the logs into the build

## Step Plan

### Step 1: Delete everything

Status: `completed`

Deliverables:

- Delete nearly all of .github/workflows
- You can leave the github pages

Done when:

- No staging/production deployment workflow triggers automatically from legacy files.

---

### Step 2: Write and lock the new plan (this document)

Status: `completed`

Deliverables:

- Create `docs/deploy-v2-plan.md`.
- Capture goals, constraints, and execution order.

Done when:

- Plan is reviewed and accepted as the rollout source of truth.

---

### Step 3: Minimal staging CI->CD deploy entrypoint

Status: `in_progress`

Deliverables:
- No hidden nested orchestration.

Scope:

- Steps: lint -> test -> prepare GCP image -> deploy staging -> smoke check.
- Deploy CP VM on GCP and a VM for one tiny TDX agent 
- Wait for `/health` and one verified agent and cp.

Done when:

- Command succeeds locally/in-CI and outputs a short summary.

---
### Step 5: Minimal production workflow

Status: `pending`

Deliverables:

- Trigger: merge/push to `main`.
- Same flow as staging with prod env/secrets.

Done when:

- Production deploy is deterministic and readable.

---

### Step 6: Basic test + runbook

Status: `pending`

Deliverables:

- One deploy smoke test checklist.
- One operator runbook for manual verification.

Done when:

- A human can verify rollout health in under 5 minutes.

## Non-Goals (For This Reset)

- Billing redesign.
- Capacity marketplace logic.
- Advanced autoscaling/reconciliation.
- Refactoring unrelated control-plane APIs.

## Tracking Rules

- Every step gets one PR (or one tightly scoped PR series).
- If a step grows beyond ~200 lines of workflow/script changes, split it.

## Immediate Next Action

Finish **Step 3** with one fully green PR staging run using the new minimal workflow, then capture the exact runbook checks from that run.
