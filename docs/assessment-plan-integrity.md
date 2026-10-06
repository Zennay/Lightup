# AssessmentPlan integrity boundary

LightUp remains plan-only in Security Twin ST5. `AssessmentPlan` is planning metadata, not execution authority.

## Construction invariants

Every `AssessmentPlan`, including one constructed directly instead of through `Planner.build()`, fails closed unless all of these conditions hold:

- `execution_enabled` is exactly `False`;
- the scope decision uses a real boolean `allowed` value and a known `ScopeReason`;
- allowed and denied scope reasons are coherent;
- denied scopes carry no capability IDs;
- capability IDs are a tuple of unique, non-empty strings;
- every capability ID exists in the canonical capability registry;
- disabled capabilities are forbidden;
- `LAB_ONLY` capabilities are permitted only for loopback or private-lab scope reasons.

Public explicit-host and explicit-network plans can therefore contain planning capabilities only. Loopback/private-lab plans may contain planning and lab-only capabilities. No plan created by this boundary can grant execution, target interaction, remediation, retest, deployment, or attack-path mutation authority.

## Sequencing

This hardening is intentionally stacked on the exact head of the planner capability-boundary change from PR #204. It must remain a child until #204 lands. If the parent head changes, restack and re-prove this child before promotion.

The child changes the same legacy orchestrator module only after inheriting #204's completed planner narrowing; it does not modify the parent branch itself or any independently owned domain, state, execution-policy, activation, web, lab-worker, discovery, AI, or evidence-remediation surface.
