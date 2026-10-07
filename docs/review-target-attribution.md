# AI review target attribution

Issue: #847  
Parent: #846 remediation-advisor evidence context

## Problem

Planner-driven assessments can review findings from multiple concrete targets.
The verifier and remediation-advisor requests already receive the finding-local
target, but the reviewed finding object previously dropped that value. As a
result, serialized review output and the report synthesizer saw only the
aggregate run-level target label.

That loses the asset binding required to interpret remediation safely in a
multi-target assessment.

## Contract

The review pipeline now preserves the exact target value already selected for
each finding:

- an explicit finding `target` remains attached to the corresponding
  `ReviewedFinding`;
- `ReviewResult.to_dict()` serializes that target per finding;
- report-synthesizer finding context carries the same target;
- finding ordering and the existing title, severity, verdict and remediation
  fields remain unchanged;
- when a finding has no local target, the existing run-level `target` /
  `targets` fallback is preserved exactly;
- no new target is inferred, resolved or contacted.

The aggregate top-level report target label remains unchanged for backwards
compatibility. Per-finding target attribution is additive.

## Regression coverage

`tests/test_review_target_attribution.py` proves:

1. two findings from different loopback targets preserve their individual
   targets through the immutable review result, serialized output and report
   request; and
2. a single-target finding without its own target preserves the pre-existing
   run-level fallback.

## Safety

Metadata preservation only. This change adds no network or target interaction,
scope/authorization widening, evidence collection, tool execution,
remediation/retest execution, deployment, security-verdict authority or
attack-path mutation.
