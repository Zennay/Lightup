# Remediation authoring-item direct-construction integrity

`FutureRemediationAuthoringRequestItem` is planning metadata inside an ST5
remediation authoring request. Its persisted handoff already requires both
lifecycle markers to be true:

- `remediation_required`
- `future_state_retest_required`

Direct in-memory construction now enforces the same rule. Both fields must be
the exact boolean `True`; false values and integer lookalikes such as `1`
fail closed.

This prevents caller-created nested items from weakening the remediation/retest
contract before a later strict handoff or live-lineage validation.

The change is integrity-only. It adds no tool call, target interaction,
remediation execution, retest execution, deployment authority, future-state
resolution, security verdict, or attack-path mutation.
