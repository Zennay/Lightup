# ST5 remediation/retest positive-version acceptance

Issue #384 preserves the upstream twin-version contract at the persisted ST5
remediation/retest-plan boundary.

## Upstream contract

The ST3 transition proposal rejects `current_twin_version` and `twin_version`
when either value is below one. ST4 reporting and the ST5 remediation/retest
plan are derived from that validated live lineage, so zero is not a
producer-reachable version.

The exact #190 persisted parser currently treats these fields as non-negative
integers and therefore accepts zero.

## Acceptance

The regression starts from a real producer plan, replaces exactly one version
with zero, recomputes a matching canonical `plan_sha256`, and requires strict
persisted parsing to fail closed. This proves positive-version enforcement
independently of stale-digest rejection.

A canonical producer plan still round-trips unchanged.

## Parallel boundary

Tests/docs only. No #190 source modification and no overlap with identifier
canonicalization (#381), whitespace-only lineage (#377), cross-item lineage
(#378), or graph-action coherence (#375).

## Safety

Persistence-integrity only. No evidence collection, model invocation, target
interaction, tool execution, remediation/retest execution, deployment, verdict
creation, or attack-path mutation.
