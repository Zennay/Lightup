# ST5 remediation evidence bundle classification/path acceptance

Issue #400 preserves the upstream classification-dependent current-path
semantics when remediation-evidence bundles cross the persisted #194 boundary.

## Producer contract

Only INTRODUCED and WORSENED items are eligible for remediation authoring in
this bundle. Their current-path lineage has different meaning:

- INTRODUCED represents a new path hypothesis and cannot claim an existing
  current attack path;
- WORSENED represents increased risk on an existing path and therefore requires
  current attack-path lineage.

The canonical #60 producer copies these values from an already live-validated
transition resolution. The persisted parser must not admit a combination the
producer cannot emit merely because the public bundle digest was recomputed.

## Acceptance

Real INTRODUCED and WORSENED producer bundles remain positive controls.

Two forged payloads then recompute an exact matching `bundle_sha256`:

1. add a valid-looking current-path ID to an INTRODUCED item;
2. erase all current-path IDs from a WORSENED item.

Both must fail closed at strict persisted parsing. The handoff rejects rather
than normalizes or invents path lineage.

## Collision boundary

Tests/docs only, based directly on active #194. No #194 source/tests/docs are
modified.

This is distinct from #386 at the earlier remediation/retest-plan handoff and
from bundle-specific #398 positive versions and #399 exact capability coverage.

## Safety

Persistence-integrity acceptance only. No evidence collection, target
interaction, tool execution, remediation/retest execution, deployment, verdict
creation, or attack-path mutation.
