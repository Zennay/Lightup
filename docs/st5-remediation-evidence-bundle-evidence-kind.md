# ST5 remediation evidence bundle canonical evidence-kind acceptance

Issue #402 preserves the exact upstream ST4 evidence-kind contract when a
remediation-evidence bundle crosses the persisted #194 boundary.

## Producer contract

Live transition-resolution validation accepts only evidence records whose
`kind` is exactly `future-transition-verification`. The #60 remediation
bundle rereads that live evidence and copies its kind into each bounded evidence
reference.

The #194 persisted parser currently checks only that `kind` is a non-empty
string, so a caller can create typed persisted state that the canonical producer
cannot emit.

## Acceptance

Real INTRODUCED and WORSENED producer bundles are the positive controls and
confirm the canonical kind.

The negative case substitutes another non-empty kind and recomputes both the
item's `evidence_manifest_sha256` and the top-level `bundle_sha256`. Strict
persisted parsing must still fail closed. Alternative names are rejected rather
than normalized or aliased.

## Collision boundary

Tests/docs only, based directly on active #194. No #194 source/tests/docs are
modified.

This is distinct from #399 exact capability coverage, #401 resolution/effect
lineage, #319 snapshot isolation, and the upstream #60 live producer check.

## Safety

Persistence-integrity acceptance only. No evidence collection, target
interaction, tool execution, remediation/retest execution, deployment, verdict
creation, or attack-path mutation.
