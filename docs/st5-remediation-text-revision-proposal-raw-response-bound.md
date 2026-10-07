# ST5 revised remediation proposal raw-response bound

Issue: #819

## Purpose

The revised-remediation advisor declares a 16,000-character model-output
boundary. That limit must apply to the provider's raw response before
normalization, not only to the trimmed content retained by LightUp.

## Acceptance contract

This tests/docs-only child is pinned directly above source-owner PR #234 head
`7156a6dc00b79c1cfb87c2fe783a957e2e81ecf7`.

The regression proves:

- exactly 16,000 raw characters remain accepted;
- a 16,001-character raw response that becomes 16,000 only after `.strip()`
  fails closed with the bounded-output error;
- small ordinary surrounding whitespace still normalizes to canonical revised
  remediation prose;
- revised prose remains unaccepted and grants no code/tool/execution/target/
  retest/deployment/attack-path authority.

## Expected pre-fix result

The exact-boundary and ordinary-whitespace controls are green. The oversized
raw-whitespace case is intentionally RED on the pinned #234 implementation,
because source currently checks length only after normalization.

## Ownership and collision boundary

This branch adds only one regression module and this contract document. It does
not modify `src/lightup/future_remediation_text_revision_proposal.py` or any
other production source. PR #234 remains the sole source owner.

The source-owner fix should enforce the raw-response ceiling before calling
`.strip()`, while preserving the existing empty-content, NUL, role/model
identity, digest, revision-lineage, and non-executable authority contracts.

## Safety

Repository-only defensive validation. No target interaction, tool execution,
remediation/retest execution, deployment, verdict creation, or attack-path
mutation is added.
