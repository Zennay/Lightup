# ST5 remediation text proposal raw-response bound

Issue: #818

## Purpose

The remediation-advisor producer declares a 16,000-character model-output boundary.
That boundary must apply to the provider's raw response before normalization, not
only to the trimmed content that LightUp persists.

## Acceptance contract

This tests/docs-only child is pinned directly above source-owner PR #207 head
`eaf03f3b672867ef3a22107e3c03ceeaedfb5ef7`.

The regression proves:

- exactly 16,000 raw characters remain accepted;
- a 16,001-character raw response that becomes 16,000 characters only after
  `.strip()` fails closed with the bounded-output error;
- small ordinary surrounding whitespace still normalizes to canonical trimmed
  remediation prose;
- no code, tool, execution, target, future-state retest, deployment, or
  attack-path mutation authority is introduced.

## Expected pre-fix result

The exact-boundary and ordinary-whitespace controls are green. The oversized
raw-whitespace case is intentionally RED on the pinned #207 implementation,
because the current source checks length only after normalization.

## Ownership and collision boundary

This branch adds only this regression module and this contract document. It does
not modify `src/lightup/future_remediation_text_proposal.py` or any other
production source. PR #207 remains the sole source owner for the remediation
text proposal producer.

The source-owner fix should enforce the raw-response ceiling before calling
`.strip()`, while preserving the existing empty-content, NUL, model identity,
digest, and non-executable authority contracts.

## Safety

Repository-only defensive validation. No target interaction, evidence
collection, tool invocation, remediation execution, retest execution,
deployment, or attack-path mutation is added.
