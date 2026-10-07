# ST5 revised-remediation review persisted-consumer exactness

Issue: #831  
Source owner: PR #248  
Pinned parent: `546716d6117918dbbb12a0720f7659b6a59ff002`

## Contract

The composed revised-remediation review consumer is a persistence boundary.
Canonical persistence can produce either:

- exact built-in JSON text (`type(value) is str`), or
- an exact built-in JSON-decoded object (`type(value) is dict`).

Equal-content Python subclasses cannot be emitted by canonical JSON persistence.
They are therefore producer-impossible inputs and must fail closed before parser
selection or live-lineage validation.

The acceptance proof keeps both canonical forms green and requires equal-content
`str` and `dict` subclasses to raise. Rejection must leave the caller-owned
persisted value and durable state unchanged.

## Expected RED on source-owner head

PR #248 currently dispatches with broad `isinstance(..., str)` /
`isinstance(..., dict)` checks. The subclass rejection tests are intentionally
RED on the pinned source-owner head until #248 absorbs the narrow exact-type
repair.

## Collision boundary

This branch adds only:

- `tests/test_future_remediation_text_revision_review_consumer_subclasses.py`
- this contract document.

It does not modify PR #248 production source or existing tests. It does not
touch revision proposal/request ownership, evidence collection, scope
authorization, model execution, target interaction, remediation/retest
execution, deployment, verdict creation, or attack-path mutation.
