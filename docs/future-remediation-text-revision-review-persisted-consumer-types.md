# Revised-remediation review persisted consumer runtime types

Issue: #831

## Purpose

The strict revised-remediation review handoff accepts persisted JSON text or a
programmatic persisted object before it revalidates the complete live review
lineage. Canonical persistence can produce only exact built-in `str` and
JSON-decoded built-in `dict` values.

Python subclasses with equal content are producer-impossible polymorphic inputs.
The outer composed consumer should therefore reject them before dispatching to
either strict parser.

## Acceptance contract

`tests/test_future_remediation_text_revision_review_persisted_consumer_types.py`
proves:

- exact built-in serialized JSON remains accepted;
- exact built-in programmatic dictionaries remain accepted;
- a `str` subclass fails before the JSON parser is invoked;
- a top-level `dict` subclass fails before the direct parser is invoked;
- rejection leaves caller-owned persisted input unchanged;
- the review's planning-only authority stop line remains unchanged.

The branch is pinned directly to PR #248 exact head
`546716d6117918dbbb12a0720f7659b6a59ff002`.

## Collision boundary

This is tests/docs-only acceptance work. PR #248 retains all production source
ownership for the persisted revised-review consumer. PR #246 retains revised
review producer ownership. Upstream revision request/proposal handoffs,
scope-authorization work, and target-capable code are not modified.

## Safety

Persistence-integrity narrowing only. No model invocation, target interaction,
scanning, evidence collection, remediation/retest execution, deployment,
security verdict creation, or attack-path mutation.
