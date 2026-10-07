# Remediation review persisted-consumer runtime-type contract

Tracking: GitHub issue #789.

This acceptance slice covers only the **outer composed persisted consumer**
`load_and_validate_future_remediation_text_review()` above exact PR #220 head
`82126cfccdcef85f51cd5d34cdcccfb05ebe8270`.

## Required boundary

Canonical persistence can supply only:

- exact built-in JSON text (`type(value) is str`); or
- an exact built-in decoded/programmatic mapping (`type(value) is dict`).

Equal-content subclasses are producer-impossible runtime shapes and must fail
closed **before** dispatch to either the JSON parser or direct object parser.
The consumer must not normalize those values into accepted persistence.

The canonical `review.to_json()` and `review.as_dict()` forms remain valid.

## Why this is separate

This is not the direct parser contract. Issue #623 owns nested persisted-object
exactness inside `future_remediation_text_review_from_dict()`, while #586
owns raw JSON parser typing inside
`future_remediation_text_review_from_json()`.

This contract is one level outside both: the composed consumer must choose a
parser only for exact producer-emittable persisted container types.

## Safety stop line

This acceptance work does not create or alter a review decision. An approved
review still means remediation prose passed review only. It does not authorize
code/config changes, tool calls, execution, target interaction, retesting,
deployment, security verdicts, or attack-path mutation.

The slice is tests/docs only. PR #220 retains all production-source ownership.
