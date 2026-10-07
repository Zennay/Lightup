# ST5 remediation-review composed consumer persisted runtime types

Issue #789 isolates the outer persisted-input boundary of
`load_and_validate_future_remediation_text_review()` above exact PR #220 head
`82126cfccdcef85f51cd5d34cdcccfb05ebe8270`.

## Contract

Canonical persistence has only two supported runtime shapes at this boundary:

- exact built-in JSON `str` from `FutureRemediationTextReview.to_json()`;
- exact built-in `dict` from the programmatic persisted-object representation.

Python subclasses of either type are producer-impossible polymorphic objects.
They must fail closed **before** parser dispatch. That prevents overridden string
or mapping behavior from participating in strict parsing or later live-lineage
validation.

The acceptance regression also proves the rejected caller-owned object remains
unchanged. Canonical exact built-in controls must keep round-tripping with the
same reviewed-prose-only stop line: `remediation_accepted` may be true, while
execution, target interaction, retest, deployment and attack-path mutation
remain false.

## Ownership boundary

This is tests/docs only.

- PR #220 keeps production consumer source ownership.
- #623 keeps direct parser persisted-object exactness.
- #586 keeps raw JSON parser input typing.
- #453 keeps live-validation input/state atomicity.
- #688/#716 keep broader review integrity/canonicality composition.

The expected source-owner fix is deliberately narrow: reject non-exact outer
persisted runtime types before selecting either parser. This branch does not
change source code, review decisions, remediation/retest execution, scope,
targets, deployment, verdicts or attack paths.

## Expected proof posture

The exact built-in controls are expected green on #220. The two subclass cases
are intentionally expected red until #220 absorbs the exact-runtime-type guard.
No extra permanent self-hosted workflow should be created merely to demonstrate
that known red partition while the shared LightUp queue is occupied.
