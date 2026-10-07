# ST5 remediation authoring-request live object identity

Issue: #783  
Pinned parent: #198 exact head `7f41af2dcbecd84eee7830cae8b05c6acecdb923`

## Boundary

`validate_future_remediation_authoring_request()` is the typed live-lineage
consumer for a remediation authoring request. The canonical producer returns an
exact frozen `FutureRemediationAuthoringRequest`.

The consumer must reject subclasses before rebuilding/comparing lineage. A
subclass is not a producer-emittable artifact and may override Python
`__eq__` / `__ne__` behavior used by the live-rebuild comparison.

## Acceptance contract

The regression module proves:

- an exact producer request remains accepted;
- an equality-spoofing subclass with otherwise canonical fields must fail
  closed;
- an equality-spoofing subclass with `execution_allowed=True` must also fail
  closed and cannot hide the contradictory authority field behind custom
  comparison behavior;
- repeated rejection leaves the caller-owned object unchanged.

The required source-owner repair is intentionally narrow: require exact runtime
identity (`type(request) is FutureRemediationAuthoringRequest`) before any
live rebuild/equality comparison. Do not normalize a subclass into the canonical
type.

## Non-overlap

This child is tests/docs only. Production ownership remains with #196/#198.

It does not replace or modify:

- #450 live-validation input/state atomicity;
- #628 persisted mapping/list/key exactness;
- #638 snapshot isolation;
- #640 parser purity;
- #583 raw JSON text typing;
- direct-constructor structural hardening;
- #782 evidence-bundle live-validator object identity.

## Safety

This is an in-process integrity/fail-closed contract only. It adds no model
call, target/network interaction, evidence collection, scanning, tool
execution, remediation/retest execution, deployment authority, future-state
resolution, security verdict, or attack-path mutation.
