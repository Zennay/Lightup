# ST5 evidence-collection consumer persisted runtime types

Issue #747 isolates the runtime-type boundary at the persisted evidence-collection
consumer introduced by PR #136.

## Why this is separate from #611 / #746

#611 and the preferred #746 pack exercise the strict request parser owned by
#64. This acceptance sits one layer later: #136 first decides whether a caller
supplied JSON text or an already-decoded object before invoking the #64 parser
and live-lineage validator.

The canonical persisted forms are exact built-in values:

- `request.to_json()` returns an exact built-in `str`;
- `json.loads(request.to_json())` returns an exact built-in `dict`.

A Python `str` or `dict` subclass cannot be emitted by JSON persistence.
Accepting one therefore widens the consumer's input surface beyond its persisted
contract.

## Acceptance

The dedicated regression keeps both canonical forms green and requires
equal-content subclasses to fail closed at the outer consumer boundary:

- exact built-in JSON text: accepted;
- exact built-in decoded object: accepted;
- `str` subclass carrying byte-identical JSON: rejected;
- top-level `dict` subclass carrying the canonical decoded payload: rejected;
- rejected caller-owned values remain unchanged;
- a `str` subclass is rejected before `json.loads` is dispatched;
- a `dict` subclass is rejected before the strict #64 request parser is
  dispatched.

The pre-dispatch assertions are deliberate. They prove this consumer owns the
runtime-type boundary instead of relying on deeper parser behavior to reject an
in-process object that canonical persistence cannot produce.

On the pinned #136 source head these subclass cases are intentionally expected
RED because `_persisted_payload()` uses broad `isinstance` checks.

## Ownership and stop line

This branch adds tests and documentation only. PR #136 retains production source
ownership. It does not modify #64, #611/#746, snapshot isolation (#318),
parser-purity/rejection-purity (#323/#329), freshness/admission consumers, or the
classification-review boundary.

This is persistence-integrity acceptance only. It does not authorize evidence
collection, capability/tool selection, target interaction, remediation/retest,
deployment, classification, verdict creation, or attack-path mutation.
