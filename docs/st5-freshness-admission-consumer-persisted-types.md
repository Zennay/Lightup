# ST5 freshness-admission consumer persisted runtime types

Issue #763 isolates the outer persisted runtime-type boundary at the
freshness-admission consumer introduced by PR #141.

## Why this is separate from #613

#613 owns exact built-in type requirements inside the direct strict #72
admission parser. This acceptance sits at the later composed consumer boundary,
before strict parsing and live validation.

Canonical persisted forms are exact built-in values:

- `admission.to_json()` returns an exact built-in `str`;
- `json.loads(admission.to_json())` returns an exact built-in `dict`.

Python `str` and `dict` subclasses cannot be emitted by canonical JSON
persistence. Accepting them widens the composed boundary beyond its persistence
contract.

## Acceptance

The regression requires canonical forms to remain green while equal-content
`str` and top-level `dict` subclasses fail closed without rewrite/mutation.
Sentinels additionally prove rejection occurs before JSON decode or strict
admission-parser dispatch.

On the pinned PR #141 source head these subclass cases are intentionally
expected RED because `_persisted_payload()` uses broad `isinstance` checks.

## Collision boundary

This branch adds tests/docs only and is pinned to PR #141 exact head
`cfa22936bb2e3fc95665a0a032143d708a4568fe`.

PR #141 retains production source ownership. #613 retains direct parser
persisted-object exactness. The #128/#131/#136 consumer lanes remain separate.

## Safety

Freshness-admission persistence integrity only. Freshness does not establish
suitability/sufficiency, classification, transition, collection, tool/target
execution, remediation/retest, deployment, verdict, or attack-path authority.
