# ST5 classification-review consumer persisted runtime types

Issue #780 isolates the outer persisted runtime-type boundary at the
classification-review request consumer introduced by PR #109.

## Why this is separate from #618

#618 owns exact built-in type requirements inside the direct strict #98
classification-review request parser. This acceptance sits at the later composed
consumer boundary, before strict parsing and mandatory live lineage validation.

Canonical persisted forms are exact built-in values:

- `request.to_json()` returns an exact built-in `str`;
- `json.loads(request.to_json())` returns an exact built-in `dict`.

Python `str` and `dict` subclasses cannot be emitted by canonical JSON
persistence. Accepting them widens the composed boundary beyond its persistence
contract before the final evidence-remediation live-validation stop line.

## Acceptance

The regression requires canonical forms to remain green while equal-content
`str` and top-level `dict` subclasses fail closed without rewrite or
mutation. Sentinels additionally prove rejection occurs before JSON decode or
strict classification-review parser dispatch.

On the pinned PR #109 source head these subclass cases are intentionally
expected RED because `_persisted_payload()` uses broad `isinstance` checks.

## Collision boundary

This branch adds tests/docs only and is pinned to PR #109 exact head
`ad7f54c7a94467eefbc1f9ef9582ac849cb08175`.

PR #109 retains production consumer source ownership. #618 retains direct parser
persisted-object exactness. #332/#334/#336/#340 retain consumer atomicity,
read-only and fail-fast ordering. #158/#159/#160/#161 retain the durable
evidence-remediation gate. Classification review itself remains out of scope.

## Safety

Persistence-integrity acceptance only. No classification decision, transition
resolution, evidence collection, target interaction, tool execution,
remediation/retest execution, deployment, verdict creation or attack-path
mutation.
