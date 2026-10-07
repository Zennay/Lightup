# ST5 freshness-coverage consumer persisted runtime types

Issue #755 isolates the outer persisted runtime-type boundary at the
freshness-coverage consumer introduced by PR #128.

## Why this is separate from #619

#619 owns exact built-in type requirements inside the strict coverage parser.
This acceptance sits one layer later: #128 first decides whether a caller
supplied JSON text or an already-decoded object before invoking that parser and
the live-lineage validator.

Canonical persisted forms are exact built-in values:

- `coverage.to_json()` returns an exact built-in `str`;
- `json.loads(coverage.to_json())` returns an exact built-in `dict`.

Python `str` and `dict` subclasses cannot be emitted by canonical JSON
persistence. Accepting them widens the composed consumer boundary beyond the
persisted contract.

## Acceptance

The regression requires:

- exact built-in JSON text and decoded object forms remain accepted;
- an equal-content `str` subclass is rejected without rewrite and before
  `json.loads` dispatch;
- an equal-content top-level `dict` subclass is rejected without mutation and
  before strict coverage-parser dispatch.

On the pinned PR #128 source head these subclass cases are intentionally
expected RED because `_persisted_payload()` uses broad `isinstance` checks.

## Collision boundary

This branch adds tests and documentation only and is pinned to PR #128 exact
head `fd5f9c39ae2f1d268b72359b904dc93b1e5e4a57`.

PR #128 retains production source ownership. #619 retains direct parser
persisted-object exactness. #748/#754 belong to the separate freshness-
constraints consumer and are not modified here.

## Safety

Freshness-coverage persistence integrity only. It does not authorize evidence
suitability/sufficiency decisions, classification, transitions, collection,
target interaction, remediation/retest execution, deployment, verdict creation,
or attack-path mutation.
