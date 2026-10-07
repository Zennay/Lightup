# ST5 remediation revision-proposal composed consumer persisted runtime types

Issue #794 isolates the outer persisted-input dispatch in
`load_and_validate_future_remediation_text_revision_proposal()` above exact PR
#238 head `ef38622caf8c63be34785f971d0526e85740b55d`.

Canonical persistence reaches this boundary only as exact built-in JSON
`str` or exact built-in `dict`. Equal-content Python subclasses are
producer-impossible and must fail closed before parser dispatch. That prevents
polymorphic string/mapping behavior from influencing strict parsing or the
complete live revision-request/review/proposal lineage validation.

Exact built-in JSON/object controls remain green. Rejected subclass inputs must
remain unchanged. Revised remediation prose stays unaccepted and grants no
execution, target, retest, deployment or attack-path mutation authority.

PR #238 retains production source ownership. #625 owns direct parser object
exactness, #588 raw JSON typing, #645 parser purity, #633 snapshot isolation,
and #684 broader persisted-integrity composition. This branch is tests/docs
only and does not alter production source, model behavior, evidence collection,
scope, targets, remediation/retest execution, deployment, verdicts or attack
paths.

The subclass cases are intentionally expected red until the source owner
absorbs a narrow exact outer runtime-type guard. No additional permanent
self-hosted run is warranted solely for known-red acceptance while the shared
LightUp queue is occupied.
