# ST5 remediation revision-request composed consumer persisted runtime types

Issue #793 isolates the outer persisted-input dispatch in
`load_and_validate_future_remediation_text_revision_request()` above exact PR
#231 head `30ebbd9f335bcbbc0ab076d344b79d94be8434e6`.

Canonical persistence reaches this boundary only as an exact built-in JSON
`str` or exact built-in `dict`. Equal-content Python subclasses must fail
closed before parser dispatch so polymorphic string/mapping behavior cannot
participate in the strict parse or subsequent live review-chain rebuild.

The regression keeps exact built-in JSON/object controls green and proves
rejected subclass inputs remain caller-owned and unchanged. Revision-request
authority remains planning-only: remediation acceptance, execution, target
interaction, future-state retest, deployment and attack-path mutation stay
false.

PR #231 retains production source ownership. #624 owns direct parser
persisted-object exactness, #587 raw JSON typing, #644 parser purity, #634
snapshot isolation, and #687 broader persisted-integrity composition. This
branch is tests/docs only and does not change model behavior, evidence
collection, scope, target interaction, remediation/retest execution,
deployment, verdicts or attack paths.

The subclass cases are intentionally expected red until the source owner
absorbs a narrow exact outer runtime-type guard. No additional permanent
self-hosted run is warranted solely to prove known-red acceptance while the
shared LightUp queue is occupied.
