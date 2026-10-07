# ST5 revised-remediation review composed consumer persisted runtime types

Issue #798 isolates the outer persisted-input dispatch in
`load_and_validate_future_remediation_text_revision_review()` above exact PR
#248 head `546716d6117918dbbb12a0720f7659b6a59ff002`.

Canonical persistence reaches the composed review consumer only as exact
built-in JSON `str` or exact built-in `dict`. Equal-content Python
subclasses are producer-impossible and must fail closed before parser dispatch
so polymorphic string/mapping behavior cannot influence strict parsing or live
revised lineage validation.

Exact built-in controls remain green. Rejected subclass inputs remain unchanged.
An approved revised prose review may retain `remediation_accepted=true`, but
execution, target interaction, future-state retest, deployment and attack-path
mutation remain false.

PR #248 retains production source ownership. #627 owns direct parser object
exactness, #591 raw JSON typing, #630 parser purity, #629 snapshot isolation,
and #679 broader integrity composition. This tests/docs-only branch does not
alter production source, model behavior, evidence collection, scope, targets,
remediation/retest execution, deployment, verdicts or attack paths.

Subclass cases are intentionally expected red until the source owner absorbs a
narrow exact outer runtime-type guard. No extra permanent self-hosted run should
be consumed solely for known-red acceptance while the shared LightUp queue is
occupied.
