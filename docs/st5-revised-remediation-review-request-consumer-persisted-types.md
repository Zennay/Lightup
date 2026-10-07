# ST5 revised-remediation review-request composed consumer persisted runtime types

Issue #797 isolates the outer persisted-input dispatch in
`load_and_validate_future_remediation_text_revision_review_request()` above
exact PR #244 head `7eb4f5f72f5656b5476ba8735d7e83ded06decf3`.

Only exact built-in JSON `str` and exact built-in `dict` are
producer-reachable persisted forms. Equal-content Python subclasses must fail
closed before parser dispatch so polymorphic behavior cannot enter strict
parsing or the complete live revised-proposal lineage rebuild.

Exact built-in controls remain green, rejected subclass inputs remain unchanged,
and the review request grants no remediation acceptance, execution, target,
retest, deployment or attack-path mutation authority.

PR #244 retains production source ownership. #626 owns direct parser object
exactness, #589 raw JSON typing, #631 parser purity, #632 snapshot isolation,
and #681 broader integrity composition. This tests/docs-only branch does not
alter production source, models, evidence collection, scope, targets,
remediation/retest execution, deployment, verdicts or attack paths.

Subclass cases are intentionally expected red until the source owner absorbs a
narrow exact outer runtime-type guard. No extra permanent self-hosted run should
be consumed solely for known-red acceptance while the shared LightUp queue is
occupied.
