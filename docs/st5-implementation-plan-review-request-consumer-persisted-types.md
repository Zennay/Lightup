# ST5 ImplementationPlanReviewRequest composed consumer persisted runtime types

Issue #801 isolates the outer persisted-input dispatch above exact
source-owner head `08dc953ed7fa9e38976be7d7f66a3ec381ae6124` (#280).

Canonical persistence reaches this composed consumer only as exact built-in
JSON `str` or exact built-in `dict`. Equal-content Python subclasses are
producer-impossible and must fail closed before parser dispatch, before
polymorphic string/mapping behavior can participate in strict parsing or live
lineage validation.

The acceptance regression keeps exact built-in JSON/object controls green and
proves rejected caller-owned subclass inputs remain unchanged. All
implementation/remediation execution, target interaction, future-state retest,
deployment and attack-path mutation authority remains fail-closed.

The source owner keeps production handoff ownership; existing direct-parser,
raw-JSON, parser-purity, snapshot and broader canonicality packs retain their
scopes. This branch owns only the outer composed persisted-consumer
runtime-type boundary and changes tests/docs only.

Subclass cases are intentionally expected red until the source owner absorbs a
narrow exact outer runtime-type guard. Canonical #62 self-hosted proof is still
queued, so no duplicate permanent runner job should be dispatched merely to
demonstrate this known-red partition.
