# ST5 implementation-plan revision-request composed consumer persisted runtime types

Issue #804 isolates the outer persisted-input dispatch in
`load_and_validate_future_remediation_implementation_plan_revision_request()`
above exact #501 head `81cd78f074a777a0380672050082fd21616a447c`.

Canonical persistence reaches this boundary only as exact built-in JSON
`str` or exact built-in `dict`. Equal-content Python subclasses are
producer-impossible and must fail closed before parser dispatch, before
polymorphic string/mapping behavior can influence the strict parser or live
review-chain rebuild.

Exact built-in controls remain green; rejected subclass inputs remain unchanged.
The revision request stays planning-only: no revised plan is created or
accepted, and execution, target interaction, future-state retest, deployment
and attack-path mutation remain false.

#501 retains production source ownership. Existing #510/#516/#522/#537 and
parser-purity/live-validation/snapshot lanes retain direct persisted-field,
container and validation ownership. This tests/docs-only branch owns only the
outer composed consumer runtime-type dispatch.

The subclass cases are intentionally expected red until #501 absorbs a narrow
exact outer runtime-type guard. #511 is explicitly not part of this gap because
its revised-plan consumer already uses exact `type(...) is str/dict`
dispatch. No duplicate permanent CI is warranted while canonical runner
capacity remains occupied.
