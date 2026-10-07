# ST5 metadata-review consumer persisted runtime types

This tests/docs-only acceptance isolates the outer persisted runtime-type boundary
at the evidence metadata-contract review consumer introduced by PR #145.

#614 owns exact built-in type requirements inside the direct strict persisted
parser. This later composed consumer boundary must itself accept only canonical
JSON persistence forms: exact built-in `str` text or exact built-in `dict`
object input.

The regression keeps canonical producer text/object forms green and requires
equal-content `str` / `dict` subclasses to fail closed before JSON decode or
strict-parser dispatch, without mutating caller-owned input.

On exact PR #145 head `e2a64382a55289a45cf74aedf6e0f65f04126e04`
these subclass cases are intentionally expected RED because
`_persisted_payload()` uses broad `isinstance` checks.

PR #145 retains production source ownership. #614 retains direct-parser
exactness; #774 retains ordering/atomicity/read-only consumer acceptance; and
#157/#159/#161 retain evidence-remediation dependency/gate ownership.

Safety remains persistence/live-validation integrity only. No classification
decision, transition resolution, evidence collection, target interaction, tool
execution, remediation/retest execution, deployment, verdict creation or
attack-path mutation.
