# ST5 verifier-preflight consumer persisted runtime types

This tests/docs-only acceptance isolates the outer persisted runtime-type
boundary at the evidence sufficiency-verifier preflight consumer introduced by
PR #150.

#616 owns exact built-in type requirements inside the direct strict persisted
parser. This later composed consumer boundary must itself accept only canonical
JSON persistence forms: exact built-in `str` text or exact built-in `dict`
object input.

The regression keeps canonical producer text/object forms green and requires
equal-content `str` / `dict` subclasses to fail closed before JSON decode or
strict-parser dispatch, without mutating caller-owned input.

On exact PR #150 head `05fa52659f7b7d44bc87d737429d6e719e9a769a`
these subclass cases are intentionally expected RED because
`_persisted_payload()` uses broad `isinstance` checks.

PR #150 retains production source ownership. #616 retains direct-parser
exactness; #770 retains ordering/atomicity/read-only consumer acceptance; and
#157/#159/#161 retain evidence-remediation dependency/gate ownership.

Safety remains persistence/live-validation integrity only. No classification
decision, transition resolution, evidence collection, target interaction, tool
execution, remediation/retest execution, deployment, verdict creation or
attack-path mutation.
