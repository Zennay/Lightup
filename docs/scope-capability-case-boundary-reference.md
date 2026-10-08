# Capability identifier case-sensitivity: offline reference boundary

Status: proposed acceptance contract, **not** production authorization enforcement.

Risk: case-insensitive comparisons, Unicode casefolding, normalization and
whitespace trimming can map an unapproved capability spelling onto an approved
one. This may silently widen a tenant's permitted operations.

Proposed invariant: the authorization owner chooses and documents an
issuance-time canonical vocabulary. After trusted issuance, admission and
dispatch must compare the exact approved canonical capability ID; neither
request-side Unicode transformations nor a permissive equality override may
turn an unapproved spelling into permission. Reject malformed, oversized,
non-string or noncanonical identifiers rather than guessing their intent.

The reference tests model lexical membership only; they deliberately do not
claim that case variants are invalid in every possible future vocabulary. A
production owner must define canonical IDs and apply the policy at issuance,
admission, live revalidation and final dispatch.

Run offline: `python -m unittest discover -s tests -p 'test_scope_capability_case_reference.py'`

No DNS, network, targets, scans, handlers, approvals, deployments or grants.
Do not interpret a passing reference test as active-target authorization.
Production executor remains owned by #107; no source file modified.
