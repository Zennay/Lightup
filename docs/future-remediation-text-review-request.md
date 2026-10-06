# Future remediation text review request

This ST5 contract asks for independent review of a remediation text proposal
that has already passed the strict persisted proposal handoff and live lineage
validation.

The request binds the reviewer to the exact:

- authoring request SHA-256;
- remediation evidence bundle SHA-256;
- remediation proposal SHA-256;
- model content SHA-256;
- provider/model provenance;
- remediation item count.

The required checks are fixed to evidence alignment, unsupported claims,
least-privilege guidance, and separation between proposal authoring and any
future-state retest.

## Authority boundary

The review request deliberately contains no remediation body, patch, command,
tool arguments, target arguments, credentials, evidence source or arbitrary
evidence metadata.

It only requests review. It does not record a review decision and
`remediation_accepted` remains false. Code-change, tool-call, execution,
target-interaction, future-state-retest, deployment and attack-path-mutation
authority remain false. Future semantics remain unresolved and the security
verdict remains `not_evaluated`.
