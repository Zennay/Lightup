# Future remediation text revision proposal

This ST5 slice performs one bounded rewrite of remediation prose after an
independent review has explicitly returned revision_required.

The implementation consumes the strict persisted revision-request handoff
before any model invocation. That transitively revalidates the review,
review-request, original proposal and live evidence lineage.

## Model input boundary

The existing provider-neutral remediation-advisor role receives only:

- the revision-request identifier;
- prior review/proposal/content digests;
- the canonical non-pass review-check names;
- the bounded review summary;
- the prior remediation prose.

State-store source payloads, metadata, credentials, authorization references
and target arguments are not exported. All supplied prose and identifiers are
treated as untrusted data, never as instructions.

## Output boundary

The revised prose records provider/model provenance, a content digest and a
canonical revision-proposal digest. It is deliberately marked unaccepted.

No code/config generation, tool call, target interaction, remediation
execution, future-state retest, deployment, future-state resolution, attack
path mutation or security verdict is authorized. Another independent review is
required before revised text could become accepted prose.
