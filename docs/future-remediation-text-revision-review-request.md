# Future remediation text revision review request

This ST5 boundary requests another independent review after a revised
remediation-text proposal has passed its strict persisted handoff.

The review request binds the exact revised-proposal, revision-request,
prior-review and revised-content digests plus the revision model provenance. It
uses the same fixed four-check rubric as the initial remediation-text review:
evidence alignment, unsupported claims, least privilege and future-retest
separation.

The builder performs no model call. The revised proposal must first pass the
complete live revision-proposal handoff, which transitively validates the
revision request, prior review, original proposal and current evidence lineage.

review_requested is true, but remediation_accepted remains false. Code/config
generation, tool calls, target interaction, remediation execution, future-state
retest, deployment, attack-path mutation, future-state resolution and security
verdict authority all remain unavailable.
