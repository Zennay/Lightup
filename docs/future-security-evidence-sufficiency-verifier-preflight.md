# ST5 evidence sufficiency verifier preflight

This stage creates the authorization preflight for the independent evidence
sufficiency review requested by the preceding ST5 handoff.

It proves only that an existing LightUp authorization context is eligible to
perform that later review. It does not accept a sufficiency decision.

## Authorization boundary

The verifier must be an `AccessContext` whose role is `Role.OPERATOR`.
The implementation calls `AccessContext.require_operator(...)` after the
source sufficiency-review request has been live-revalidated.

`CLIENT_ADMIN` and `CLIENT_MEMBER` contexts therefore fail closed.

The verifier `user_id` must also be a canonical, non-empty identifier without
leading/trailing whitespace or control characters.

`AccessContext` is an authorization context. This preflight deliberately does
not claim to implement or prove authentication itself.

## Live lineage first

Before verifier eligibility exists,
`preflight_future_security_evidence_sufficiency_verifier(...)` calls
`validate_future_security_evidence_sufficiency_review_request(...)`.

That recursively validates the metadata-contract review, freshness admission,
freshness constraints, evidence request, upstream ST4/ST5 lineage, candidate
RunContext and current evidence ledger.

A stale or forged sufficiency-review request therefore cannot gain verifier
eligibility.

## Output

The immutable preflight binds:

- client ID;
- sufficiency-review request SHA-256;
- metadata-review and freshness-admission SHA-256 values;
- source resolution/change/subject identities;
- candidate run/evidence/capability identities;
- candidate classification only as an untrusted evidence claim;
- verifier user ID and fixed verifier role `operator`;
- deterministic `preflight_sha256`.

The bounded export copies no raw evidence metadata, source, payload, target,
arguments, credentials, passwords or sessions.

## What eligibility does not mean

A successful preflight sets only
`eligible_for_sufficiency_review=true`.

It retains:

- `sufficiency_decision_created=false`;
- `evidence_sufficiency_evaluated=false`;
- `classification_selected=false`;
- `transition_resolution_created=false`;
- `collection_authorized=false`;
- `tool_call_created=false`;
- `execution_allowed=false`;
- `target_interaction_allowed=false`;
- `remediation_authoring_allowed=false`;
- `future_state_retest_allowed=false`;
- `deployment_authorized=false`;
- `attack_path_mutation_allowed=false`;
- `future_semantics=unresolved`;
- `security_verdict=not_evaluated`.

Persisted preflights must be rebuilt through
`validate_future_security_evidence_sufficiency_verifier_preflight(...)`.
Changed request lineage, verifier identity or forged decision/authority flags
fail exact equality.

This slice is stacked on draft PR #83. The serialized request handoff tracked
separately in #84 is not modified here. Exact-head hosted Python 3.11/3.14 and
canonical `vps-bb300bba` proof remain mandatory after dependencies land.
