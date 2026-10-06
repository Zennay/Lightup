# ST5 evidence sufficiency attestation

This stage records the authorized operator's explicit judgment for the two
checks requested by the evidence sufficiency review handoff:

- whether the admitted evidence is sufficient for a later classification
  review; and
- whether the candidate evidence's classification **claim** is justified.

It does not select a LightUp classification and does not create a transition
resolution.

## Preconditions

Before an attestation exists,
`attest_future_security_evidence_sufficiency(...)` live-validates the exact
`FutureSecurityEvidenceSufficiencyVerifierPreflight`.

That preflight recursively validates the sufficiency-review request, metadata
contract review, freshness admission, freshness constraints, evidence request,
upstream ST4/ST5 lineage, candidate RunContext and current evidence ledger.

The same `Role.OPERATOR` authorization context/user identity bound by the
preflight must be used for the attestation.

## Exact dispositions

`EvidenceSufficiencyAttestationDisposition` has three values:

- `insufficient_for_classification`
  - `evidence_sufficient=false`
  - `classification_claim_justified=false`
  - `needs_more_evidence=true`
  - `eligible_for_classification_review=false`
- `sufficient_claim_unjustified`
  - `evidence_sufficient=true`
  - `classification_claim_justified=false`
  - `needs_more_evidence=false`
  - `eligible_for_classification_review=false`
- `sufficient_claim_justified`
  - `evidence_sufficient=true`
  - `classification_claim_justified=true`
  - `needs_more_evidence=false`
  - `eligible_for_classification_review=true`

The last flag means only that a **later** classification-review stage may be
created. It is not classification selection.

## Review state versus security outcome

Because this object is the explicit operator review result, it sets:

- `sufficiency_decision_created=true`;
- `evidence_sufficiency_evaluated=true`;
- `classification_justification_evaluated=true`.

It still hard-codes:

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

No disposition is therefore a LightUp security verdict or execution grant.

## Bounded provenance and persistence

The attestation binds the exact:

- client;
- sufficiency-review request and verifier-preflight digests;
- metadata-review and freshness-admission digests;
- source resolution/change/subject;
- candidate run/evidence/capability identities;
- candidate classification claim;
- verifier user identity;
- disposition and all derived flags.

`attestation_sha256` is deterministic over that bounded state.

Raw evidence metadata, source, payload, target details, arguments, credentials,
passwords and sessions are not copied into the attestation.

Persisted attestations must be rebuilt with
`validate_future_security_evidence_sufficiency_attestation(...)`. Any changed
verifier/preflight/upstream evidence lineage, forged derived flag, attempted
classification selection, transition creation or execution authority fails
exact equality.

This slice is stacked on draft PR #88. Exact-head hosted Python 3.11/3.14 plus
canonical `vps-bb300bba` proof remain required after dependencies land.
