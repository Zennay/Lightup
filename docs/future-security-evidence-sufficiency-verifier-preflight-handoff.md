# Future security evidence sufficiency verifier preflight handoff

This ST5 handoff defines the strict serialization boundary for
`FutureSecurityEvidenceSufficiencyVerifierPreflight`.

The producer preflight proves only that an existing LightUp `Role.OPERATOR`
authorization context is eligible to perform a later independent evidence
sufficiency review. Persisting that object does not make the persisted JSON
trusted.

## Strict parsing boundary

`future_security_evidence_sufficiency_verifier_preflight_from_dict(...)`
requires:

- the exact v1 top-level schema;
- canonical non-empty identifiers;
- canonical lowercase SHA-256 values;
- non-empty, sorted and unique candidate evidence and capability identities;
- an existing `AttackPathTransitionClassification` value retained only as an
  evidence claim;
- `verifier_role=operator`;
- `eligible_for_sufficiency_review=true`;
- every decision, classification, resolution, collection, tool, execution,
  target, remediation, retest, deployment and attack-path authority flag to
  remain false;
- `future_semantics=unresolved` and
  `security_verdict=not_evaluated`;
- exact recomputation of `preflight_sha256`.

The parser rejects missing or extra fields, malformed types, non-canonical or
duplicate identities, unsupported classification claims, forged operator or
review-eligibility semantics, forged safety flags and digest drift.

## Live validation remains mandatory

Successful parsing proves serialization integrity only. Before any later review
stage consumes a persisted preflight, it must still call
`validate_future_security_evidence_sufficiency_verifier_preflight(...)`
against the live sufficiency request, the current verifier authorization
context, the full upstream ST4/ST5 lineage and the current `StateStore`.

That live rebuild is what detects stale request/evidence lineage or a changed
verifier identity. A parser round trip can never create an evidence-sufficiency
decision, select a security classification, create a transition resolution, or
grant target/execution/remediation/retest/deployment authority.

## Safety boundary

This package is serialization integrity only. It performs no evidence
collection, target interaction, tool invocation, sufficiency decision,
classification selection, remediation authoring, retest execution, deployment
or attack-path mutation.
