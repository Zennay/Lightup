# ST5 candidate evidence freshness admission

This package checks only whether candidate evidence is **new enough to be
considered later**. It does not decide whether that evidence is sufficient,
does not classify an attack-path transition, and does not authorize collection,
tool use, target interaction, remediation, retesting or deployment.

## Preconditions

`admit_future_security_evidence_freshness` first live-revalidates the exact
`FutureSecurityEvidenceFreshnessConstraints` against the evidence collection
request, ST4/ST5 lineage and current StateStore.

The caller identifies one exact source resolution and supplies evidence IDs that
already exist in the ledger plus an immutable candidate `RunContext`.

The candidate context must:

- be `LAB_AUTONOMOUS`;
- have `is_lab=true`;
- belong to the same client and engagement as the source resolution;
- use a run ID that is not in the freshness constraint's forbidden run IDs.

The candidate evidence IDs must be non-empty, sorted, unique and disjoint from
the forbidden prior evidence IDs.

## Live ledger binding

Every candidate evidence record is re-read from `StateStore` and must:

- belong to the exact candidate run;
- retain canonical non-empty evidence/run/capability/kind identities;
- retain a canonical lowercase SHA-256 digest.

Capability IDs are **derived** from the live candidate evidence. They are not
preselected by this contract and they are not required to match the prior
capabilities that produced insufficient evidence.

The exported fingerprints contain only:

- evidence ID;
- run ID;
- capability ID;
- kind;
- SHA-256.

Raw source, metadata, payloads, targets, arguments and credentials are omitted.

## What a successful admission means

`freshness_check_passed=true` means only that the submitted evidence is not
the previously insufficient evidence and did not come from a previously
forbidden run.

It explicitly does **not** mean the evidence is suitable for a security
conclusion:

- `evidence_suitability_evaluated=false`
- `classification_selected=false`
- `transition_resolution_created=false`
- `security_verdict=not_evaluated`

A later independent verification step must decide whether the evidence satisfies
the existing transition-evidence metadata contract and what classification, if
any, is justified.

## Persistence and drift

The canonical `admission_sha256` binds the exact freshness constraints,
candidate run, evidence fingerprints, derived capabilities and all safety flags.

Persisted admissions must be passed through
`validate_future_security_evidence_freshness_admission`. The validator
rebuilds the admission against the live ledger and requires exact equality.

## Safety boundary

- `collection_authorized=false`
- `tool_call_created=false`
- `execution_allowed=false`
- `target_interaction_allowed=false`
- `remediation_authoring_allowed=false`
- `future_state_retest_allowed=false`
- `deployment_authorized=false`
- `attack_path_mutation_allowed=false`
- `future_semantics=unresolved`
- `security_verdict=not_evaluated`

Refs #69.
