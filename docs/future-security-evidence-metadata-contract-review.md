# ST5 candidate evidence metadata-contract review

This stage sits after freshness admission. It answers one narrow question:

**Does the already-admitted candidate evidence carry one internally consistent
instance of the existing ST4 transition-verification metadata contract?**

It does not answer whether the evidence is sufficient to close the gap and it
does not select or accept a security classification.

## Live validation first

Before inspecting metadata,
`review_future_security_evidence_metadata_contract(...)` calls
`validate_future_security_evidence_freshness_admission(...)`. The candidate
admission therefore remains bound to the live freshness constraints, request,
upstream ST4/ST5 lineage, candidate lab RunContext and current evidence ledger.

Every admitted evidence record is then re-read from `StateStore`.

## Evidence requirements

Each candidate record must:

- belong to the exact admitted candidate run;
- keep the exact admitted evidence/capability identity;
- use kind `future-transition-verification`;
- carry a supported `classification` metadata value;
- agree with every other admitted record on that classification claim;
- satisfy every key/value in the existing
  `future_attack_path_transition_evidence_contract(...)` for that claim,
  proposal item and candidate RunContext.

The classification value remains an **evidence claim**. The review stores it as
`candidate_classification_claim`; it does not turn it into a selected LightUp
classification.

## Output semantics

A successful review means only:

- freshness admission was live-valid;
- transition-verification metadata was present and internally consistent;
- the metadata claim is compatible with the existing proposal review action;
- all required ST4 metadata values match the canonical contract.

Hard fail-closed semantics remain:

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

The bounded export contains lineage IDs, the evidence IDs/capabilities, the
metadata classification claim, fixed safety semantics and `review_sha256`.
It does not copy raw evidence metadata, source, payload, target details,
arguments or credentials.

## Persistence

Persisted reviews must be rebuilt with
`validate_future_security_evidence_metadata_contract_review(...)` before use.
Metadata drift therefore fails closed even when the freshness admission itself
still matches, because freshness fingerprints intentionally do not contain raw
metadata.

Dependency chain for this draft:

`#62 -> #64 -> #66 -> #68 -> #71 -> #72 -> #76`.

No merge or promotion is valid until upstream dependencies land and the exact
head has fresh hosted Python 3.11/3.14 plus canonical `vps-bb300bba` proof.
