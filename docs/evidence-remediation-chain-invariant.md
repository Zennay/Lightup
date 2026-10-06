# Evidence-remediation end-to-end invariant

This integration proof fixes one product-level safety invariant for the ST5
unresolved evidence path:

> Complete freshness coverage is not evidence sufficiency, gap closure, a
> classification, or authority to act.

The proof executes the current isolated-lab chain:

1. insufficient-evidence remediation/retest plan;
2. fail-closed evidence collection request;
3. freshness constraints that forbid the prior evidence and run identities;
4. admission of live `StateStore` evidence from a genuinely new lab run;
5. aggregate freshness coverage;
6. strict persisted coverage round-trip.

## Required lineage

The integration test requires exact digest continuity:

- constraints reference the exact collection request digest;
- admission references the exact request and constraints digests;
- coverage references those exact request and constraints digests;
- the covered item references the exact live admission digest.

The admitted candidate evidence is read back from `StateStore` and must belong
to the new candidate run. Reuse of the prior run/evidence identities remains
forbidden by the upstream constraints/admission gates.

## Safety invariant

Even when every unresolved gap has a fresh candidate and
`all_gaps_have_fresh_candidates=true`, both the live coverage object and its
strict serialized round-trip must retain:

- `evidence_sufficiency_evaluated=false`;
- `gap_closed=false`;
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

The request, constraints and admission are also rechecked for action-authority
flags, and the current twin plus upstream request/constraints are compared
before and after the successful chain to prove they remain immutable.

This proof uses only isolated test/lab state. It performs no real-target
interaction, credential use, exploit execution or tool dispatch.
