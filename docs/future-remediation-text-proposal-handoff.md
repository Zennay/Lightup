# Future remediation text proposal handoff

This boundary persists and reloads model-generated remediation prose without
turning that prose into action authority.

## Strict persisted contract

The handoff rejects:

- missing or unknown fields;
- duplicate raw JSON keys before last-value-wins decoding;
- bool/int confusion for the item count;
- empty provider, model or content values;
- non-canonical SHA-256 values;
- content digest drift;
- proposal digest drift;
- widened authority flags;
- resolved future semantics or a precomputed security verdict.

After structural validation it immediately revalidates the exact upstream
remediation-authoring request against the live evidence bundle, remediation
plan, ST4 report/preview/proposal/resolutions, run contexts and StateStore. A
persisted text proposal whose request/bundle lineage is no longer live-valid is
therefore rejected before follow-up use.

## What this proves — and what it does not

The SHA-256 values provide deterministic integrity and lineage binding for the
persisted proposal. They do not independently attest that an external provider
authored the bytes; provider/model IDs remain provenance recorded by the
producer. No model is re-invoked during handoff validation.

The accepted object still carries no authority to:

- change code or configuration;
- create or invoke a tool call;
- interact with a target;
- execute remediation;
- perform a future-state retest;
- deploy a change;
- mutate an attack path.

The future state remains unresolved and the security verdict remains
`not_evaluated`.
