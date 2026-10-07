# Future remediation implementation plan

This ST5 slice creates a structured **planning artifact** after the remediation
text has passed independent review and the implementation-planning request has
passed its strict live handoff.

## Model boundary

The existing provider-neutral `remediation_advisor` role receives only:

- the exact implementation-request/review/proposal lineage;
- the accepted remediation proposal text;
- the verifier summary;
- bounded remediation-item identifiers/classification/effect/capability data;
- evidence identifiers and SHA-256 references.

StateStore evidence source/metadata, credentials, authorization references and
target arguments are not included.

The model must return one strict JSON object with a bounded summary,
`plan_items`, assumptions and unresolved questions. Each plan item contains
only:

- a unique planning ID;
- a constrained change-area category;
- implementation intent;
- verification intent;
- rollback intent.

Unexpected top-level or plan-item keys are rejected. This deliberately gives
the output no field for patches, diffs, commands, tool arguments or target
arguments.

## Authority stop line

Successful generation advances only
`implementation_plan_created=true`. It does **not** authorize a code/config
change, tool call, target interaction, remediation execution, future-state
retest, deployment or attack-path mutation. Future semantics stay
`unresolved` and the security verdict stays `not_evaluated`.

The plan is evidence-bound guidance for a later, separately gated implementation
proposal boundary; it is not itself an executable remediation.
