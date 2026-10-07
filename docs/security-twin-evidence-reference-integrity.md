# Security Twin evidence reference integrity

Issue #858 closes the typed-object evidence-lineage gap in the core Security Twin primitives.

## Scope

The following immutable model types all expose `evidence_refs`:

- `TwinFact`
- `TwinRelationship`
- `AttackStep`
- `AttackPath`

Before this change, only VERIFIED facts and relationships checked evidence **presence**. The container and members themselves were otherwise trusted.

## Canonical contract

Each primitive now validates the same narrow evidence-reference contract:

- the container is an exact built-in `tuple`;
- every member is an exact built-in `str`;
- every member is non-blank;
- references are unique;
- input is never trimmed, sorted, deduplicated or converted.

An empty tuple remains valid wherever evidence is optional. The existing stronger rule for VERIFIED facts and VERIFIED relationships remains unchanged: they still require at least one evidence reference.

## Why this belongs in the core model

Security Twin snapshots can be constructed from current-state projection, future-state materialization, change binding and other internal producers. Keeping the invariant on the primitive itself prevents any producer or direct constructor from introducing malformed evidence lineage and then binding it into snapshot validation or a stable digest.

This is intentionally independent from:

- domain persistence and read-side validation (#856/#857);
- lab finding intake/retest (#854/#849);
- ST5 remediation/retest evidence lineage;
- projection ordering semantics.

## Safety

The change only narrows immutable model validation. It performs no target interaction, evidence collection, capability execution, remediation/retest execution, deployment, verdict creation or attack-path mutation.
