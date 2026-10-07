# ST5 remediation/retest-plan persisted object type exactness

Issue #620 isolates one persistence-integrity boundary above strict remediation/retest-plan handoff #190 at exact parent head `c554baaa0c6570f2e7b5affd9e7d68e2c9c22c13`.

## Contract

The canonical direct-object control is `json.loads(plan.to_json())`. JSON decoding can only produce built-in dictionaries, lists, strings, integers, booleans and null values. The programmatic `future_security_remediation_retest_plan_from_dict` entry point must therefore not accept Python subclasses that persisted JSON could never produce.

The acceptance regression requires fail-closed rejection for equivalent-content subclasses at these boundaries:

- top-level plan mapping and nested item mappings;
- top-level and nested schema keys;
- the top-level `items` list;
- item string-list containers and their string entries;
- identifiers and lineage SHA-256 strings;
- fixed schema/future/verdict metadata strings;
- classification, graph-action and next-action persisted enum strings;
- twin-version and aggregate-count integers.

Canonical JSON-decoded producer state must continue to parse to the exact typed plan. Rejection must leave caller-owned input value-equivalent to its pre-call snapshot.

## Separation from existing owners

This slice is tests/docs only and does not modify #190 source.

- #609 separately owns the raw JSON text-type boundary.
- Existing JSON-envelope, duplicate-key and nested-integrity packs retain their scopes.
- Parser-purity, live-lineage validation, snapshot isolation and direct typed-object construction remain separate.
- Scope authorization and target-capable behavior are out of scope.

## Safety

This is a persistence-type fidelity proof only. It performs no target interaction, evidence collection, capability/tool selection, remediation or retest execution, deployment, security-verdict creation, or attack-path mutation. All existing fail-closed action-authority semantics remain unchanged.

## Expected state

The exact #190 parser currently uses broad `isinstance` checks, schema equality, enum conversion and list iteration at several of these boundaries. The new acceptance module is intentionally expected RED until the #190 source owner absorbs exact built-in type guards.
