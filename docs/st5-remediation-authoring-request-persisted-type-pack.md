# ST5 remediation authoring-request persisted type acceptance pack

Source owner: #198  
Exact parent: `7f41af2dcbecd84eee7830cae8b05c6acecdb923`  
Mode: composition-only tests/docs acceptance

## Included contracts

This branch composes the persisted runtime type-fidelity contracts that share
the exact #198 source head:

- #583 — exact built-in raw JSON text;
- #628 — exact built-in mappings, lists and schema-key strings;
- #658 — exact built-in persisted non-boolean scalar values.

The #658 scalar slice exhausts top-level string/int values, item scalar strings,
entries from every item string-list family and all nested evidence strings.
Boolean lifecycle/authority fields already use identity checks and Python does
not permit subclassing `bool`.

## Excluded ownership

This pack does not absorb semantic/canonical-content owners, direct-constructor
hardening, snapshot isolation, parser purity, producer/live-validation
atomicity, implementation-planning, scope authorization, or target-capable
paths.

## Promotion use

Use this branch as one future acceptance overlay after the #198 source owner
absorbs exact-type guards. The target is for all type regressions to move from
expected RED to green without weakening the parent handoff, live revalidation,
digest checks or non-executable stop lines.

No PR/workflow/retrigger is required merely to preserve this composition while
permanent LightUp CI is occupied.

## Safety

No model invocation, evidence collection, target interaction, scanning,
remediation/retest execution, deployment, scope-authorization mutation,
security verdict creation or attack-path mutation.
