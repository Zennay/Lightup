# ST5 remediation evidence-bundle persisted type acceptance pack

Source owner: #194  
Exact parent: `ec4b09f539289fbf3b497a534980323bd3c11bef`  
Mode: composition-only tests/docs acceptance

## Included contracts

This branch composes the independent persisted type-fidelity contracts that
share the exact #194 source head:

- #577 — exact built-in schema-key strings;
- #578 — exact built-in mapping/list containers;
- #579 — exact built-in fixed metadata/classification strings;
- #580 — exact built-in SHA-256 strings;
- #581 — exact built-in count integers;
- #582 — exact built-in raw JSON text;
- #663 — exact built-in remaining lineage/evidence strings.

Each source slice keeps its own dedicated regression and contract document. The
pack intentionally copies those files without modifying #194/#60 production
source.

## Excluded ownership

This pack does not absorb or redefine:

- #398 positive twin-version semantics/exact-integer requirement;
- #399 capability-set binding;
- #400 classification/current-path presence;
- #401 resolution/effect lineage semantics;
- #402 evidence-kind value semantics;
- #405/#407 canonical identifier content and ordering;
- #429 cross-item ownership;
- direct-construction, snapshot, parser-purity or live-validation owners.

Those remain independent contracts and should not be conflated with persisted
runtime type fidelity.

## Promotion use

Use this branch only as a future acceptance overlay after the #194 source owner
absorbs the corresponding exact-type guards. The target is that all dedicated
type regressions move from expected RED to green while the canonical #194
handoff and its safety stop lines remain green.

No PR/workflow/retrigger is required merely to preserve this composition while
permanent LightUp CI is occupied.

## Safety

No model invocation, evidence collection, target interaction, scanning,
remediation/retest execution, deployment, scope-authorization mutation,
security verdict creation or attack-path mutation.
