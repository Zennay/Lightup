# ST5 remediation evidence-bundle effect ordering acceptance

Issue #666 pins one narrow persisted-integrity invariant above the active
remediation evidence-bundle handoff in PR #194.

## Invariant

The producer lineage emits effect identifiers in canonical lexical order.
Persisted effect_ids must preserve that order. A caller must not be able to
reorder the same canonical-looking identifier set, recompute the outer bundle
digest, and have the strict handoff accept the alternate representation.

The acceptance regression therefore keeps the canonical producer control green,
then supplies at least two distinct canonical-looking effect identifiers in
reverse lexical order and recomputes bundle_sha256. The strict persisted
parser must reject that payload before it can become a typed remediation
evidence bundle, and rejection must leave caller-owned input unchanged.

## Ownership boundary

This branch is an acceptance-only child of exact PR #194 head
ec4b09f539289fbf3b497a534980323bd3c11bef.

It changes no production source. PR #194 remains the owner for the eventual
minimal parser repair. Existing branches keep ownership of effect identifier
shape/lineage, capability and current-path ordering, scalar/container exact
types, schema keys, JSON input types, and live-validation atomicity.

## Safety

This is persistence-integrity coverage only. It does not invoke a model, collect
new evidence, interact with targets, generate or apply code/config changes,
execute remediation/retests, deploy, create a security verdict, or mutate attack
paths. All execution and target-authority stop lines remain unchanged.
