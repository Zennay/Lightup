# ST5 remediation evidence-bundle container exactness

Issue: #578  
Parent: #194 exact head `ec4b09f539289fbf3b497a534980323bd3c11bef`

## Purpose

The strict persisted remediation evidence-bundle object parser accepts direct
Python objects in addition to raw JSON. JSON decoding naturally produces exact
built-in `dict` and `list` containers; direct callers can instead supply
subclasses with different behavior. A strict persisted boundary must not widen
that input model through polymorphic containers.

## Required contract

The direct object parser must require exact built-in containers at these layers:

- top-level bundle: exact `dict`;
- `items`: exact `list`;
- each remediation item: exact `dict`;
- nested `evidence`: exact `list`;
- each evidence reference: exact `dict`.

A canonical producer payload decoded through `json.loads` remains a green
control. Every subclass rejection must leave caller-owned input unchanged.

This contract intentionally does not cover the separate sequence-valued item
fields such as path/effect/capability identifiers; those remain outside this
slice to avoid colliding with existing path/capability ownership.

## Why the current parent is expected RED

At #194 head `ec4b09f539289fbf3b497a534980323bd3c11bef` the object parser uses
`isinstance(..., dict)` and `isinstance(..., list)` at these container
boundaries. Therefore subclasses are accepted even though they are not shapes
that raw JSON can produce.

The source owner should absorb this proof with exact container checks before
schema comparison, iteration or field access. Rejection is preferred over
normalization so the caller-visible object is never silently rewritten.

## Collision boundary

This slice is independent from #577 mapping-key exactness and does not modify:

- #194 / #60 production source or existing tests/docs;
- canonical identity/value bounds;
- cross-item lineage;
- path/capability ownership;
- snapshot-isolation and parser input-purity slices;
- scope authorization;
- execution, target interaction, remediation/retest execution or deployment;
- verdict creation or attack-path mutation.

## Safety

Persistence-integrity validation only. No model call, evidence collection,
network or target interaction, scan, tool execution, remediation, retest,
deployment, verdict creation or attack-path mutation.
