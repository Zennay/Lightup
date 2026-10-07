# Durable coverage read integrity

Coverage facts can feed the current Security Twin directly through
`DomainStore.get_coverage()`. The durable consumer boundary must therefore
revalidate persisted rows instead of assuming every row was produced by the
current writer.

## Invariant

Before returning coverage for an engagement, LightUp verifies that every
persisted capability identifier still exists in the canonical capability
registry and every persisted status resolves to a canonical
`CoverageStatus`.

Any corrupt row fails the entire read closed. Validation is strictly read-only:
the invalid row is not normalized, deleted, or repaired. This preserves the
forensic state while preventing producer-impossible coverage from becoming a
trusted twin fact.

Canonical rows continue to round-trip unchanged.

## Dependency and scope

This branch is stacked on #871, which is stacked on #869. The parent slices
own producer validation; this child owns durable read revalidation only.

No Security Twin source, `coverage.py`, labsync, evidence-remediation,
activation, execution policy, target worker, or network-capable code is
modified.
