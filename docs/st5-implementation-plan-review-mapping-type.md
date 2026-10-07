# ST5 implementation-plan review mapping exactness

Issue: #undefined

The strict persisted implementation-plan review object parser must accept only
an exact built-in `dict`. Canonical producer snapshots remain valid. A
`dict` subclass carrying identical values must fail closed before schema
traversal, without coercion or normalization.

Current #283 source uses `isinstance(payload, dict)`, so the subclass
regression is intentionally RED until the source owner absorbs the exact-type
guard.

This tests/docs-only branch is distinct from #598 raw JSON text typing, #305
schema erosion, #493 live-validation atomicity, and existing review-semantic
owners.
