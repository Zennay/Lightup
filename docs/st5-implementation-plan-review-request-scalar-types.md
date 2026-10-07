# ST5 implementation-plan review-request scalar exactness

Issue: #undefined

The strict persisted implementation-plan review-request object parser must not
widen JSON scalar identity when consuming direct Python objects. Canonical
built-in strings and integers remain valid, while subclasses carrying the same
values must fail closed.

This slice pins representative exact-type boundaries for SHA-256 lineage,
planner provenance, and the positive plan-item count. Authority booleans are
already identity-checked and are intentionally excluded.

Current #280 source uses `isinstance(..., str)` / `isinstance(..., int)` in
these paths, so the subclass regressions are intentionally RED until absorbed
by the source owner.

Tests/docs only; distinct from #597, #602, #306, #489 and #487.
