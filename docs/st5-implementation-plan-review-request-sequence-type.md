# ST5 implementation-plan review-request sequence exactness

Issue: #undefined

The strict persisted implementation-plan review-request object parser must not
normalize polymorphic sequence containers. Canonical built-in
`required_checks` sequences remain valid, while a list subclass carrying the
same values must fail closed before iteration or tuple conversion.

Current #280 source uses `isinstance(raw_checks, (list, tuple))` and then
`tuple(raw_checks)`, so the subclass regression is intentionally RED until
the source owner absorbs an exact-container guard.

Tests/docs only; distinct from #597, #602, #604, #306, #489 and #487.
