# ST5 implementation-plan review scalar exactness

Issue: #undefined

The strict persisted implementation-plan review object parser must preserve
exact JSON scalar identity when direct Python objects are supplied. Canonical
built-in strings remain valid, while subclasses carrying the same digest,
reviewer-provenance or summary text must fail closed.

Current #283 helpers use `isinstance(..., str)` on these paths, so the
subclass regressions are intentionally RED until the source owner absorbs
exact-type guards.

Decision/check semantics and authority booleans are deliberately excluded.
Tests/docs only; distinct from #598, #603, #305 and #493.
