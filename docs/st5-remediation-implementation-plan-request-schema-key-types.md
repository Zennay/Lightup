# ST5 implementation-planning request schema-key exactness

Issue: #599

The strict direct-object parser must require every top-level schema key to be an
exact built-in `str`. Canonical producer dictionaries remain valid. Replacing
any one key with an equivalent-text `str` subclass must fail closed before
field access while leaving caller input unchanged.

Current #230 source compares `set(payload)` with the canonical key set. A
`str` subclass with the same hash/value therefore passes schema comparison
and can be addressed by the canonical string key, so the rejection regression
is intentionally RED until the source owner adds exact key-type validation.

#594 owns the outer mapping container, #596 scalar values, #592 raw JSON text,
and #492 general parser purity. This branch changes tests/docs only.
