# ST5 remediation/retest JSON text exactness

Issue: #609  
Parent: #190 exact head `c554baaa0c6570f2e7b5affd9e7d68e2c9c22c13`

The strict raw JSON entry point must accept only an exact built-in `str`.
Canonical producer JSON remains valid. A `str` subclass carrying identical
JSON text must be rejected before decoding and must not be coerced or
normalized.

Current #190 source uses `isinstance(raw, str)`, so the subclass rejection
regression is intentionally RED until absorbed by the source owner.

This contract is separate from #374 outer JSON-envelope/content validation,
nested duplicate/schema integrity, parser input purity, live-validation
atomicity and producer-invariant acceptance branches. Tests/docs only; no
production/source or authority change.
