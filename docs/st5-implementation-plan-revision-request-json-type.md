# ST5 implementation-plan revision-request JSON text exactness

Issue: #undefined

The strict persisted implementation-plan revision-request JSON entry point must
accept canonical producer text only as an exact built-in `str`. A subclass
with identical JSON must fail closed before string handling or decoding.

The current #501 handoff uses `isinstance(raw, str)` followed by
`raw.strip()`, so the subclass regression is intentionally RED until the
source owner absorbs the exact-type guard.

This tests/docs-only branch leaves #501 source untouched and is independent
from the existing sequence, schema-key, metadata, parser-purity, and
live-validation acceptance slices.
