# ST5 implementation-plan review-request JSON text exactness

Issue: #undefined

The strict persisted implementation-plan review-request JSON entry point must
accept canonical producer text only as an exact built-in `str`. A subclass
carrying identical JSON must fail closed before string handling or decoding.

The current #280 handoff uses `isinstance(raw, str)` followed by
`raw.strip()`, so the subclass regression is intentionally RED until the
source owner absorbs the exact-type guard.

This tests/docs-only branch does not modify #280 source and stays separate
from the existing parser-purity and live-validation acceptance work.
