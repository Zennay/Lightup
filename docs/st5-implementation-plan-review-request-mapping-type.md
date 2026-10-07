# ST5 implementation-plan review-request mapping exactness

Issue: #undefined

The strict persisted implementation-plan review-request object parser must
accept only an exact built-in `dict`. Canonical producer snapshots remain
valid. A `dict` subclass carrying the same values must fail closed before
schema traversal, without coercion or normalization.

Current #280 source uses `isinstance(payload, dict)`, so the subclass
regression is intentionally RED until the source owner absorbs the exact-type
guard.

This branch adds one regression module and this document only. It is distinct
from #597 raw JSON text typing, #306 schema erosion, #489 parser input purity
and #487 live-validation atomicity.
