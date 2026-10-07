# ST5 implementation-planning request JSON text exactness

Issue: #undefined

The strict persisted implementation-planning request JSON entry point must
accept only an exact built-in `str`. Canonical producer JSON remains valid.
A `str` subclass with identical JSON text must be rejected before string
methods or JSON decoding, without coercion or normalization.

Current #230 source uses `isinstance(raw, str)` followed by `raw.strip()`,
so the subclass rejection regression is intentionally RED until absorbed by
the source owner.

This branch adds one regression module and this document only. It does not
modify #230 source and remains separate from #482 live-validation atomicity,
#492 parser input purity, and downstream plan-generation ownership.

Persistence parsing only; no external systems are contacted and no action
authority is added.
