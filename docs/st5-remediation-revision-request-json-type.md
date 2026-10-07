# ST5 remediation revision-request JSON text exactness

Issue: #587

The strict persisted revision-request JSON entry point must accept only an exact
built-in `str`. Canonical producer JSON remains valid. A `str` subclass with
identical JSON text must be rejected before string methods or JSON decoding,
without coercion or normalization.

Current #231 source uses `isinstance(raw, str)` followed by `raw.strip()`,
so the subclass rejection regression is intentionally RED until absorbed by
the source owner.

This branch adds one regression module and this document only. It does not
modify #231 source and is separate from #460, #463, and #582-#586.

Persistence parsing only; no external systems are contacted and no action
authority is added.
