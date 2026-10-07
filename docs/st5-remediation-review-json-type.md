# ST5 remediation review JSON text exactness

Issue: #586

## Contract

The strict persisted review JSON entry point accepts only an exact built-in
`str`. Canonical producer JSON stays valid. A `str` subclass carrying the
same JSON text must be rejected before string methods or JSON decoding, with no
coercion or normalization.

Current #220 source uses `isinstance(raw, str)` followed by `raw.strip()`,
so the subclass rejection regression is intentionally RED until the source
owner absorbs an exact-type guard.

## Scope

This branch adds one regression module and this document only. It does not
modify #220 source or existing files and is separate from #582-#585.

## Safety

Persistence parsing only. No external systems are contacted and no action
authority is added.
