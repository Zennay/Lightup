# ST5 remediation review-request JSON text exactness

Issue: #585
Parent: #215 exact head `8b332b6e652a56c32974721cf251fe2056acc6f4`

## Contract

The strict raw-JSON entry point must accept only an exact built-in `str`.
Canonical producer JSON remains valid. A `str` subclass carrying identical
JSON text must be rejected before string methods or JSON decoding. The input is
not coerced or normalized.

Current #215 source uses `isinstance(raw, str)` followed by `raw.strip()`,
so the subclass rejection test is intentionally RED until the source owner
absorbs an exact-type guard.

## Scope

This branch adds one regression module and this document only. It does not
modify #215 source or existing files, and is separate from #459 live-validation
atomicity, #462 builder atomicity, and #582-#584.

## Safety

Persistence parsing only. No external systems are contacted and no action
authority is added.
