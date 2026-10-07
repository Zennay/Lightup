# ST5 revised remediation proposal JSON text exactness

Issue: #588

The strict persisted revised-proposal JSON entry point must accept only an exact
built-in `str`. Canonical serialized text remains valid. A `str` subclass
with identical content must be rejected before string methods or JSON decoding,
without coercion or normalization.

Current #238 source uses `isinstance(raw, str)` followed by `raw.strip()`,
so the subclass rejection regression is intentionally RED until the source
owner absorbs an exact-type guard.

This branch adds one regression module and this document only and does not
modify the #238 source branch.
