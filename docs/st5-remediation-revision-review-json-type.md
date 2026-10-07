# ST5 revised remediation review JSON text exactness

Issue: #591
Parent: #248 exact head `546716d6117918dbbb12a0720f7659b6a59ff002`

The strict persisted revised-remediation review JSON entry point accepts only an
exact built-in `str`. Canonical serialized review JSON remains valid. A
`str` subclass with identical content must be rejected before string methods
or JSON decoding, without coercion or normalization.

Current #248 source uses `isinstance(raw, str)` followed by `raw.strip()`,
so the subclass rejection regression is intentionally RED until the source
owner absorbs an exact-type guard.

This branch adds one regression module and this document only. It does not
modify #248 source or #458 live-validation atomicity work.
