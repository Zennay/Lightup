# ST5 revised remediation review-request JSON text exactness

Issue: #589
Parent: #244 exact head `7eb4f5f72f5656b5476ba8735d7e83ded06decf3`

The strict persisted revised review-request JSON entry point must accept only an
exact built-in `str`. Canonical serialized text remains valid. A `str`
subclass with identical content must be rejected before string methods or JSON
decoding, without coercion or normalization.

Current #244 source uses `isinstance(raw, str)` followed by `raw.strip()`,
so the subclass rejection regression is intentionally RED until absorbed by
the source owner.

This branch adds one regression module and this document only and does not
modify #244 source.
