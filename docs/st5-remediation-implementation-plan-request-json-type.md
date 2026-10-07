# ST5 implementation-planning request JSON text exactness

Issue: #593

The strict persisted implementation-planning request JSON entry point accepts
only an exact built-in `str`. Canonical serialized request text remains valid.
A `str` subclass with identical content must be rejected before string methods
or JSON decoding, without coercion or normalization.

Current #230 source uses `isinstance(raw, str)` followed by `raw.strip()`, so
the subclass rejection regression is intentionally RED until the source owner
absorbs an exact-type guard.

This branch adds one regression module and this document only. It does not
modify #230 source, #492 dict-parser purity, or live-validation ownership.
