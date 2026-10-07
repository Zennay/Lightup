# ST5 implementation-plan JSON text exactness

Issue: #595

The strict persisted implementation-plan JSON entry point accepts canonical
producer JSON, but the caller-provided JSON value must be an exact built-in
`str`. A subclass carrying identical text must be rejected before string
handling or JSON decoding.

The current #237 handoff checks `isinstance(raw, str)` before `raw.strip()`.
The subclass regression is therefore intentionally RED until the source owner
absorbs the exact-type guard.

This branch adds one regression module and this contract document only. It
does not modify the handoff source and remains separate from existing
parser-purity, nested-schema, and live-validation work.
