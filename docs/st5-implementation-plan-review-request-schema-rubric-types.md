# ST5 implementation-plan review-request schema/rubric exactness

Issue: #606  
Parent: #280 exact head `08dc953ed7fa9e38976be7d7f66a3ec381ae6124`

## Contract

The strict direct-object review-request parser must preserve the same type shape
that real persistence can produce:

- every top-level schema key is an exact built-in `str`;
- `required_checks` may be an exact built-in tuple from `as_dict()` or an
  exact built-in list from JSON decoding;
- list/tuple subclasses are rejected rather than normalized;
- every rubric entry is an exact built-in `str`;
- rejection does not mutate caller-owned input.

Both canonical tuple and JSON-list forms remain green.

## Current expected RED

#280 validates schema keys through set equality and accepts rubric containers
through `isinstance(raw_checks, (list, tuple))`, then immediately calls
`tuple(raw_checks)`. Equivalent-text key/check subclasses compare equal to
canonical strings, so polymorphic persisted state can pass or be normalized.

## Collision boundary

#597 owns raw JSON text, #602 the top-level mapping container, #604
SHA/provenance/count scalars, #489 parser purity and #487 live-validation
atomicity. This branch changes tests/docs only; no #280 source or model/target
behavior is modified.
