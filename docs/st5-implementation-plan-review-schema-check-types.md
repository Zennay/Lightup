# ST5 implementation-plan review schema/check exactness

Issue: #608  
Parent: #283 exact head `996fa91daac86136caf2dc0c900c2edd84a0703b`

## Contract

The strict direct-object review parser must reject Python subclasses that JSON
persistence cannot produce while keeping both canonical producer forms valid:

- every top-level schema key is an exact built-in `str`;
- `checks` may be an exact built-in tuple from `as_dict()` or exact list
  from JSON decoding, but not a subclass;
- every nested check schema key is an exact built-in `str`;
- persisted `decision`, check names and check results are exact built-in
  strings, not equivalent-content subclasses;
- rejection leaves caller input unchanged.

## Current expected RED

#283 uses set equality for schemas, `isinstance(..., (list, tuple))` for the
check container, Enum conversion for decision and equality/membership for
check strings. Those operations admit or normalize equivalent subclasses.

## Collision boundary

#598 owns raw JSON text, #603 the top-level mapping container, #605
digest/provenance/summary scalar exactness, #305 schema erosion/non-object
substitutions and #493 live-validation atomicity. This slice deliberately does
not claim nested mapping-container identity or those scalar fields.

Tests/docs only; no #283 source, verifier behavior, target interaction or
execution authority changes.
