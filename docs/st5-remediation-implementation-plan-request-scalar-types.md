# ST5 implementation-planning request scalar exactness

Issue: #596

## Contract

The strict persisted #230 object parser accepts only exact built-in scalar
types for fixed metadata, SHA-256 lineage/digest fields, reviewer provenance,
and the positive item count.

Canonical producer values remain valid. Equivalent-content `str` subclasses
and positive `int` subclasses must be rejected rather than normalized into
canonical typed state. Authority booleans already use identity checks and are
not part of this slice.

## Current expected RED

Current #230 helpers use `isinstance(value, str)` for digests/provenance,
`isinstance(value, int)` for the count, and value equality for fixed metadata.
Those checks admit scalar subclasses.

## Collision boundary

Top-level mapping exactness is #594, raw JSON text exactness is #592, parser
input purity is #492. This branch changes tests/docs only and does not modify
#230 source, live validation or downstream implementation planning.
