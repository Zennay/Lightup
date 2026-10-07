# ST5 implementation-plan revision-request schema key types

## Scope

This tests/docs-only acceptance slice is a child of strict implementation-plan
revision-request handoff #501.

- exact parent head: `81cd78f074a777a0380672050082fd21616a447c`
- acceptance issue: #540
- production/source changes: **0**

It is separate from #510 mapping-object typing, #516 provenance, #522 SHA
scalars, #536/#537 sequence containers, #538/#539 persisted fixed metadata
values, #506 parser input-purity, #507 live-validation atomicity, #486 builder
atomicity, #528-#531 direct-object types, and #534/#535 snapshot isolation.

## Invariant

An exact persisted dictionary must also use exact built-in string keys before
schema equality or any field lookup.

The current #501 parser checks `set(payload) == _REVISION_REQUEST_KEYS`.
A `str` subclass carrying the same canonical key text inherits compatible
hashing/equality, so it passes the schema-set comparison and can be looked up
through the canonical built-in string. JSON decoding cannot produce that
polymorphic key type, so accepting it makes the programmatic dict path broader
than the serialized persistence path.

The regression requires:

- an exact built-in dict with exact built-in string keys remains accepted;
- any top-level string-key subclass fails closed before schema equality/reads;
- rejection does not normalize or mutate the caller-owned dictionary.

## Authority stop line

This is persistence-integrity only. It creates no revised plan and authorizes
no code/config change, tool call, execution, target interaction, remediation,
retest, deployment, attack-path mutation, future-state resolution, or security
verdict.

## Safety

No model invocation, target interaction, scanning, tool/remediation/retest
execution, deployment, verdict creation, or attack-path mutation.
