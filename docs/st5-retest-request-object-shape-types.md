# ST5 persisted retest-request object-shape exactness

Issue: #610  
Parent: #359 exact head `51ef9d8574e69c2f82c3f9635b508e835a822177`

## Purpose

The strict retest-request handoff already requires exact built-in text for raw
JSON and for most persisted string values. The direct-object parser still uses
Python `isinstance` checks and schema set equality at several container and
primitive boundaries that JSON decoding cannot produce as subclasses.

## Required contract

The canonical control is `json.loads(request.to_json())`. It remains valid.
The parser must reject, before normalization or field traversal:

- a top-level `dict` subclass;
- equivalent-text `str` subclasses for every top-level schema key;
- an `items` list subclass;
- a nested item `dict` subclass;
- equivalent-text `str` subclasses for every nested item schema key;
- list subclasses for top-level requested capability/evidence IDs;
- list subclasses for item current-path/effect/evidence/capability IDs;
- `int` subclasses for current/future twin versions;
- an equivalent-content `str` subclass for fixed `schema_version`.

Rejection must leave caller-owned persisted input unchanged.

## Current expected RED

At the current #359 head, top-level/nested mappings use
`isinstance(..., dict)`, list containers use `isinstance(..., list)`, schema
keys rely on set equality, version fields use `isinstance(..., int)`, and
`schema_version` is checked by value equality. These checks admit Python
subclasses that real JSON persistence cannot emit.

## Collision boundary

This is direct persisted-object shape only. #356/#357 own earlier request
snapshot work, #363 parser purity, #387 positive-version semantics, #388
cross-item current-path ownership, #389 canonical item ordering, #391
resolution-ID shape and #394 direct typed-object construction.

Tests/docs only. No #359 source, scope authorization, target interaction,
retest execution, deployment, verdict creation or attack-path mutation.
