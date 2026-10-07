# ST5 revised-remediation review snapshot isolation

Issue #629 proves public snapshot detachment above strict revised-remediation review handoff #248 at exact parent head `546716d6117918dbbb12a0720f7659b6a59ff002`.

## Invariant

The immutable typed review is the authority-bearing in-memory value. Public serialization helpers must expose detached data only:

- repeated `to_json()` is byte-for-byte deterministic;
- separately returned `as_dict()` values do not alias each other, including nested check mappings;
- mutating digest, summary, nested check result, execution authority or verdict fields in one snapshot cannot alter the typed review or later JSON;
- an untouched built-in programmatic snapshot still parses back to the exact review;
- authority-widened snapshots fail closed at the strict parser without parser-side mutation;
- once a caller-owned dictionary has been parsed, later caller mutation cannot rewrite the parsed typed review.

## Separation from existing owners

This is tests/docs only. #248 keeps strict persisted-review source ownership. #627 covers persisted Python object-type exactness, #458 covers live-validation atomicity, #250 covers the whole revision loop remaining non-executable, and #252 covers impossible direct typed construction.

## Safety

The regression reuses the existing deterministic in-memory revised-review fixture. It performs no external model/network call, target interaction, code/config application, tool/remediation/retest execution, deployment, security-verdict creation or attack-path mutation.
