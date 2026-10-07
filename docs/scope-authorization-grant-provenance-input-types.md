# Canonical grant-provenance input contract

This acceptance slice pins the runtime string boundary for durable grant
approval/reference provenance above exact #554 head
`4c8d5651fc0e23f94514daae56b4e5fe0549de37`.

## Invariant

`DomainStore.record_authorization_grant()` currently reads both
`approved_by` and `reference` twice through `.strip()`:

1. once to decide whether provenance is non-blank;
2. again while constructing the object that is persisted.

String annotations do not prevent a `str` subclass from overriding
`.strip()`. A stateful subclass can therefore return a non-empty value during
the guard and an empty value during construction, minting a durable grant with
blank provenance.

Grant issuance must require exact built-in strings, trim those deterministic
values once, require the canonical results to be non-empty, and persist those
same canonical results.

## Acceptance proof

`tests/test_scope_authorization_grant_provenance_input_types.py` provides:

- a built-in string green control proving ordinary surrounding whitespace is
  trimmed before persistence;
- a benign `str` subclass rejection;
- an `approved_by` subclass that is non-blank on the validation read and blank
  on the persistence read;
- an equivalent `reference` substitution;
- durable row snapshots proving rejected provenance cannot create a grant row.

Against exact #554 source, the subclass cases are intentionally expected RED.
The stateful cases explicitly inspect any accidentally persisted row and catch
blank durable provenance.

## Separation from existing owners

- #475/#471/#554 validate provenance after it already exists in durable state.
- #177 owns binding grant provenance to an approved assessment request.
- legacy `models.Authorization` provenance work remains separate.
- This contract owns only the raw issuance input type/value coherence before a
  durable grant is minted.

## Collision boundary

Tests/documentation only. No changes to `src/lightup/domain.py`, execution
policy/orchestration, evidence remediation, or target-capable source.

## Safety

Temporary SQLite and in-process grant construction only. No DNS/network I/O,
target interaction, scanning, exploit behavior, capability execution,
remediation/retest execution, deployment, verdict creation, or attack-path
mutation.
