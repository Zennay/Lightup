# Legacy Finding evidence integrity acceptance

Issue: #894

This acceptance slice isolates the in-memory evidence boundary on
`lightup.models.Finding` without modifying the active `models.py` source
owner.

## Boundary

`Finding.validate()` is the validation gate used by markdown reporting. The
current implementation validates finding identity, title, target and
remediation, but does not validate the runtime shape of `evidence`.

Canonical evidence for this legacy object is:

- an exact built-in `list`;
- containing exact built-in `str` items;
- with each item non-blank after whitespace inspection;
- or the existing exact empty list, which remains supported so reporting can
  render its explicit `No evidence recorded.` fallback.

The gate must reject rather than normalize:

- `list` subclasses;
- tuples or other sequence/container types;
- `str` subclasses;
- non-string items;
- empty or whitespace-only evidence strings.

Rejected inputs remain caller-owned and unchanged.

## Expected state

The dedicated acceptance regression is intentionally RED on exact current
`main` `1abc16a66fc490b1ba7272890dfbf498482fca9c`: the current validator does
not inspect `evidence`, so malformed containers/items pass validation.

A later source-owner repair should add only the narrow evidence validation
needed to satisfy this contract. It must not alter authorization, target
scope, evidence collection, remediation/retest execution, deployment,
security verdicts or attack-path state.

## Collision boundary

`src/lightup/models.py` is actively touched by scope-authorization owner
#100. This branch therefore contains tests and documentation only.

This acceptance is separate from durable finding evidence intake/read
contracts (#851/#856), labsync evidence intake (#848/#850/#853/#854), and
Security Twin evidence-reference integrity.

## Safety

Pure in-memory validation and rendering only. No DNS, network or target
interaction; no scanning; no evidence collection; no capability, remediation
or retest execution; no deployment; no verdict creation; no attack-path
mutation.
