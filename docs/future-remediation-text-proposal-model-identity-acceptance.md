# ST5 remediation-text proposal model identity acceptance

Issue #427 isolates a narrow persisted-integrity mismatch above exact active
#209 head `38c40d112751728c238dcf5d7ab556079528c38e`.

## Producer invariant

The model gateway normalizes a role binding with `model_id.strip()`. Proposal
generation then requires the model response identity to equal that exact bound
model ID before constructing `FutureRemediationTextProposal`.

As a result, the producer path cannot emit a persisted proposal whose
`model_id` has leading or trailing whitespace.

The strict #209 persisted parser is currently weaker: its generic non-empty
string predicate accepts that whitespace. Because `proposal_sha256` is a
public deterministic digest, a persisted caller can change `model_id`,
recompute the digest, and still pass structural parsing.

## Acceptance

The regression contract requires:

1. an untouched real producer proposal still round-trips;
2. leading-space `model_id` fails closed;
3. trailing-space `model_id` fails closed;
4. tab-wrapped `model_id` fails closed;
5. each forged case recomputes matching `proposal_sha256`, so stale-digest
   rejection cannot satisfy the contract;
6. the parser rejects rather than silently stripping persisted input.

## Deliberate non-claim

This contract does not impose the same rule on `provider_id`. Current provider
registration accepts a nonblank provider key without an equivalent normalization
guarantee, so strengthening that field here would outrun the producer contract.

## Collision and safety boundary

Tests/documentation only. No #209/#207 source or existing tests are modified.
No scope/activation changes, target interaction, code/config application, tool
execution, remediation/retest execution, deployment, security verdict or
attack-path mutation is introduced.

Until #209's source owner absorbs this one-field persisted invariant, the
canonical producer control should stay green and the three forged cases should
remain expected RED. Post-fix target: 3 RED -> 0 RED.
