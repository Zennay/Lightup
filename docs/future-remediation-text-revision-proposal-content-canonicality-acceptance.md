# ST5 remediation revision-proposal content canonicality acceptance

Issue #443 isolates a narrow persisted-integrity mismatch above exact active
#238 head `ef38622caf8c63be34785f971d0526e85740b55d`.

## Producer invariant

The remediation revision-proposal producer rejects blank model output, then
executes `content = response.content.strip()` before computing both
`content_sha256` and `revision_proposal_sha256`.

Producer-created revision proposals therefore cannot contain leading or trailing
whitespace in `content`.

## Persisted-boundary gap

The strict #238 handoff currently calls `.strip()` on persisted `content`
before checking `content_sha256` and the full revision-proposal digest.

A persisted caller can therefore add outer whitespace while keeping the original
producer digests. The parser silently normalizes those bytes back to the
canonical producer value and accepts them.

## Acceptance contract

1. an untouched real producer revision proposal still round-trips;
2. leading-space persisted content fails closed;
3. trailing-space persisted content fails closed;
4. tab-wrapped persisted content fails closed;
5. forged cases keep the original producer `content_sha256` and
   `revision_proposal_sha256`;
6. the parser rejects noncanonical persisted bytes rather than normalizing them.

The expected source-owner fix is deliberately narrow: require persisted
`content == content.strip()` before typed construction. Existing non-empty,
NUL, size and digest checks remain unchanged.

## Collision and safety boundary

Tests/documentation only. No #238 source or existing tests are modified. This is
independent of #435/#436 revision-proposal model identity.

No scope/activation changes, target interaction, code/config application, tool
execution, remediation/retest execution, deployment, security verdict or
attack-path mutation is introduced.

Expected pre-fix state: canonical producer control green + exactly 3 RED content
whitespace cases per interpreter. Post-fix target: 3 RED -> 0 RED.
