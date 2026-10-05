# ST5 GitHub Check publication contract

This slice advances issue #45 after the ST5 CI verdict policy was proven and
merged. It defines the fail-closed boundary between a live-revalidated
`FutureSecurityCIVerdictDecision` and a future GitHub Checks adapter.

It does **not** add a live GitHub API adapter yet.

## Why this boundary exists

A serialized verdict is not trusted by itself. Before a publication request can
be built, LightUp independently recomputes the exact ST5 CI verdict from the ST4
report, graph-diff policy decision, preview, transition proposal/resolutions,
run contexts, policy, and live StateStore. A stale, tampered, cross-tenant, or
lineage-drifted decision fails closed.

Publication also requires an explicit
`GitHubCheckPublicationAuthorization` bound to exactly:

- client;
- GitHub `owner/repo`;
- exact 40-hex source revision;
- exact ST5 verdict SHA-256;
- reporting permission.

The authorization must not grant merge or deployment capability.

## Deterministic request

The request binds repository/source SHA, twin lineage, ChangeSet, ST4 report
digest, ST5 policy digest, verdict digest, verdict, CI conclusion, and check
name into a canonical request SHA-256. That digest becomes the deterministic
`external_id`.

The only conclusion mapping remains:

- PASS -> `success`
- PASS_WITH_WARNING -> `neutral`
- REVIEW_REQUIRED -> `action_required`
- BLOCK -> `failure`

## Idempotency

The injected publisher boundary is `publish_once(request)`. Adapters must use
the deterministic `external_id` as their idempotency key. Fixture coverage
proves replay of the same repository/source/verdict tuple creates one fake
provider write and returns the same immutable receipt.

## Safety boundary

A publication request or receipt is reporting metadata only:

- `merge_authorized=false`
- `deployment_authorized=false`
- no target interaction;
- no credential use;
- no exploit execution;
- no authorization widening;
- no attack-path mutation.

The next package may add a real GitHub Checks adapter only after this contract
passes hosted Python 3.11/3.14 verification and the canonical exact-head
`vps-bb300bba` proof.
