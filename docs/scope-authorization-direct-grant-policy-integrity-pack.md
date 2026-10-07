# Direct grant policy integrity acceptance pack

Tracked by #742.

## Pinned source owner

This successor pack is rooted in #739 and remains pinned to draft PR #100 exact head:

`ef553b6e0aa0c99855e9907f4b2dee9edc5aac0f`

PR #100 retains all production ownership for the direct `AuthorizationGrant` / `ExecutionPolicy` boundary.

## Included contracts

- #347 — canonical durable grant time-window semantics;
- #734 — explicit evaluation datetime exactness;
- #735 — falsy explicit evaluation inputs;
- #737 — revocation provenance coherence;
- #738 — stored validity datetime exactness;
- #740 — direct scope object exactness;
- #741 — outer authorization-grant object exactness.

## Expected partition on the pinned source

Expected RED total: **14**.

- #734: 2;
- #735: 3;
- #737: 3;
- #738: 2;
- #740: 2;
- #741: 2.

All #347 methods and all canonical controls are expected GREEN. No unexpected errors are accepted.

## Owner-side repair guidance

Keep production repair with PR #100:

1. require an exact canonical `AuthorizationGrant` before policy reads any grant field or method;
2. require an exact canonical `ScopeDefinition` before policy reads risk or membership;
3. distinguish omitted `now=None` from explicit malformed evaluation input;
4. require exact built-in aware datetime values for explicit and stored grant times;
5. fail closed on stale revocation actor/reason provenance without `revoked_at`;
6. preserve current exact-grant lineage, scope, inclusive-window and revocation behavior.

#646/#647 remain issuance ownership and #106 remains canonical live resolver ownership.

## Safety and collision boundary

Tests/docs composition only. No production source, domain persistence/resolution, activation, orchestration, target-capable handler, evidence-remediation, deployment, verdict or attack-path code is modified.

No target/network activity or capability execution is performed.
