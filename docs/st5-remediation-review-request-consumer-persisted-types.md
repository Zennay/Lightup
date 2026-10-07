# ST5 remediation review-request composed consumer persisted runtime types

Issue #790 isolates the outer persisted-input dispatch in
`load_and_validate_future_remediation_text_review_request()` above exact PR
#215 head `cee2e5391f32eed5212424d778c66cae73042e4a`.

## Contract

Only producer-reachable persisted runtime forms are valid at the composed
consumer boundary:

- exact built-in JSON `str`;
- exact built-in `dict` representing the persisted object.

Equal-content Python subclasses are not canonical persisted values and must
fail closed before parser dispatch. This keeps polymorphic string or mapping
behavior from influencing strict parsing or the later live proposal-chain
rebuild.

The regression retains exact built-in JSON/object controls and asserts that
rejected caller-owned subclass inputs remain unchanged. The review request
continues to grant only review intent: remediation acceptance, execution,
target interaction, retest, deployment and attack-path mutation all remain
false.

## Ownership boundary

Tests/docs only.

- PR #215 retains production consumer source ownership.
- #622 retains direct parser object exactness.
- #585 retains raw JSON parser typing.
- #642 retains parser caller-input purity.
- #635 retains snapshot isolation.
- #691 retains broader persisted-integrity composition.

The eventual source-owner change should be limited to exact outer runtime-type
checks before selecting either parser. This branch does not alter production
source, model behavior, scope, evidence collection, remediation/retest
execution, targets, deployment, verdicts or attack paths.

## Expected proof posture

Canonical exact built-in controls are expected green. The two subclass cases
are intentionally expected red until PR #215 absorbs the narrow fail-closed
guard. Do not create an extra permanent self-hosted run solely to demonstrate a
known-red acceptance partition while the shared LightUp queue is occupied.
