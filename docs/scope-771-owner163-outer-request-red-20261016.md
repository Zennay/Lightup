# Issue #771 — exact outer ExecutionRequest boundary (source-owner #163)

**Posture:** LightUp INCUBATE M3/M7, PLAN/LAB ONLY, DRAFT/HOLD.
No merge, deploy, real client grant, real scan, tool dispatch, network or release.

## Proven source and ownership

This independently added acceptance packet starts at **unchanged source-owner
PR #163** at commit `3dfacdcf2d939cd5e19bf9ce143f03a0b16a4274`.
It neither changes the owner's `src/lightup/execution_policy.py` nor
supersedes other source owners (#121, #124, #162, #567, #575, #576, #740,
#741). The separate opt-in strict admission PR #1174 is not wired into this
installed source and is **not** substituted for owner integration.

The installed #163 `ExecutionPolicy.decide()` reads
`request.interaction`, `request.requested_risk` and `request.is_lab`
before proving the exact outer request class. Python annotations and
inner-field checks do not establish the origin of the outer container.
Untrusted duck-typed objects or subclasses can currently pass the policy
as if they were a canonical request. This is an in-memory boundary
demonstration, **not** proof that an external target has been reached.

## Acceptance contract (24 tests; 8 deliberately OPEN source RED)

The new standalone `tests/test_scope_771_owner163_outer_request_red_20261016.py`
has fifteen ordinary green controls: exact analysis and passive requests,
canonical lab boolean false/true owner semantics, target-active without
grant denial, exact fictional target-active with valid grant allowed, revoked
grant denied, wrong-client or wrong-engagement tenant mismatch denied, expired
grant rejection, risk escalation denial, wrong asset and capability denials,
and malformed lab-context boolean and analysis-risk typing denials. Eight source-RED cases
require denial for a synthetic duck analysis request, duck passive request,
subclass analysis, subclass lab true, property-spy object before any untrusted
getter, duck target-active with an otherwise valid fictional grant, subclass
target-active with that grant, and non-envelope objects without fields.
All RED cases are marked `@unittest.expectedFailure` to preserve CI
visibility without claiming the authorization source is fixed. The
eleventh case is an ordinary strict replay oracle, requiring **exactly
eight actual expected failures**, zero unexpected successes, skips,
errors or ordinary failures. If the source is fixed, this oracle fails
until an authorized owner replaces RED markers with normal green
assertions and verifies the denial semantics.

There is no DNS, HTTP, socket, filesystem mutation, handler, grant
issuance, registry mutation or customer data in the test logic.

### Source-owner repair requirements

1. Check `type(request) is ExecutionRequest` **before any request
   attribute access** or invocation of user-controlled special methods.
2. Return a concrete non-authorizing `PolicyDecision(allowed=False, ...)`
   for noncanonical requests; do not throw or interpret unknown objects.
3. Retain existing exact canonical analysis/passive/lab behavior,
   strict bool lab marker and target-active tenant/grant/risk/asset gates.
4. Promote each intentional RED only when actual owner-source repair
   has been reviewed, re-run all tests and repeat genuine exact-commit
   hosted Python 3.11 + 3.14 and registered permanent VPS CI checks.
5. Require independent security/privacy, actual client/operator consent,
   revocation proof and human GO before any deployment or active work.

## Handoff / evidence limits

This branch is **test-and-documentation only**. It does not activate the
opt-in policy from #1174 and is not a production repair. GitHub-hosted
suite green with expected failures means reproducible defects, never GO.
A queued/unassigned self-hosted job is **not** runner proof.
No merge or deployment is authorized by this packet.

## Exact witness markers — avoid false-green expected failures

Every intentional source RED now has a distinct stable synthetic failure marker, verified by the replay oracle against the actual `unittest.expectedFailures` traceback for that case. Unexpected `TypeError`/`ValueError`, arbitrary crashes or unrelated assertions **cannot** satisfy the RED count. A duck or subclass source RED must first receive an actual `PolicyDecision(allowed=True)` and then hit its dedicated marker; malformed missing-members must witness `AttributeError`; the property spy must witness **real untrusted getter reads**. If the production source starts denying the outer object correctly, its RED becomes an unexpected success until an authorized source owner promotes that assertion. Seven new ordinary controls preserve source-owner time, tenant, capability, asset, risk and exact type safety behavior.
