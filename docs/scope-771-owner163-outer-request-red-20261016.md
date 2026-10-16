# Issue #771 — exact outer ExecutionRequest boundary (source-owner #163)

**Posture:** LightUp INCUBATE M3/M7, PLAN/LAB ONLY, DRAFT/HOLD.
No merge, deploy, real client grant, real scan, tool dispatch, network or release.

## Proven source and ownership

This independently added acceptance packet starts at **unchanged source-owner
PR #163** at commit `3dfacdcf2d939cd5e19bf9ce143f03a0b16a4274`.
It neither changes the owner's `src/lightup/execution_policy.py` nor
supersedes other source owners (#121, #124, #162, #567, #575, #576, #740,
#741). Independent [draft #1174](https://github.com/Zennay/Lightup/pull/1174) already owns a **broader** standalone strict admission reference with nested scope/grant checks. The narrow local wrapper added below is NOT a rewrite or replacement for #1174 and does NOT wire #1174 into any consumer; neither helper replaces owner-source integration.

The installed #163 `ExecutionPolicy.decide()` reads
`request.interaction`, `request.requested_risk` and `request.is_lab`
before proving the exact outer request class. Python annotations and
inner-field checks do not establish the origin of the outer container.
Untrusted duck-typed objects or subclasses can currently pass the policy
as if they were a canonical request. This is an in-memory boundary
demonstration, **not** proof that an external target has been reached.

## Acceptance contract (26 tests; 8 deliberately OPEN source RED)

The new standalone `tests/test_scope_771_owner163_outer_request_red_20261016.py`
has seventeen ordinary green controls: exact analysis and passive requests,
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

The **installed owner-source acceptance module** remains test-and-documentation only. This child separately contains a narrow, UNWIRED opt-in reference helper and its own green tests. Neither opt-in module (this one or #1174) is imported by the default app or source-owner policy, so this is not a production repair. GitHub-hosted
suite green with expected failures means reproducible defects, never GO.
A queued/unassigned self-hosted job is **not** runner proof.
No merge or deployment is authorized by this packet.

## Exact witness markers — avoid false-green expected failures

Every intentional source RED now has a distinct stable synthetic failure marker, verified by the replay oracle against the actual `unittest.expectedFailures` traceback for that case. Unexpected `TypeError`/`ValueError`, arbitrary crashes or unrelated assertions **cannot** satisfy the RED count. A duck or subclass source RED must first receive an actual `PolicyDecision(allowed=True)` and then hit its dedicated marker; malformed missing-members must witness `AttributeError`; the property spy must witness **real untrusted getter reads**. If the production source starts denying the outer object correctly, its RED becomes an unexpected success until an authorized source owner promotes that assertion. Seven new ordinary controls preserve source-owner time, tenant, capability, asset, risk and exact type safety behavior.

## Mutation-tested replay integrity

Two additional ordinary synthetic mutation controls **execute the real replay oracle under temporary, in-process monkey-patched owner policy**: a generic `RuntimeError` must be rejected because it carries no exact source defect marker, and a simulated complete canonical deny fix must be rejected as unexpected RED success until reviewed migration to normal PASS. Patching is confined to unittest contexts; it does not persist, issue grants, run handlers or modify source ownership.

## Narrow, working, opt-in envelope admission (not a production fix)

The wholly new isolated `src/lightup/scope_771_request_admission_optin.py` exports
`decide_exact_execution_request(policy, request)`. It rejects a policy that is
not **exactly** `ExecutionPolicy`, then rejects a request that is not
**exactly** `ExecutionRequest` with a typed `PolicyDecision(False, ...)`.
Both checks occur before any attacker-controllable request getter or policy
subclass override can run. The exact canonical pair delegates to the original
owner's `policy.decide(request)` unchanged; authorization cannot be broadened
by the helper itself. A returned allow is **only an in-memory policy decision**
and never permission to start a scanner or real capability.

A completely separate new
`tests/test_scope_771_request_admission_optin_20261016.py` uses 32
ordinary in-memory tests: exact fictional analysis/passive/lab modes and valid
approved synthetic target; missing, expired, revoked or mismatched fictional
grants, risk, target and capability narrowing; malformed canonical fields;
duck getters that throw on use; subclass getters and policy overrides that
must never run; three forged `__class__` identity probes for request, grant-envelope,
and policy impostors; null/opaque input denial; and request/grant non-mutation.
No network, real grant, registry, authorization write, target handler,
tool execution or deployment.

**Collision note:** existing [PR #1174](https://github.com/Zennay/Lightup/pull/1174)
already implements a different, more comprehensive **unwired** strict policy
module with nested grant checks. Do not overwrite its files or take over
that owner's integration. This narrower adapter tests an exact source-owner
`#163` delegation seam only, for eventual **owner review**. It is not a
production substitute for #1174 and does not itself prove grant authenticity,
live revocation, destination binding, operator step-up or durable consent.
The original 26-case source-RED test module is still separate: eight known
owner-source REDs are unresolved even if all opt-in controls pass.

## W11: exact policy instance method-shadow closure (opt-in only)

Security hardening is not satisfied by an exact `type(policy) is ExecutionPolicy`
check alone: owner `ExecutionPolicy` has a writable instance `__dict__`, so
`policy.decide = forged_allow` can replace the *method* without changing its
class. The isolated helper now rejects an instance with a shadowed `decide`
entry **before any call**, returning typed `PolicyDecision(False, ...)`.
For a canonical instance with no shadow it calls `ExecutionPolicy.decide(policy,
request)` directly rather than using polymorphic `policy.decide(request)`.
Three new ordinary in-memory tests prove the forged allow method is not called,
that even safe analysis is denied if the policy method binding was changed,
and that deleting the synthetic shadow restores owner behavior. The source
`src/lightup/execution_policy.py` is **not changed** and remains independently
vulnerable; owner issue [#935](https://github.com/Zennay/Lightup/issues/935)
retains its separate lifetime-binding scope. This is **not** a fix to
`ToolExecutor`, live resolver or real authorization, and should not be
used as a GO signal.
