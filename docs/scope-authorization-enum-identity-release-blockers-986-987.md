# ST5 authorization enum identity — production-owner release blocker

Status: **acceptance contract only**. This document grants no authorization and changes no runtime behavior.

## Source and ownership

- Issue [#986](https://github.com/Zennay/Lightup/issues/986): unknown interaction values can fall through to TARGET_ACTIVE handling.
- Issue [#987](https://github.com/Zennay/Lightup/issues/987): PASSIVE_PUBLIC comparisons can accept numeric/foreign-enum lookalikes.
- Production `ExecutionPolicy` implementation and integration remain with the owning PR/worker (#100 and downstream); this sidecar must not modify that source.
- Tool execution and live grant revalidation remain owned by #107.

## Production invariants (must BOTH hold before promotion)

1. Explicitly require the **exact** `InteractionKind` member, not a coercible value. Only `InteractionKind.TARGET_ACTIVE` may enter the target-active branch. Every unknown, malformed or foreign-enum interaction must deny before grant lookup/dispatch.
2. For `InteractionKind.PASSIVE_PUBLIC`, require `type(requested_risk) is RiskLevel` before comparisons. Reject booleans, integers (including 0/1/-1), floats, strings, foreign IntEnum members and objects; never coerce them into a canonical risk.
3. Preserve positive controls for legitimate canonical PASSIVE_PUBLIC/PASSIVE and target-active requests with independently valid, in-scope grants. A recognized enum is necessary but never sufficient for authorization.
4. No exception fallback to allow. Denials must perform zero target I/O, zero tool dispatch and zero grant/evidence mutation. Do not log raw attacker-controlled enum representations.
5. Run negative controls **through the real admission/policy boundary**; isolated reference tests alone cannot demonstrate production safety.

## Owner acceptance matrix

| Input | Expected |
| --- | --- |
| PASSIVE_PUBLIC + canonical RiskLevel.PASSIVE | Normal policy evaluation (not automatic allow) |
| PASSIVE_PUBLIC + bool/int/foreign IntEnum/float/str/object risk | Deny |
| TARGET_ACTIVE + canonical interaction + fully scoped valid grant | Normal active policy evaluation |
| TARGET_ACTIVE + valid grant but interaction string `"target_active"` or arbitrary truthy value | Deny |
| Unknown interaction + any valid grant | Deny |
| None/missing interaction + any grant | Deny |
| LAB_ACTIVE/ANALYSIS with canonical enums | Preserve existing narrower-mode restrictions |
| Any rejected input | No dispatch, no target access, no persistent grant or evidence writes |

## Exact-head release protocol

- Source owner lands minimal production guards, links the change back to both #986 and #987, and runs the issue-specific regression suites plus existing policy tests on the **exact resulting commit**.
- Record exact commit, test command, exit status and canonical permanent self-hosted VPS runner URL; also record hosted check result. A queued/stale/different-SHA result is not a green gate.
- Review scope narrowing, positive-control preservation and missing side effects before merge.
- Require human review for release. No live assessment, target, scanning or deployment should be used to prove this matrix.

## Stop condition

Until **both** identity flaws are fixed in the production boundary and exact-head proofs are green, ST5 target-capable promotion remains **NO-GO**, even when isolated offline reference PRs pass.
