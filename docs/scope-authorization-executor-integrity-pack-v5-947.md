# ToolExecutor authorization-boundary integrity pack v5 — issue #947

**LightUp release posture:** INCUBATE M3/M7, PLAN/LAB ONLY. **DRAFT / HOLD — NO MERGE, NO DEPLOY.**

## Immutable composition ancestry

- Source of truth for executor implementation: original PR [#107](https://github.com/Zennay/Lightup/pull/107) frozen `c37ee27d922a7dd400eee1db39268f4a6269e431`. **This pack does not change source.**
- Parent pack v4: issue [#945](https://github.com/Zennay/Lightup/issues/945), exact parent commit `36183475b0aecdd5203b798c94957b0c59377601`. This pack does not modify the parent.
- Added exact outer ToolCall test/doc, byte-for-byte copied from independent [#946 acceptance draft #1301](https://github.com/Zennay/Lightup/pull/1301), pinned `a9302f9b2427484706d23498a907f4723a499551`; copied file SHA-1 blobs: `320d90e34406e73eccfa62becd6fe40baf3d8c85` (test), `7645cb34a6ad1d1d174ff4682e7d42ac71afe1a2` (handoff).
- Only new paths relative to v4: `tests/test_scope_946_exact_toolcall_red_20261013.py`, `docs/scope-946-exact-toolcall-admission-20261013.md`, and this manifest. No existing file is edited.

## Seven simultaneous authorization contracts

| Issue | Required invariant | Owner |
|---|---|---|
| #779 | Constructor accepts omitted/None or exact `ExecutionPolicy` only | #100/#107 |
| #935 | Exact policy object cannot have instance-level `decide` shadowed | #100/#107 |
| #938 | Construction-selected live resolver cannot be replaced/shadowed | #107 |
| #940 | Exact `ToolRegistry` required and pinned for executor lifetime | #107/#156 |
| #942 | Retained policy reference cannot be switched after construction | #107 |
| #944 | Only exact outer `RunContext` accepted before context field access | #107 |
| #946 | Only exact outer `ToolCall` accepted before registry or argument access | #107 |

**Ordering:** before any user-controlled object getter, registry lookup, argument extraction or handler dispatch, verify exact outer identities and trusted bound components; then apply canonical policy, mode, risk, live authorization and state/evidence checks. No target-active call should proceed on a stale, substituted or noncanonical authority. Rejection must have no handler and no evidence side effects.

## Regression matrix

Existing v4 tests are retained unchanged. Added #946 regression has **9 true in-process executor methods** over disposable SQLite `StateStore`, inert ANALYSIS-only handler and `.invalid` synthetic asset: **4 intentionally unresolved `unittest.expectedFailure`** for duck/subclass/overridden `arguments_dict` and canary getter; **5 ordinary controls** for exact canonical calls and invalid argument/tool refusal.

The intentionally failing cases are **release blockers**. A green CI result containing expected failures is *test harness health*, not proof that the source owner fixed the exploit class. Require original source-owner code change and convert every expected RED to an ordinary passing test without weakening previous controls.

## Safety and review gate

No network/DNS, real targets, scans, customer grants, activation, production interaction, model inference, deployed ingress, remediation/retest, or merge. Exact-final-head GitHub-hosted Python 3.11/3.14 must pass the complete offline suite and producer integration; **separate permanent registered VPS CI must pass the same immutable commit**. Additionally require latest-main compatibility, original #107/#100/#156 source owners, independent security/privacy review and explicit human authorization. Until then: **DRAFT/HOLD/NO MERGE/NO DEPLOY**.
