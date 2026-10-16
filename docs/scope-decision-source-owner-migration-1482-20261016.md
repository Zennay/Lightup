# LightUp #1482 — collision-safe original-source remediation handoff

**Owner scope:** `src/lightup/activation.py`, `src/lightup/scope.py`, `src/lightup/models.py`, installed callers and original runtime integrations belong to the **original-source maintainers**. This is **review-only planning** attached to our isolated [draft PR #1483](https://github.com/Zennay/Lightup/pull/1483), never an implemented runtime patch. Do **not** automatically cherry-pick fixes from this branch.

## Current frozen baseline and precise original-source defects

Original main `e73b7445c87ad239bdb03c50a99078ef93163b02`; `src/lightup/activation.py` blob SHA `156e94c18d5221b3d55e2c9fff4e393369e0f38e`, `src/lightup/scope.py` SHA `23909917822b5630c76be0cb47c99e1549b30cf8`, `src/lightup/models.py` SHA `74b96d45a5308d39e2c4c930728e10a2ccc18d2a`. These are **exact original-source fingerprints**, not current post-merge truth.

Three *synthetic Python-programmer-controlled boundary* observations are source-pinned as intended REDs; none demonstrates that external application inputs can inject Python policy objects:

| Contract | Current original installed behavior | Required owner acceptance before any source fix can be called complete |
|---|---|---|
| Constructor provenance | `ActivationGate(ForgedPolicyWithDecide, ActivationPolicy(LAB_ONLY))` accepted, forged `ScopeDecision` can stamp an **in-memory** LAB record for a fictional public hostname | Reject noncanonical policy construction **before** decision/permit creation; independently prove no supported plugin/DI path depends on duck typing. Preserve normal exact `ScopePolicy` policy construction. |
| Decision allow type | `decision.allowed="yes"` passes source truthiness and may mint in-memory fictional LAB record | Require an **actual built-in bool**, not truthy `str`/`int`, and exact `ScopeDecision` result identity. No permit on invalid fields. |
| Target binding | `decision.normalized_host` is placed in permit target without equality check against original `Target.value` normalization | Reject a decision naming a different destination, and handle lexical aliases, auth/port/path and CIDR rules in an owner-approved canonical identity contract; never infer real target consent from matching text. |

**Source trust caveat:** Checking `type(policy) is ScopePolicy` and `type(result) is ScopeDecision` is **necessary in this synthetic contract but not sufficient provenance** if code running inside the process can mutate class members or forge original dataclass instances. Real provenance requires a trusted constructor factory, immutable configuration snapshot, verified code, installed ingress/callers, and segregated permissions.

## Non-overlap and ordered owner integrations

1. **Agree source-owner interface** before taking changes. Existing independent owners already work on ActivationGate policy lifetime [issue #1476](https://github.com/Zennay/Lightup/issues/1476) / [draft PR #1477](https://github.com/Zennay/Lightup/pull/1477) and permit issuance instant [issue #1480](https://github.com/Zennay/Lightup/issues/1480) / [draft PR #1481](https://github.com/Zennay/Lightup/pull/1481). Earlier owner PRs [#122](https://github.com/Zennay/Lightup/pull/122) (capability binding) and [#126](https://github.com/Zennay/Lightup/pull/126) (mode identity) overlap `activation.py`; merge/reconcile them only in the owners' upstream sequence. **Never restack/merge our branch over these automatically.**
2. On the reviewed source-owner branch, reconcile immutable policy identity, temporal validity, authorization capabilities, and exact decision identity in **one final issue-level acceptance matrix**. No independent owner acceptance should weaken any other guard.
3. Treat policy constructor validation and decision validation as **different trust boundaries**. A canonical typed policy does not prove `decide` was faithfully called; a well-formed supplied `ScopeDecision` does not prove it was produced by the installed policy. A `REVIEW_ONLY` helper output may never be mapped to a permit.
4. Re-evaluate trusted original policy and normalized requested destination at the actual issuance point; separately prove tenant/asset/capability/risk/authorization expiry/revocation and evidence-before-handler for **every installed active entry point**. This document does not define permission to test a live target.
5. Require exact immutable-head hosted Python 3.11 **and** 3.14 results plus canonical assigned **permanent VPS runner identity** on the same SHA; if a runner is queued/missing (#1144), status remains **HOLD**. A green isolated offline test does not compensate for an unavailable producer integration suite.
6. Customer/operator **explicit scope and ongoing revocation**, independent security/privacy review, and explicit human GO are mandatory before changing `Incubate` posture or deploying anything. No scan, grant, credentials, handler or active adapter from this PR.

## Deterministic transition of our original RED tests after real owner fix

* The three `@unittest.expectedFailure` contracts in `tests/test_scope_decision_shape_activation_1482_20261016.py` should be converted to **ordinary PASS assertions** only when actually satisfied by the installed source. An **unexpected success** before deliberate review must remain a failure of the strict verifier, not silently interpreted as overall safety. Keep the normal loopback, out-of-scope public and PLAN_ONLY preservation tests.
* The `test_current_legacy_canary_synthetic_policy_can_stamp_lab_record` in `tests/test_scope_decision_legacy_constructor_witness_1482_20261016.py` intentionally asserts an unsafe **historical** behavior. It MUST be replaced by a **rejection** canary after constructor repair, not artificially preserved. Keep tests that verify normal policy denial, no network, and the fact that a non-authorizing helper always HOLDs the forgery.
* The two opt-in verifiers in `scripts/check_scope_1482_source_acceptance_20261016.py` and `scripts/check_scope_1482_all_owned_acceptance_20261016.py` intentionally pin immutable old `activation.py` and a three-source-RED manifest. They MUST return `HOLD` on changed source until a source owner explicitly approves new reviewed Git blob fingerprints **and** updates exactly expected RED-vs-normal method IDs and counts. Do not blindly re-pin to the new code or remove assertions to manufacture green.
* The new strict 15-blob source verifier is only a **local offline source-content contract**. A file watcher/attacker that changes disk contents between hashing and import is outside its guarantees, as are signed supply-chain attestation, Python import cache provenance, test-runner integrity, Git replace refs and remote workflow trust. These are separately owned reviews.
* Run **ordinary suites, deliberately unresolved REDs, and genuine integrations separately** and clearly annotate. A historical fixed-date #301 fixture still fails on 16 Oct 2026; the separate [owner draft #1452](https://github.com/Zennay/Lightup/pull/1452) must be handled by its owner, **never edited here**.

## Strict decision table for release handoff (non-authorizing)

| Condition | Classification |
|---|---|
| Any original RED remains unresolved | **HOLD** (regardless of our isolated green tests) |
| Original-source tests converted ordinary PASS but no permanent runner | **HOLD** |
| Exact-head hosted full suite has unrelated #301 ordinary FAIL | **HOLD** |
| Producer integrations SKIPPED or installed source/caller unreviewed | **HOLD** |
| Customer/operator consent, durable revocation, risk/tenant/capability, independent security/privacy or human GO missing | **HOLD** |
| All gates evidenced on an immutable, independently trusted install and approved by actual owners | Eligible only for **human review**, not automatic release or grant |

**Project posture: INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD. No merge, deploy, internet-wide targets, active handlers, real grants, scans or release through our work.**
