# #1482 — ActivationGate decision-envelope trust boundary (offline, draft)

LightUp is **INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD**. This artifact is an independently owned, additive source-acceptance experiment, not a live security finding or authorization to scan.

## Exact tested boundary

Original `src/lightup/activation.py` on pinned main (`e73b7445c87ad239bdb03c50a99078ef93163b02`) accepts a `scope_policy` duck-type at construction, and reads `decision.allowed`, `decision.reason.value`, and `decision.normalized_host` from its result. Python annotations on `ScopePolicy` and `ScopeDecision` do not enforce canonical identity or boolean type at runtime. Synthetic in-process tests demonstrate three currently unresolved expected-source-RED acceptance contracts:

1. Constructing a LAB gate with a forged `.decide()` provider must be rejected as a noncanonical policy; currently the constructor accepts it. This is only a programmer-controlled constructed boundary, **not** evidence the real app accepts untrusted policy objects.
2. A synthetic source `ScopePolicy.decide` response with `allowed="yes"` must not satisfy LAB execution admission (it currently evaluates as truthy).
3. A synthetic source response with a `normalized_host` different from the original target must not cause a permit to be stamped for that different host. This test does **not** claim a normal exact `ScopePolicy` produces this result.

Control tests verify legitimate in-memory loopback LAB use, public-name LAB denial, and default PLAN_ONLY denial. No sockets, DNS, target connection, subprocess, handlers, real consent, grants, DB, tests against public internet, or deployment.

## Independent, **not wired** helper

`src/lightup/activation_decision_shape_review_1482.py` exports `review_decision_shape(policy, target, decision)` for *only offline review of supplied objects*. It rejects noncanonical container identities, nonboolean allow flags, wrong enum identities, mismatched normalized host, inconsistent reason/allowed pairs, forged public loopback classification, and overly long target inputs. It **never calls policy.decide**. Its `DecisionShapeReview` result is a `NamedTuple` containing only `status=HOLD` or `status=REVIEW_ONLY`; both its execution/release flags are always false. It does **not** attest the policy's provenance, origin of the decision, customer authorization, tenant, operator approval, revocation, execution safety, CI trust or human GO. It is deliberately not registered with `ActivationGate` or any production caller. In particular, even `REVIEW_ONLY` is **never an execution permit**.

## Reproduction

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -p 'test_scope_decision_shape_activation_1482_20261016.py' -v
```

Expected partition: **15 ordinary PASS and exactly 3 original-source `expected failure`**, barring additional regressions. Expected failures intentionally remain open: a `unittest.expectedFailure` is not a production repair or green security attestation. Review any unexpected success carefully against exact original SHA before promoting it.

## Ownership / independent prerequisites

This branch adds only three namespaced files (one unused helper, one tests module, one documentation path). Do **not** alter original `src/lightup/activation.py`, `scope.py`, `models.py`, existing test paths or workers #120/#125/#726/#1476/#1480, workflows/runners or production adapters. Source owners must decide immutable trusted policy construction, verifying `ScopeDecision` provenance and target binding, type enforcement, actual caller reachability and revocation. Any future integration must independently test tenant/scope/asset/risk/capability/consent/permit expiry and durable evidence before handler invocation.

**NO MERGE, DEPLOY, REAL GRANTS, ACTIVE TARGETS, SCANS, OR HANDLERS; release requires independent source-owner, client/operator consent, security/privacy, exact-head hosted and permanent VPS CI, and human GO.**
