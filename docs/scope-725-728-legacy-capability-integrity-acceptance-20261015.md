# #725 + #726 + #728 — legacy capability authorization integrity (independent acceptance)

**Posture:** LightUp **INCUBATE M3/M7 — PLAN/LAB ONLY — DRAFT/HOLD**. This packet is non-authorizing. Do **not** merge, deploy, run target scans, issue production permits or infer live operator consent from it.

## Exact source-owner isolation

- Owner: [#122](https://github.com/Zennay/Lightup/pull/122) at original unchanged source SHA `3554630323cf6a8625ac2a1856fb35b22516cdd9`; our PR must target that original branch, **not main**.
- Original owner retains `src/lightup/models.py` and `src/lightup/activation.py` source; this acceptance set changes **only three new isolated test files and this new documentation file**.
- Open issues: [#725](https://github.com/Zennay/Lightup/issues/725) caller list snapshot semantics [#726](https://github.com/Zennay/Lightup/issues/726) runtime capability parameter identity and [#728](https://github.com/Zennay/Lightup/issues/728) exact builtin collection/entry type constraints. These are **not** #300 (assets), #648 (durable grants) or #650/#576 (durable execution).
- Other reviewers/workers can continue untouched on their own branches.

## Instantiated synthetic tests

`tests/test_scope_725_legacy_capability_snapshot_20261015.py` calls the **installed original Authorization and ActivationGate** with fabricated `*.example.test` host, fictional authority, and capability IDs. Its ordinary tests preserve exact tuple accept, unknown capability deny, empty capability deny, unauthorized host deny, PLAN_ONLY deny, absent authorization deny and expiry deny. Five deliberate `unittest.expectedFailure` cases demand immutable caller-input snapshots: type must be builtin tuple, an appended list entry must never grant membership/permit, and removing a list entry must not retroactively revoke already-snapshotted authority/permit.

`tests/test_scope_728_legacy_capability_canonical_20261015.py` uses the **installed original Authorization and ActivationGate** with a synthetic `tuple` subclass overriding membership and a `str` subclass overriding equality. Five normal controls preserve exact tuple + builtin strings, foreign capability/empty scope denial, unknown host denial, and expired grant denial. Six **deliberate expected source RED** methods enforce exact tuple, exact str entries, no membership forgery and no permit from either polymorphic input. `tests/test_scope_726_legacy_capability_parameter_20261015.py` checks **real ActivationGate.issue** with a caller-controlled capability identifier: six normal controls prove canonical requested strings, denial for unknown string, missing grant, wrong host, expired grant and plan-only mode. Three deliberately expected source REDs require rejection of a matching `str` subclass, non-string equality spoofing and preservation of only canonical builtin `str` in any permit. No handler, socket, DNS lookup, network call, command, external asset, real grant, scan, migration or producer state is involved.

Run offline after checkout/install (on the approved CI runner, not production):

```sh
python -m unittest discover -s tests -p 'test_scope_72?_legacy_capability_*_20261015.py' -v
```

**Expected installed-source result:** ordinary controls pass, known source deficits are reported as expected failures, and no unexpected success is treated as proof of a fix. For owner acceptance, **first fix the production source in its own authorized branch**, then remove the expectedFailure annotations only when each assertion is confirmed ordinary PASS on actual installed code, and rerun the broader 3.11/3.14 suites + real producer integrations.

## Acceptance / decision record

1. Check exact base and head SHAs, full changed paths and no source overlap.
2. Individually inspect original hosted Python 3.11 and 3.14 CI logs for checkout SHA and the actual tests. Hosted success is not self-hosted proof.
3. Independently require a **genuinely assigned, registered permanent VPS runner** job (not merely queued), then security/privacy and source-owner review.
4. Confirm no authority is granted by tests, artifacts, PR discussions or Notion notes; actual customer/operator consent, revocation, asset+capability scope, lab isolation and explicit human release stay mandatory.
5. Until then **DRAFT/HOLD, NO MERGE/DEPLOY/SCAN/ACTIVATION**. Current source has known authorization weaknesses; intentionally expected RED tests are **not** a repaired security boundary.
