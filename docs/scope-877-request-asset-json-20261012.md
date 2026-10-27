# Scope #877 — durable assessment-request asset JSON admission

**LightUp:** Incubate M3/M7 **PLAN/LAB ONLY — DRAFT/HOLD/NO MERGE/NO DEPLOY**.

## Ownership and current risk
[Open issue #877](https://github.com/Zennay/Lightup/issues/877) identifies producer-impossible persisted `requested_assets_json` shapes that the real `DomainStore._request_from_row` currently casts via `tuple(json.loads(...))`. A JSON object becomes a tuple of its keys, string becomes individual characters, and mixed/empty arrays are admitted. A reconstructed assessment request **is not authorization**, but it may later become provenance for #177 request-to-grant binding.

This branch is isolated from the previously pinned #877 test-only branch and [#878](https://github.com/Zennay/Lightup/issues/878) composition, and from [#880 DRAFT #1261](https://github.com/Zennay/Lightup/pull/1261) decision-provenance code. It is based directly on unchanged main `05b80319cd0581fed21fe9d8f565bcb0a56cd2df`. Existing `domain.py`, intake source #654/#875/#876, approval #133, grant #177, web, execution, queue, and all other worker-owned paths remain untouched.

## Concrete, uninstalled reference
- `src/lightup/request_assets_shape_optin.py` adds a **read-only, non-authorizing, opt-in** `checked_requested_assets_json(raw)` contract that accepts only an exact builtin JSON text string decoding to a nonempty array of exact builtin nonblank strings. No silent repair, trimming, sorting, dedupe, stringify or fallback. Generic failures do not echo source content. This module is deliberately **not used by `DomainStore`, request approval, web or grant/target execution**.
- `tests/test_scope_877_request_asset_json_20261012.py`: 14 actual disposable SQLite `DomainStore` unittest methods, including 5 deliberate `@expectedFailure` default-producer canaries for object-key promotion, string splitting, mixed members, empty list and blank strings. Positive guards check canonical fixture roundtrip, array/member type narrowing, byte-for-byte unchanged persisted JSON row after refusal, no implicit grant/engagement creation and independent client-tenant selector denial.
- A deliberate unittest expected RED is evidence of an unresolved default-producer weakness, **not proof of a production fix**, safe request approval, or an authorization grant. No DNS/network/listener, real client/asset, scan, action dispatch, retest or deployment.

## Required owner remediation and acceptance
The original `DomainStore._request_from_row` source owner must validate exact durable JSON array/member shape **before** creating any `AssessmentRequestRecord`. Invalid rows must fail closed on **all selectors** and remain unchanged; never reinterpret objects as scope assets or treat any persisted approval as an independent live grant. Preserve legitimate recorded strings exactly. Coordinate canonical mode/risk, actor/time decision provenance (#880), requester, issuer/tenant and independent request→grant #177 checks. Convert the five expected RED canaries to ordinary passing negative tests once production source actually enforces this rule.

Exact-head GitHub-hosted Python 3.11 + 3.14 full tests, **independently registered permanent self-hosted VPS CI**, latest-main review, security/privacy/tenant review and explicit human release approval are required. Keep #877 **OPEN** and this PR **DRAFT/HOLD** until then.

```bash
PYTHONPATH=src python -m unittest discover -s tests -p 'test_scope_877_request_asset_json_20261012.py' -v
```


## W2 — same SQLite row, cross-tenant fail-before-decode, and all-or-none visibility

Added TWO more exclusively new paths atop PR #1262 (no original domain, activation, web, request, grant or other worker files modified):

- `src/lightup/request_assets_snapshot_optin.py`: **UNINSTALLED** read-only `checked_get_assessment_request` / `checked_list_assessment_requests` reference selectors. They read a single SQLite row/snapshot, check tenant visibility **before validating private row contents** for point reads, and validate the **entire visible list before building any result records**. They deliberately use the same snapshot row for validation and projection, avoiding separate uncoordinated validation/producer queries. They never issue grants, approve requests, authorize targets or mutate durable content.
- `tests/test_scope_877_snapshot_read_20261012.py`: **15 more** real synthetic disposable SQLite selector regressions including get/list tenant boundaries, operator vs tenant list, cross-tenant corruption isolation, single/whole-batch malformed refusal, invalid identifier, row immutability, no grants or engagements and empty-list behavior.

These opt-in tests demonstrate only local shape/tenant admission of persisted assets: `DomainStore._request_from_row` still ignores unrelated decision/status/provenance faults (#880, #879), and there is **no production installation, current client authorization, anti-TOCTOU dispatch fence, or release proof**. Even a passing test run must not be described as security acceptance. Default `get_assessment_request` / `list_assessment_requests` are still unchanged and vulnerable to the recorded shape issue.

Replay the isolated W1 + W2 modules:
```bash
PYTHONPATH=src python -m unittest discover -s tests -p 'test_scope_877_*20261012.py' -v
```

Keep DRAFT/HOLD/NO MERGE/NO DEPLOY pending source-owner integration, conversion of intentional RED to ordinary passing producer tests, latest-main security/privacy/tenant review, exact-head GitHub-hosted matrix and separate permanent VPS CI, and explicit human approval.
