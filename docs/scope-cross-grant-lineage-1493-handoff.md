# #1493 — Cross-grant lineage, non-authorizing offline review

**Status:** LightUp INCUBATE M3/M7 · PLAN/LAB ONLY · **DRAFT/HOLD**.
Never merge/deploy or infer an execution grant, customer consent, trusted operator, actual client asset, or target authorization from this report.

## Existing source boundary (read-only)
- `models.Authorization` is a legacy `Target` proof, read by `ScopePolicy` and `ActivationGate`.
- `engagements.AuthorizationGrant` carries a separate tenant/engagement/scope/validity claim, read by `ExecutionPolicy`.
- Even if each independently says yes, the two are **not cryptographically or durably joined**. The legacy object does not include a client/engagement ID. Equality of `legacy.owner` and `durable.approved_by` is a *review heuristic*, not authenticated equality of roles.
- Existing #262 independently tests allow/deny across policy gates; #1491 reviews a legacy permit against one scope decision. This review checks **two disjoint grant assertions** and is neither of those implementations.

## New opt-in, unwired component
`src/lightup/cross_grant_lineage_review_1493.py` is a pure, bounded in-memory reviewer requiring explicit synthetic `legacy`, `durable`, `client_id`, `engagement_id`, `asset`, `capability_id`, `requested_risk`, `evaluated_at`. The caller owns all data, including the clock. Exact built-in primitive/dataclass/enum checks reject subclass/coercion, whitespace, malformed asset entries, overlong IDs or duplicate asset/capability entries; review also requires UTC instants, legacy window wholly contained by the durable window, reference/actor equality, explicit exact asset and capability membership, and risk bounds. The deliberately conservative no-wildcard policy may reject otherwise legitimate broad authorizations until product owners review it.

**Every output, including coherent synthetic assertions, has fixed literal false `authorized`, `consent_verified`, `dispatch_allowed` and `release_allowed`.** Possible statuses are **HOLD** and **REVIEW_ONLY** only; this is not a production policy plugin or authority source.

## Offline acceptance
```bash
PYTHONPATH=src python -m unittest discover -s tests -p 'test_cross_grant_lineage_review_1493.py' -v
```
The 106 tests include fixed 2020 UTC input fixtures and real original policy source smoke showing historical approvals remain rejected at present without any external targets/handlers. All names use imaginary `.example.test` documentation values, and review uses no DB, socket, file, subprocess, HTTP or DNS operations.

## W2 atomic batch review
\`review_cross_grant_batch\` checks 1–32 exact fictional candidate records in one all-or-nothing operation: same caller-supplied client and engagement, no repeated grant/asset/capability tuple, exact canonical hashable identity, common explicit UTC evaluation instant, and individually REVIEW_ONLY source shapes. A single invalid or mixed-tenant record returns batch HOLD with zero reported reviewed records. No intermediate authorizing results or private values are returned. These 20 additional tests (including hostile field-equality protection) preserve the source boundaries and compare pure synthetic input only.

## W4 — Same grant-ID immutable snapshot guarantee\nFor one grant ID, every independently passing claim in the cohort must carry **exactly the same immutable validated grant contents** (client/engagement, approver, reference, UTC interval, retest flag, scope assets/exclusions/capabilities/risk). Multiple different assets and capabilities on that same single explicit canonical grant remain eligible for synthetic REVIEW_ONLY. Conflicting same-ID snapshots (including a widened/revised time range) return atomic HOLD. Seven added tests include field-isolated positives for each individual claim, to ensure the batch denial is genuinely triggered by same-ID inconsistencies. This is not durable grant revalidation or an authenticated source of truth.\n\n## W5 — Executable fictional-only stdin review CLI
New additive `src/lightup/cross_grant_lineage_cli_1493.py` consumes at most 65,536 UTF-8 bytes from standard input, only with explicit `--synthetic-only`. It requires exact versioned `FICTIONAL-CROSS-GRANT-V1` schema, exact object key sets, no duplicate JSON keys, no numeric/NaN/Inf tokens, exact UTC `Z` instants, exact RiskLevel names, synthetic operator identities at `@example.test`, synthetic `SYNTH-` authorization references, and canonical fixture assets ending `.example.test`. No live client identities, production assets, adapter, network, database, grants or executor can be accessed through this flow.

A complete fictional input is included at `examples/fictional_cross_grant_1493.json` (fixed 2020-01-01 UTC, fake identifiers). On the VPS/runner **only in a local checkout**, with no real targets:

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python -m lightup.cross_grant_lineage_cli_1493 --synthetic-only < examples/fictional_cross_grant_1493.json
# Prints only a sanitized one-line JSON HOLD/REVIEW_ONLY receipt.
# Always exits nonzero: 2 for evaluated synthetic data; 3 for malformed input.
```

Explicit sample output for internally coherent *fabricated* records:
```json
{"authorized":false,"consent_verified":false,"dispatch_allowed":false,"reason":"UNTRUSTED_COHERENCE","release_allowed":false,"reviewed":1,"status":"REVIEW_ONLY"}
```
**Exit 2, never 0.** This is not evidence of customer authorization, tenant identity, a current runtime clock, revocation, a permitted scan or release. An invalid or mixed synthetic batch emits privacy-minimal HOLD with zero reviewed count; responses never echo actor, host, tenant, grant or capability. The exact-depth, duplicate-key, invalid UTF-8, false consent field, unbounded input, subprocess and no-I/O tests run in the isolated matrix. CLI subprocess testing is the only subprocess work; the reviewer itself has no process calls.

## Still RED / human-controlled release gates
- Genuine linkage to the authenticated operator, canonical client and engagement, approved asset/capability, signed decision and durable trusted row, *not* equality of two caller-supplied strings.
- Proof of current revocation and revalidation at use time, including atomic proof that approval cannot be replayed against another run or tool. Coordinate with original source owners #99/#100, #1491/#1492 and executor chain without editing their files/branches.
- Security/privacy approval, representative customer consent, exact-head hosted test success, registered `self-hosted,zcloud,vps` job and verified `vps-bb300bba`, then explicit human GO. No bypass for #301 / #1144.
- No activation, active scanning, production consumer wiring or permanent runner changes in this branch.

GitHub issue: https://github.com/Zennay/Lightup/issues/1493
