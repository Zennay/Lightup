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
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python -m unittest discover -s tests -p 'test_cross_grant*_1493.py' -v
```
The 150 tests include fixed 2020 UTC input fixtures and real original policy source smoke showing historical approvals remain rejected at present without any external targets/handlers. All names use imaginary `.example.test` documentation values, and review uses no DB, socket, file, subprocess, HTTP or DNS operations.

## W2 atomic batch review
\`review_cross_grant_batch\` checks 1–32 exact fictional candidate records in one all-or-nothing operation: same caller-supplied client and engagement, no repeated grant/asset/capability tuple, exact canonical hashable identity, common explicit UTC evaluation instant, and individually REVIEW_ONLY source shapes. A single invalid or mixed-tenant record returns batch HOLD with zero reported reviewed records. No intermediate authorizing results or private values are returned. These 20 additional tests (including hostile field-equality protection) preserve the source boundaries and compare pure synthetic input only.

## W4 — Same grant-ID immutable snapshot guarantee
For one grant ID, every independently passing claim in the cohort must carry **exactly the same immutable validated grant contents** (client/engagement, approver, reference, UTC interval, retest flag, scope assets/exclusions/capabilities/risk). Multiple different assets and capabilities on that same single explicit canonical grant remain eligible for synthetic REVIEW_ONLY. Conflicting same-ID snapshots (including a widened/revised time range) return atomic HOLD. Seven added tests include field-isolated positives for each individual claim, to ensure the batch denial is genuinely triggered by same-ID inconsistencies. This is not durable grant revalidation or an authenticated source of truth.
\n## W5 — Executable fictional-only stdin review CLI
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

## W6 — Direct installed-source regression witnesses (all in memory)
Three additional tests call the **unmodified installed original** `ScopePolicy.decide()` and `ExecutionPolicy.decide()` on fixed fictional `.example.test` host/capability data, with current in-process ±10/15-minute authorization intervals, no adapters. They demonstrate that two independent original allow decisions can coexist with **distinct actor/reference** or a separately claimed incorrect client, while this unwired review returns HOLD; coherent original source decisions still only produce REVIEW_ONLY and four literal false authority flags. This is an assertion-level governance/lineage gap, NOT evidence of a reachable vulnerable production consumer.

## W7 — Same-ID legacy timestamp binding, sealed non-authority receipts, strict fictional intake
The same synthetic durable grant ID must now preserve the **legacy Authorization owner/reference and its exact UTC validity interval** as well as the durable grant snapshot across distinct claims. Five targeted in-memory methods distinguish per-record coherence from mismatched group-level legacy intervals and confirm two legitimate distinct assets remain REVIEW_ONLY. Two additional CLI tests demonstrate the identical group rule on serialized fictional JSON without leaking partial counts.

Both frozen review receipt dataclasses now declare their four authority flags with `init=False` and validate exact HOLD/REVIEW_ONLY status and bounded reason. Batch HOLD cannot be constructed with a nonzero reviewed count; boolean or out-of-range counts are invalid. Seven tests prove direct constructor flag spoofing and `dataclasses.replace` escalation are rejected on Python 3.11/3.14 (exception types differ), while `dataclasses.asdict` still includes four false flags. This is **a safer preview API, not cryptographic authorization**.

The fictional CLI now validates identifiers using strict ASCII syntax before shape review, and only admits well-formed DNS labels ending in `.example.test`. It denies newline/tab JSON escapes, repeated dots, leading/trailing hyphens, overlong DNS labels and case aliases at intake. The exact UTC `Z` parser uses `datetime.fromisoformat` instead of lazily importing Python's `_strptime`/locale module. Eight additional negative CLI tests cover malformed identities and target aliases. None of these restrictions establish trusted provenance.

## W8 — Adversarial malformed input safety (strictly fictional and offline)
Three new regular acceptance methods run **1,024 seeded malformed byte mutations** of the supplied fictional reference payload, a deep-but-bounded nested JSON document and an actual `python -B` subprocess with 65,537 input bytes. All responses must remain one sanitized HOLD or REVIEW_ONLY JSON object, have a nonzero (2/3) exit code, and keep the four authority flags literally false. The mutation seed is a fixed `1493`; no random network, credentials, real targets, files or tool handlers are used by the review. The subprocess test intentionally launches the CLI locally to prove real stdin resource gating, without scanning targets.

## W10–W11 — Cross-grant collision and order independence
When an otherwise individually coherent asset/capability pair is represented again under a **different** durable grant ID inside one fictional cohort, the whole batch now returns **atomic HOLD** with `reviewed=0`. This is deliberately more conservative than the original three-part `(grant_id, asset, capability)` replay check: a new grant ID must never inflate the apparent number of independently reviewed authorizations for the **same target/capability**. Exactly the same asset with a different capability, and different assets under the same capability, remain distinct review-only claims. This is only bounded synthetic cohort consistency; it is not proof of actual issuance, uniqueness or revocation.

Ten new genuine in-memory/serialized CLI regressions cover collision, reversed order, distinct capability/asset positive controls, different actors with independently matching references, and the 32-record replay ceiling. Corrected the existing 32-record *positive* fixture to use 32 actually different fictional assets; the previous all-on-one-asset fixture correctly became a **red test after intentional fail-closed hardening**, not an authorization bug.

Five further ordinary acceptance methods prove **permutation independence**: 24 orders each of four in-memory claims (ambiguous => HOLD, disjoint => REVIEW_ONLY), six orders each of three canonical JSON CLI claims, and preserved original source objects even after repeated denial. Every output still holds the literal four false authority flags; there is no partial count or trusted source implication. The dedicated workflow enforces an exact 150-method inventory on hosted Python 3.11 and 3.14 and executes the real fictional stdin CLI sample with nonzero exit status.

## Still RED / human-controlled release gates
- Genuine linkage to the authenticated operator, canonical client and engagement, approved asset/capability, signed decision and durable trusted row, *not* equality of two caller-supplied strings.
- Proof of current revocation and revalidation at use time, including atomic proof that approval cannot be replayed against another run or tool. Coordinate with original source owners #99/#100, #1491/#1492 and executor chain without editing their files/branches.
- Security/privacy approval, representative customer consent, exact-head hosted test success, registered `self-hosted,zcloud,vps` job and verified `vps-bb300bba`, then explicit human GO. No bypass for #301 / #1144.
- No activation, active scanning, production consumer wiring or permanent runner changes in this branch.

GitHub issue: https://github.com/Zennay/Lightup/issues/1493
