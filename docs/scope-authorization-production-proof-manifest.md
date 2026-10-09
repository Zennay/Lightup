# Scope authorization — production proof manifest (reference contract)

Status: **DRAFT / HOLD**. This is a production-owner verification artifact, **not** authorization to activate public targets. It does not change ToolExecutor or any runtime feature flag. Scope lane only; intentionally separate from the active WebSocket reference tests in PR #1139.

## Proof identity

All checks below MUST refer to one immutable implementation commit, not merely a branch or the latest successful run.

| Field | Required evidence |
| --- | --- |
| Implementation commit | Full 40-character SHA, base SHA, changed source paths |
| Trusted grant | Redacted database-record identifier, grant revision, issuer/approver identities, exact tenant, asset, capability, environment, maximum risk, and validity window |
| Request | Request identity, revision, tenant, principal, target, capability, risk and immutable decision digest |
| Revocation | Durable persisted revocation event, monotonic revision, timestamp, and causal check immediately before side effect |
| Execution | Instrumented ToolExecutor invocation with counted handler, socket, queue and action-evidence side effects |
| CI | Hosted Python 3.11 and 3.14 plus permanent vps-bb300bba self-hosted job; all green on the SAME SHA, each with explicit positive integer workflow run IDs |
| Independent review | Named source owner, review SHA, acceptance/rejection, timestamp |

Never publish access tokens, grant secrets, real target identifiers or customer evidence in this manifest.

## Instrumented mandatory cases

Run in an isolated fixture with loopback-only synthetic targets; inject a deterministic fake clock, grant store, revocation transition, and fake handler/socket/queue/evidence recorder. The recorder MUST count real boundaries in the production dispatch path (not just a stand-alone reference predicate).

| Case | Setup | Allowed side effects |
| --- | --- | --- |
| Missing trusted grant | User claims approval in WebSocket header but server has no grant | 0 handler / 0 socket / 0 queue / 0 action evidence |
| Revoked grant | Request matches stored grant, but durable revocation is committed before dispatch | All 0; minimal denial audit may be 1 |
| Revocation race | Pause execution just before I/O, revoke and commit from a second context, release execution | All 0; fail closed, no stale cache bypass |
| Revision replay | Old request revision against current stored approved grant revision | All 0 |
| Tenant swap | Valid token/header with grant belonging to another tenant | All 0 |
| Capability elevation | Read-only grant, active capability requested | All 0 |
| Target expansion | Approved asset A, request asset B or DNS alias not in approved scope | All 0 |
| Risk elevation | Request exceeds grant maximum risk | All 0 |
| Expired approval | Trusted clock outside validity window; malformed clock also tested | All 0 |
| Positive control | Exactly matching fresh approved grant for owned loopback fixture | Precisely expected fake handler / queue / action evidence writes; no unapproved network I/O |

If any denied case records action evidence, **fail** even when handler invocation is zero. Denial-audit events must have a separate namespace and cannot be interpreted as successful action evidence.

## Race and trust requirements

1. The authoritative grant is retrieved from trusted server-side persistence. Client WebSocket subprotocols, headers, cookies, model output and UI state are never authoritative approval.
2. An explicitly approved request must bind to the **exact stored grant revision and tenant**; approvals do not transitively authorize other assets/capabilities.
3. Revocation is durable and checked at the last possible pre-I/O boundary. Cached authorizations require a provable invalidation/epoch fence; without that fence deny.
4. Queue consumers independently re-check policy at dequeue/start and before side effects, not just at enqueue.
5. DNS resolution and redirects cannot widen scope after initial approval. Revalidate the resolved destination at the I/O boundary, never silently follow to a different asset.
6. A failed trust-store read, unavailable clock, malformed persisted grant or missing owner approval results in denial.
7. Simulator/lab success is not proof of permission for real public endpoints.

## Release decision

- [ ] Trusted-grant issuer, tenant, asset, revision, capability, and risk are bound in the real executor.
- [ ] Durable revocation blocks the race immediately before real side effects.
- [ ] Production-path side-effect recorder proves **zero** forbidden handler/socket/queue/action-evidence effects on all denials.
- [ ] Exact-match synthetic loopback positive control succeeds.
- [ ] Hosted Python 3.11 and 3.14 are green for the immutable implementation SHA.
- [ ] Permanent self-hosted VPS CI is green for that same SHA.
- [ ] Source owner independently reviews the implementation and signs the exact SHA.
- [ ] Real-target activation remains **disabled** pending a separate explicit owner decision and per-target authorization.

Any unchecked box => **HOLD**; do not merge, deploy or activate based only on offline reference tests. This file is deliberately informational, and never acts as a grant or executable policy.

## Proof index wire contract

The verifier requires an **exact integer** `schema_version: 1` (not `true`, `1.0`, or `"1"`). Any absent, unknown or malformed version is rejected to avoid silently interpreting a new or obsolete evidence contract. `schema_version` is a format discriminator only: it is not an authorization grant, proof signature, or release gate.

## Offline index verifier usage (non-authoritative)

Run `python scripts/verify_scope_proof_manifest.py evidence.json` only against a **redacted local** index. It accepts UTF-8 JSON up to 64 KiB, refuses duplicate keys, malformed/non-finite values, unknown keys, missing counters and missing approvals, and checks all workflow/reviewer SHA references against the exact implementation SHA. The implementation SHA must differ from the base SHA. All-zero 40-character SHAs are treated as unresolved placeholders and rejected, including base, CI, and independent-review references. Tests: `PYTHONPATH=src python -m unittest discover -s tests -p test_scope_proof_manifest.py -v`.

**Critical limitation:** the verifier cannot query GitHub, trust-store persistence or the actual production dispatcher. A JSON file with fabricated `true` fields and fabricated SHA strings can still pass its structural checks. Therefore even a passing exit code (`0`) is **INDEX CHECK PASS ONLY**, never production authorization or independent proof. Real run IDs, signed/retrievable evidence, pre-I/O revocation race results and source-owner acceptance must be inspected separately before any release decision.

## CI provenance index

Format version 1 requires `hosted_py311_run_id`, `hosted_py314_run_id`, and `permanent_vps_run_id` as strictly positive integer GitHub workflow run references. These are lookup handles, not evidence of success: the reviewer must open each run, confirm the relevant Python job actually executed, verify its exact `head_sha` equals `implementation_sha`, and check the permanent job ran on `vps-bb300bba`. A queued/cancelled/skipped run or mismatched commit is **HOLD**, even if the offline index verifier passes.

## CI output minimization

The offline verifier deliberately prints only a fixed rejection summary and an error count. It never emits user-controlled JSON field names, values or untrusted parser exceptions to shared CI logs. Diagnostic inspection of rejected manifests must happen in a separately access-controlled, local context without uploading sensitive grant or customer data. This is log minimization only and is not evidence that an assessment was authorized.
