# Scope authorization incident containment (operator runbook)

Status: **offline operational contract**, M7/ST5. This document neither grants permission nor activates real-target testing. Follow the existing incident command/approval process before production actions.

## Triggers and immediate safety decision

Treat each of the following as **stop and investigate**, not as a warning: grant revoked or expired while work is queued or running; tenant or asset mismatch; grant narrowed between plan and dispatch; a missing/ambiguous audit record; a resolver unavailable or returning an unexpected type; a retry using stale authority; a risk escalation without renewed approval.

Default response: **deny new dispatch and retry**, halt already-running related work through the approved cancellation path, and quarantine results until independently reviewed. Do not use cached grants, CI success, issue labels, or this runbook as substitute authorization. Do not broaden the grant to clear a failed gate.

## Operator sequence

1. **Freeze** the affected client/engagement/run tuple. Capture timestamp in UTC, operator identity, immutable run ID, tenant ID, grant ID and exact code revision. Do not copy secrets or sensitive target payloads into tickets.
2. **Identify blast radius** using stored run/queue identifiers, including retry and child-job IDs. Never enumerate targets or contact an asset during containment merely to gather proof.
3. **Confirm authoritative state** from the canonical current grant store and explicit revocation history. If inaccessible, inconsistent or untrusted, classify authorization as unknown and deny continuation.
4. **Cancel** queued/retrying tasks and request in-flight cancellation using an approved administrative mechanism. Record cancellation request and observed terminal state separately. An API acknowledgement is not proof that a handler stopped.
5. **Preserve evidence**: minimal immutable audit receipt with the expected/observed grant version, decisions, cancellation acknowledgements, final child-job states and reason codes. Redact credentials, tokens, cookies and target data.
6. **Escalate** to the responsible scope owner and tenant representative. Require a fresh, independent approval and new authorization record for any later resumption. Old run IDs and stale approvals must not be replayed.
7. **Verify** no queued retry or child work is dispatchable; confirm tenant isolation and that revoked assets/capabilities remain denied. Use offline/test fixtures or authorized internal controls only.
8. **Close** only after the responsible human has reviewed the evidence chain. Missing records, incomplete cancellation or uncertain handler termination mean **containment unproven**, never success.

## Evidence ledger fields (all required for closure)

| Field | Meaning |
| --- | --- |
| incident_id, observed_at_utc | Stable incident reference and observation time |
| tenant_id, engagement_id, run_id | Tenant-bound correlation without displaying customer target details |
| grant_id, expected_version, observed_version | Exact authorization state comparison |
| revoked_or_narrowed_dimensions | Asset, capability, risk, validity window, or whole-grant denial |
| queued_child_ids, inflight_child_ids | Full relevant workload inventory |
| stop_requested_at, stop_acknowledged_at | Distinguish request from acknowledgement |
| terminal_state_by_child | Verified final state, or explicitly `unknown` |
| audit_receipt_refs | Tamper-evident pointers, not plaintext secrets |
| reviewer_id, review_at_utc, closure_decision | Independent human closure; default open |

If one of these fields is missing, store `unknown` where structurally possible and leave the incident open. Do not fabricate a success receipt.

## Offline tabletop acceptance scenarios

- **Revoked before dispatch:** queue entry never executes; retries remain denied.
- **Narrowed after approval:** newly excluded asset/capability is denied even if snapshot was wider; retained authorized work is separately reconsidered, not implicitly resumed.
- **Expired during multi-step run:** subsequent steps/retries are denied; cancellation attempts and each child's terminal state are independently evidenced.
- **Resolver or audit outage:** inability to prove current authority blocks continuation; incident cannot be closed from a green CI badge.
- **Cross-tenant stale run:** no other tenant's grant, receipt or approval satisfies the affected run.
- **Cancellation acknowledgement only:** close fails until every affected child is verified terminal or human review explicitly documents unresolved uncertainty (which remains open).

## Ownership and non-overlap

This new runbook is operator guidance only. PR #107 owns ToolExecutor implementation; PR #954 owns executor-integrity acceptance composition; PR #982 owns release-gate receipts; PR #983 owns the revocation transition matrix. None of those branches or production source files is changed here. All examples are offline; no scanning, network I/O, targets, deployment, capability execution, or active grant changes are authorized.
