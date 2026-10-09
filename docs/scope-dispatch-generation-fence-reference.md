# Scope authorization: dispatch generation fence (offline reference)

## Problem
An already-admitted worker can hold an old authorization decision after its job is cancelled or restarted. A fresh run or approval must not revive the stale worker. Treat a dispatch attempt as bound to one exact tenant, request and generation.

## Reference contract
The accompanying stdlib-only regression module models immutable `DispatchLease` records. A conditional positive requires two exact records, valid exact scalar types, exact matching tenant/request/generation, and both snapshots still active. All mismatch and malformed inputs deny.

A generation is a positive exact integer (not bool), must be issued by a trusted state coordinator, and must advance atomically when a job is cancelled, restarted or superseded. The worker must fetch the **current** persisted lease at the final dispatch boundary; it must never supply the supposedly live record itself.

The reference deliberately **does not** establish authentic provenance or grant authority. Even a positive result must still pass current issuer-owned grant, scoped asset/capability, risk ceiling, approval, expiry, revocation and consent checks, and cancellation should interrupt already-running work. No race-proof or multi-process durability is claimed.

## Source-owner integration acceptance
1. Atomically increment a persisted generation when replacing/cancelling jobs; guarantee monotonicity across restarts.
2. Tie a worker's immutable lease to exact tenant/request and generation at admission, then refetch coordinator-owned current lease immediately before dispatch.
3. Deny stale generation, deactivated lease and cross-tenant/request reuse with **zero handler calls, evidence writes or queue mutations**.
4. Add concurrent cancel-vs-dispatch and restart/recovery integration tests using a controlled fake handler and durable store. Ensure rollback/failover does not reuse generations.
5. Require source-owner review plus exact-head hosted and canonical self-hosted VPS checks before promotion.

## Collision and safety boundaries
Tests and documentation only; **do not** edit production ToolExecutor or ExecutionPolicy files owned by PR #107 or other approval/revocation/queue owners. This contract is an additive reference, not a live gate, deployment, permission grant or production authorization proof. Tests make no DNS, socket, target or capability calls.
