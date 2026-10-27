# Approval replay — isolated acceptance contract

This document and its JSON fixture are **offline acceptance specifications only**. They do not claim to validate the production approval issuer, trusted signatures, nonce storage, expiry, executor authorization, or deployed services. The fixture describes expected decisions, not observed behavior.

## Proposed fail-closed boundary

A human approval must be bound to its canonical **tenant, request identifier, approval identifier, and revision**. Before any active capability dispatch, the source owner should validate authoritative issuer provenance, live status, approval duration, and scope/risk restrictions. Reuse of an already-consumed single-use approval must fail closed, including after retries, concurrent scheduling, and worker restarts. A new distinct authorized request must have its own approval. Denials must not activate targets or silently mint new authorization.

The matrix lives at `tests/fixtures/scope_approval_replay_matrix.json`; `tests/test_scope_approval_replay_matrix_contract.py` verifies its integrity using standard-library unittest. 'conditionally_eligible' is deliberately **not** 'allowed': all existing runtime policy gates remain mandatory. The current matrix cannot prove atomic compare-and-set, durable replay prevention, or canonical grant lineage.

## Ownership / promotion

PR #107 owns ToolExecutor production integration, while existing revocation/provenance/release PRs remain untouched. The source owner must decide whether approval is single-use or whether explicitly authorized bounded multiple invocations are intended; this fixture specifies the **single-use candidate model**, not an adopted production policy. Do not promote it as a security control without design review, production integration and exact-head hosted/permanent-VPS evidence.

No real targets, network requests, scans, capabilities, credentials, or deployment are involved.

## Concurrency / durability candidate-model follow-up

`tests/test_scope_approval_replay_interleavings.py` specifies an **in-memory reference** using a lock to show that eight contenders for one identical key should obtain at most one conditional success. This is neither a production implementation nor a distributed atomicity proof: multiple worker processes, process crashes, storage rollback, duplicate messages, and network partitions are not modeled.

The revision-change example deliberately shows a weakness of tuple-only replay keys: changing an untrusted revision creates a fresh key. Production must resolve a canonical issuer-owned approval identity and validate signed or otherwise trusted revision lineage **before** durable atomic consumption. Never treat caller-supplied tuple fields as authority.

Acceptance for the source owner: define approval-use cardinality; ensure a single durable issuer-controlled consumption transaction or explicitly bounded-use grant, lock/transaction boundaries, crash/retry semantics and denial audit requirements; verify exact-head integration and VPS proof without contacting targets during this test lane.
