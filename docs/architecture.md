# LightUp architecture

## Objective

LightUp is designed as a broad AI-assisted security platform with two hard-separated planes:

- **Passive Discovery** for prospecting from public, non-intrusive information.
- **Authorized Assessment** for active testing of owned or explicitly authorized systems.

The current release builds orchestration, authorization, product-domain and evidence infrastructure only.

## Product boundary

An unauthenticated prospect can never become an active target automatically.

```text
Public information
      |
      v
Passive Discovery ---> Prospect Profile ---> Human outreach
                                              |
                                              v
                                      Digital authorization
                                              |
                                              v
                                   Authorized Engagement
                                              |
                                              v
                                      Assessment Engine
```

The execution layer must fail closed if a real-target action has no current authorization grant, exceeds the authorized risk level, uses an out-of-scope capability, or targets an asset outside scope.

## Control plane

Every future active adapter must receive an `ExecutionPermit` from the shared activation gate and satisfy the product-level `ExecutionPolicy`. Adapters may not decide scope themselves. Authorized permits require a current client authorization bound to both the exact normalized target asset and the exact requested capability; an empty legacy capability scope grants no active capability authority. Authorized permits preserve two distinct audit references: the operator activation reference and the client authorization reference; lab permits have no client authorization reference. For every `TARGET_ACTIVE` dispatch, the executor re-resolves the exact grant from authoritative `DomainStore` state before policy evaluation and re-resolves it again immediately before handler dispatch. Revocation or scope drift between those checks fails closed; if the persisted grant changes while remaining live, the exact call is policy-evaluated again against the newest scope. The handler receives that final live persisted grant while the caller's immutable run snapshot remains unchanged, so broader stale authorization metadata cannot re-enter through handler context. A missing resolver, a closed engagement, or a missing, revoked, expired, grant-substituted, or lineage-mismatched durable grant fails closed before the handler runs, including for run contexts created before revocation or engagement closure. Closing an engagement durably revokes every remaining grant; reopening the lifecycle record cannot revive historical authority and requires a fresh grant before target-active work can become eligible again. Grant issuance serializes its engagement-status check and insert against closure, so a concurrent close either rejects the new grant or revokes a grant that committed first.

```text
Target + Auth + Risk -> Execution Policy -> Scope Supervisor
                                             |
                                             v
                                   +-------------------+
Operator activation --------------> | Activation Gate |
                                   +---------+---------+
                                             |
                                        ExecutionPermit
                                             |
                              +--------------+--------------+
                              |              |              |
                              v              v              v
                         web/API lane   identity lane   cloud/host lane
                              \              |              /
                               +-------------+-------------+
                                             |
                                             v
                                     Evidence Ledger
                                             |
                                  +----------+----------+
                                  |                     |
                                  v                     v
                             Verification          Remediation
                                  |                     |
                                  +----------+----------+
                                             |
                                             v
                                           Retest
```

## Agent model

Workers specialize by capability rather than all sharing one giant prompt. The orchestrator can schedule independent lanes in parallel, while a SQLite lease on `(run_id, capability_id)` prevents duplicate work.

Planned roles:

- orchestration/planning;
- scope and policy supervision;
- surface/architecture modeling;
- specialized capability auditors;
- evidence verification;
- remediation engineering;
- detection engineering;
- report synthesis.

The model is never the security boundary. Tool calls are typed and policy checked outside the model.

## Model gateway

The AI integration should remain provider-neutral. Planner, analyst, verifier and reporting roles can later be routed to different models without changing execution policy.

## Adapter contract

Future adapters should be small and capability-scoped. They receive immutable run context and a permit, emit structured observations, and never write directly to another capability's state.

The project intentionally separates:

- **analysis-only** — no target interaction;
- **passive discovery** — public/non-intrusive prospect intelligence only;
- **lab execution** — isolated lab targets;
- **authorized execution** — current authorization + scope + risk + operator activation.

## Evidence model

Evidence metadata contains a SHA-256 digest, source label, capability, run id and timestamp. Raw evidence storage is deliberately separate so secrets can be redacted or access-controlled without breaking lineage.

## Coverage model

Coverage is tracked per domain as `assessed`, `partially_assessed`, `not_applicable`, `not_authorized` or `unknown`. See `docs/coverage-matrix.md`.

Zero findings are not treated as proof of security when material coverage remains unknown.

## Non-goals in M0

M0 does not implement real-target scanners, exploit modules, credential use, payload delivery, persistence or evasion. Those are not needed to prove the product and orchestration architecture.
