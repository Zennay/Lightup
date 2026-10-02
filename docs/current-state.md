# Current state

LightUp is in **M1 — Platform skeleton**: the M0 guardrails are unchanged, and
the first product layers now exist on top of them.

Current activation mode: **plan-only**.

The repository contains:

- authorization/scope contracts;
- product-level engagement, risk and execution-policy contracts;
- a hard separation between passive prospect discovery and active authorized assessment;
- an extensible security coverage registry;
- run/evidence state and collision-safe capability leases;
- a multi-client **domain/persistence layer** (`lightup.domain`): clients,
  users/roles, assessment requests, engagements, authorization grants, risk
  elevation approvals, findings/retest status and prospects, with tenant
  isolation enforced in code (`AccessContext`);
- a provider-neutral **AI model gateway** with role abstractions
  (`lightup.ai.gateway`, see `docs/ai-orchestration.md`);
- **typed AI orchestration contracts** with an immutable run context, a policy
  gate before every tool execution and a mandatory evidence ledger
  (`lightup.ai.orchestration`);
- a **lab evaluation foundation** with a lab-only run path and a benchmark
  schema (`lightup.labeval`);
- a dependency-free, loopback-only **web shell**: operator dashboard
  (Overview/Discovery/Clients/Assessments) and client portal
  (`lightup.webapp`, see `docs/webapp.md`);
- reporting/redaction helpers;
- a loopback-only lab fixture;
- CI safety tests (64 unit tests), including proofs that unauthorized active
  execution is impossible, risk escalation is blocked without new approval,
  tenants are isolated and passive Discovery cannot invoke active capabilities.

Active real-target interaction remains intentionally unimplemented. No
real-target network adapters exist; the web shell cannot trigger execution.

## Current product direction

LightUp is a standalone, multi-client web product with:

- an operator/admin dashboard;
- a minimal client portal;
- client-submitted assessment requests;
- operator approval before active execution;
- digital authorization and scope records;
- configurable risk levels with step-up approval;
- future recurring retests for subscription engagements;
- passive-first prospect discovery.

The UI direction is deliberately minimal and uses progressive disclosure. See `docs/ui-principles.md`.

## Safety invariant

`UNAUTHORIZED -> PASSIVE DISCOVERY ONLY`

No real-target active adapter may execute without a current authorization grant and successful scope/risk policy checks.

Canonical project planning and handoff live in the LightUp Notion project pages. zCloud only registers and monitors this repository.
