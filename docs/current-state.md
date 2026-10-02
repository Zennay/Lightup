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
  (`lightup.ai.gateway`, see `docs/ai-orchestration.md`), a JSON
  **configuration loader** (`lightup.ai.config`) with a shipped example config
  (`config/gateway.example.json`) and a first real provider
  adapter (`lightup.ai.providers.anthropic_provider`, optional extra
  `lightup[anthropic]`, key via environment variable);
- **typed AI orchestration contracts** with an immutable run context, a policy
  gate before every tool execution and a mandatory evidence ledger
  (`lightup.ai.orchestration`);
- a **lab evaluation foundation** with a lab-only run path and a benchmark
  schema (`lightup.labeval`);
- the **first capability worker**: a lab-only HTTP security-header baseline
  (`lightup.workers.http_baseline`) wired end-to-end through the policy gate,
  evidence ledger, findings and benchmark scoring (`lightup.labrun`,
  CLI `lightup lab-baseline`);
- further lab-only capability workers: **TCP service inventory**
  (`lightup.workers.service_inventory`) and **TLS baseline**
  (`lightup.workers.tls_baseline`: protocol, cipher, chain trust);
- a **planner role** (`lightup.ai.planner`): the model proposes a typed
  multi-lane plan that is strictly parsed and then executed call-by-call
  behind the policy gate, with denials recorded as policy-violation metrics
  and elevation needs routed to humans;
- **login brute-force lockout** in the domain layer
  (`DomainStore.authenticate`), surfaced as HTTP 429 in the web shell;
- a **lab → product findings bridge** with an automated retest loop
  (`lightup.labsync`: fixed / fix_pending / regression semantics) and an
  **AI review pipeline** over findings via the Model Gateway
  (`lightup.ai.pipeline`: verifier, remediation advisor, report synthesizer);
- explicit **coverage tracking** over the whole capability registry
  (`lightup.coverage`): assessed / partially_assessed / not_applicable /
  not_authorized / unknown, with an explicit "not a clean bill of health"
  marker when coverage is materially unknown;
- a dependency-free, loopback-only **web shell** with **session
  authentication and CSRF protection** (scrypt passwords, hashed session
  tokens, operator/client roles; bootstrap via `lightup create-operator`):
  operator dashboard (Overview/Discovery/Clients/Assessments) and client
  portal (`lightup.webapp`, see `docs/webapp.md`);
- **planted-weakness lab fixture profiles** with hand-maintained ground truth
  (`lightup.labfixtures`: exposed / partially-hardened / hardened,
  `lab/vuln_fixture.py` serves them loopback-only) and a **`lightup
  lab-assess` CLI** that runs the planner-driven assessment plus AI review
  offline on a deterministic scripted gateway, or on a real provider via
  `--gateway-config`;
- reporting/redaction helpers;
- a loopback-only lab fixture;
- CI safety tests (129 unit tests), including proofs that unauthorized active
  execution is impossible, risk escalation is blocked without new approval,
  tenants are isolated, passive Discovery cannot invoke active capabilities,
  lab workers fail closed on public targets, and the web shell rejects
  anonymous, cross-tenant and CSRF-less requests.

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
