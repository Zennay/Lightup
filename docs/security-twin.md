# Security Twin and Future Security

## Purpose

The Security Twin is LightUp's strategic differentiation layer.

LightUp must remain capable of finding and validating vulnerabilities that
exist **today**. The Security Twin adds a second capability: reason about and
safely validate whether a proposed change creates new exposure **before that
change reaches production**.

The two lanes are intentionally complementary:

```text
Current Security: What is exploitable now?
Future Security:  What becomes exploitable if we ship this change?
```

## Product promise

> **LightUp finds what is vulnerable today and proves whether the change you are about to ship makes you vulnerable tomorrow.**

## What the twin represents

Each customer should eventually have a durable, versioned, evidence-backed
security model containing:

- assets and services;
- applications, APIs and routes;
- identities, roles, permissions and trust relationships;
- cloud/IAM and infrastructure topology;
- code/config/IaC references where available;
- network reachability and security boundaries;
- sensitive data flows;
- assessed/unknown/not-authorized coverage;
- findings, remediation and retest state;
- proven attack paths and prerequisites;
- evidence lineage;
- historical regressions and changes.

Every twin fact needs provenance. The store must distinguish at least:

- **observed** — directly collected from an authorized source;
- **verified** — independently supported by evidence/test execution;
- **inferred** — modelled by reasoning but not yet verified;
- **declared** — supplied by the customer or an integration.

An LLM statement alone is never a verified fact.

## Current-state attack graph

The twin should expose an attack graph derived from verified relationships and
findings. Nodes may represent assets, identities, applications, services,
permissions or sensitive resources. Edges represent reachable or demonstrated
security transitions.

A path must preserve evidence references and preconditions. LightUp should be
able to explain not only that a risk exists, but why the path is possible.

## Future-state twin

A proposed change creates a separate future-state model. It must not mutate the
current twin until the change is actually accepted/deployed and re-observed.

Candidate change sources:

- GitHub/GitLab pull request or commit;
- OpenAPI / GraphQL schema change;
- Terraform / Pulumi / CloudFormation;
- Kubernetes manifests and policies;
- cloud IAM role/policy change;
- firewall/security-group/network-policy change;
- application/service configuration.

The ingestion layer should produce a normalized `ChangeSet` that records:

- changed objects;
- added/removed permissions;
- changed routes or services;
- changed trust/reachability relationships;
- uncertainty and missing context;
- source reference (PR, commit, deployment, config revision).

## Adversarial change simulation

The preferred verification hierarchy is:

1. materialize the proposed state in an isolated representative environment;
2. run targeted capability lanes against that environment;
3. verify findings through the existing evidence/verifier contracts;
4. compare the resulting future attack graph with the current graph.

If a proposed state cannot be materialized safely, LightUp may perform
analysis/modelled reasoning, but it must label the conclusion as inferred
rather than verified.

## Security delta

The core output is not another flat vulnerability list. It is a delta:

- **introduced** attack paths/findings;
- **removed** paths/findings;
- **worsened** blast radius or privilege;
- **improved** boundaries or mitigations;
- **unknown** consequences requiring more evidence.

Example:

```text
PR #812
  -> adds /invoice/export
  -> service role gains bucket read
  -> tenant boundary becomes reachable
  -> isolated test reproduces cross-tenant invoice access

Verdict: BLOCK
Introduced by: PR #812
New attack path: customer -> export API -> service role -> other tenant invoices
Evidence: verified in isolated future-state environment
Fix: generated/remediation-linked
Retest: pending
```

## Pre-merge / pre-deploy verdicts

A customer policy can eventually map verified deltas to:

- `PASS`
- `PASS_WITH_WARNING`
- `REVIEW_REQUIRED`
- `BLOCK`

The verdict must be explainable and evidence-linked. Unknown coverage should
never be silently converted into a pass.

## Reuse existing LightUp primitives

The Security Twin must reuse the existing platform contracts rather than create
a second security system:

- AuthorizationGrant
- ScopeDefinition
- AssessmentMode
- RiskLevel / risk elevation
- Capability registry
- ToolExecutor policy gate
- Evidence ledger
- Verifier
- Finding / remediation / retest
- Coverage tracking
- tenant isolation

Future Security must **not** weaken Current Security safety boundaries.

## Initial implementation roadmap

### ST0 — Twin domain primitives

- versioned SecurityTwin;
- TwinFact with provenance/confidence/evidence refs;
- normalized nodes/relationships;
- current-state snapshot;
- initial attack-path representation.

### ST1 — Current state projection

- project verified findings and coverage into the twin;
- create current attack graph;
- expose explainable path queries.

### ST2 — Change ingestion

- GitHub PR/commit ChangeSet;
- IaC/config ChangeSet adapters;
- immutable future-state branch of the twin.

### ST3 — Future-state lab materialization

- isolated environment builder for supported change types;
- explicit equivalence/limitations metadata;
- targeted assessment planning based on the change.

### ST4 — Attack graph diff

- introduced/removed/worsened/improved path classification;
- evidence-linked delta report;
- unknown/insufficient-evidence state.

### ST5 — CI verdict

- GitHub status/check integration;
- configurable pass/warn/review/block policy;
- remediation suggestion and automatic future-state retest.

### ST6 — Continuous learning

- promote deployed/observed future state into the current twin;
- retain history;
- detect regressions;
- prioritize tests using previous evidence without treating historical assumptions as current facts.

## Safety boundary

A future-state model is not authorization.

- real-target execution still requires valid authorization and scope;
- public/real systems cannot be reached merely because they appear in a future-state model;
- elevated/destructive simulations remain isolated or explicitly approved;
- uncertainty must be surfaced, not hidden;
- customer-provided code/config and secrets require tenant-isolated handling.
