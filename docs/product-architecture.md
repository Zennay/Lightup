# LightUp product architecture

## Product goal

LightUp is an AI-assisted security platform for multi-client assessment workflows. It has two deliberately separated planes:

1. **Passive Discovery** for finding prospects from public, non-intrusive signals.
2. **Authorized Assessment** for active testing only after a valid authorization and scope grant exists.

The boundary between these planes is a backend invariant, not a UI convention.

## Primary user journeys

### Operator/admin

- review discovered prospects;
- create and manage clients;
- review assessment requests submitted by clients;
- define assets, exclusions, permitted capabilities, test windows and maximum risk;
- record signed authorization;
- approve the assessment;
- monitor findings, evidence and remediation;
- approve risk elevation when required;
- schedule retests and later continuous assessments.

### Client

- sign in to a dedicated client account;
- request an assessment;
- provide scope and authorization information;
- review findings, impact and remediation;
- track remediation progress;
- request or view retest results.

## Core domain hierarchy

```text
Organization
  -> Client
     -> Engagement
        -> AuthorizationGrant
        -> ScopeDefinition
        -> AssessmentRequest
        -> AssessmentRun
           -> CapabilityLane
           -> Evidence
           -> Finding
           -> Remediation
           -> Retest
```

## Execution modes

- **Analysis only** — no target interaction.
- **Passive discovery** — public/non-intrusive information only; no active verification.
- **Lab autonomous** — isolated lab targets; used for agent R&D and evaluation.
- **Authorized assessment** — active target interaction only with a current authorization grant.

## Risk levels

| Level | Meaning | Approval behavior |
| --- | --- | --- |
| 0 | Analysis only | No active execution |
| 1 | Passive | Public/non-intrusive collection only |
| 2 | Low impact | Requires authorization for real targets |
| 3 | Standard | Requires authorization for real targets |
| 4 | Elevated | Requires explicit step-up approval |
| 5 | Destructive simulation | Isolated lab only |

Risk is enforced by the backend. The UI slider is only a representation of the policy.

## AI architecture

The model is a planner/analyst, not the security boundary.

```text
Web UI
  -> Application API
  -> Authorization + Scope + Risk Policy
  -> AI Orchestrator
  -> Typed Tool Registry
  -> Capability Workers
  -> Evidence Ledger
  -> Verifier
  -> Findings + Remediation
```

Every future active tool call must carry immutable run context and pass policy enforcement before execution.

## Model gateway

The AI layer must stay provider-neutral. A future model gateway can route separate roles to different models:

- planner;
- analyst;
- verifier;
- report synthesizer;
- remediation advisor.

Model choice must be configuration, not business logic.

## Prospect conversion

```text
Passive signals
  -> Prospect profile
  -> Operator outreach
  -> Client interest
  -> Digital authorization
  -> Authorized engagement
  -> Active assessment
```

A prospect never becomes an active target automatically.

## Subscription readiness

Authorization records support future recurring retests. Continuous assessment must still honor:

- authorization validity;
- asset scope;
- permitted capabilities;
- maximum risk;
- maintenance windows;
- explicit step-up approval for higher-risk actions.
