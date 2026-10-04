# LightUp product architecture

## Product goal

LightUp is an AI-assisted security platform for multi-client security validation. Its core product promise is:

> **LightUp finds what is vulnerable today and proves whether the change you are about to ship makes you vulnerable tomorrow.**

LightUp therefore has two complementary security value lanes:

1. **Current Security** — evidence-backed testing of the environment that exists now, including vulnerabilities, misconfigurations and attack paths on explicitly authorized systems.
2. **Future Security** — adversarial simulation of proposed code, API, IaC, IAM, cloud and configuration changes before they reach production.

These lanes are connected by a persistent **Security Twin**: an evidence-backed model of each client's assets, applications, APIs, identities, roles, cloud resources, trust relationships, data flows, findings, fixes, coverage and proven attack paths.

LightUp also has two deliberately separated interaction planes:

- **Passive Discovery** for finding prospects from public, non-intrusive signals.
- **Authorized Assessment** for active testing only after a valid authorization and scope grant exists.

The authorization boundary is a backend invariant, not a UI convention. Future-state simulation must never become a route around real-target authorization.

## Product differentiation

LightUp is not intended to be only an autonomous pentest scanner. The differentiating layer is continuous reasoning over both the **current** and **proposed future** security state.

The long-term loop is:

```text
Observe current state
  -> Test current vulnerabilities
  -> Build/update evidence-backed attack graph
  -> Remediate + retest
  -> Observe proposed change
  -> Build future-state twin
  -> Run isolated adversarial simulation
  -> Compare current vs future attack paths
  -> Block/regress/approve change
  -> Learn into the Security Twin
```

A Future Security result should answer concrete questions such as:

- which new attack path is introduced by this pull request or infrastructure change?
- which existing attack path disappears after the proposed fix?
- does an IAM change increase blast radius?
- does a new API route introduce cross-tenant or privilege-boundary risk?
- which single proposed remediation removes the most proven exposure?

## Security Twin

The Security Twin is a durable customer-specific model, not a one-off scan result.

It should eventually include:

- assets and reachable services;
- applications, APIs and exposed routes;
- identities, roles, permissions and trust relationships;
- cloud/IAM and infrastructure topology;
- code/config/IaC references where available;
- data flows and sensitive data boundaries;
- findings and evidence lineage;
- remediation and retest state;
- assessed, unknown and unauthorized coverage;
- proven attack paths and their prerequisites;
- historical changes and regressions.

The twin must distinguish observed facts, inferred relationships and verified findings. AI output alone is never treated as ground truth.

## Future Security / adversarial change simulation

A proposed change may create a **future-state twin** without mutating the current twin.

Supported change inputs should eventually include:

- source-code pull requests and commits;
- API/OpenAPI/GraphQL changes;
- Terraform, Kubernetes and other IaC diffs;
- cloud/IAM and role-policy changes;
- security group/firewall and network-policy changes;
- application and service configuration changes.

Where practical, LightUp should materialize the future state in an isolated representative environment and run the same evidence/verifier pipeline used by Current Security. When full materialization is not possible, LightUp must clearly mark the result as modelled/inferred rather than verified.

The output is a current-vs-future delta:

```text
Change
  -> Future-state model
  -> Candidate security hypotheses
  -> Isolated verification where possible
  -> Current attack graph vs future attack graph
  -> Introduced / removed / worsened / improved paths
  -> Evidence + remediation
  -> Automated retest
  -> Pre-merge / pre-deploy verdict
```

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
- schedule retests and later continuous assessments;
- review Security Twin changes and current-vs-future attack-path deltas;
- approve, warn or block pre-deploy changes according to customer policy.

### Client

- sign in to a dedicated client account;
- request an assessment;
- provide scope and authorization information;
- review current findings, impact and remediation;
- track remediation progress;
- request or view retest results;
- inspect which proposed changes introduce or remove proven exposure.

## Core domain hierarchy

```text
Organization
  -> Client
     -> SecurityTwin
        -> CurrentState
        -> ProposedFutureState
        -> AttackGraph
        -> ChangeDelta
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
- **Lab autonomous** — isolated lab targets; used for agent R&D, benchmark evaluation and safe future-state simulation.
- **Authorized assessment** — active Current Security target interaction only with a current authorization grant.
- **Future simulation** — a proposed state is assessed in an isolated or modelled environment. It never grants permission to interact with a real target that is not otherwise authorized.

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
  -> Security Twin / State Model
  -> AI Orchestrator
  -> Typed Tool Registry
  -> Capability Workers
  -> Evidence Ledger
  -> Verifier
  -> Attack Graph + Findings
  -> Remediation + Retest
```

Every future active tool call must carry immutable run context and pass policy enforcement before execution.

## Model gateway

The AI layer must stay provider-neutral. The model gateway can route separate roles to different models:

- planner;
- surface analyst;
- security analyst;
- verifier;
- attack-path reasoner;
- remediation advisor;
- report synthesizer;
- change-impact analyst.

Model choice must be configuration, not business logic.

## Prospect conversion

```text
Passive signals
  -> Prospect profile
  -> Operator outreach
  -> Client interest
  -> Digital authorization
  -> Authorized engagement
  -> Current Security assessment
  -> Security Twin
  -> Continuous current + future validation
```

A prospect never becomes an active target automatically.

## Subscription readiness

Authorization records support future recurring retests and continuous Current/Future Security. Continuous assessment must still honor:

- authorization validity;
- asset scope;
- permitted capabilities;
- maximum risk;
- maintenance windows;
- explicit step-up approval for higher-risk actions.

## Roadmap implication

The existing assessment engine remains core product functionality. Security Twin / Future Security is an additional strategic layer, not a replacement.

A later milestone should deliver:

1. persisted Security Twin primitives;
2. current-state attack graph built from verified evidence;
3. change ingestion for PR/config/IaC/IAM deltas;
4. future-state twin generation;
5. isolated future-state adversarial simulation;
6. current-vs-future attack-path comparison;
7. pre-merge/pre-deploy verdicts;
8. remediation and automatic retest that update the twin.


## Security Twin and Future Attack Graph

The Security Twin is a persistent, evidence-backed model of a client's security-relevant state. It stores the relationships needed to reason about and validate attack paths over time.

Current environment -> observe + assess -> evidence-backed Security Twin -> Current Attack Graph -> fix + retest -> proposed change -> Future-state Twin -> isolated adversarial simulation -> Future Attack Graph -> compare paths -> approve/block/remediate -> retest -> learn back into Twin.

### Required twin inputs

- application and API inventory;
- identities, roles and privilege relationships;
- cloud/IAM resources and trust edges;
- network/service relationships;
- repositories and relevant code/config/IaC changes;
- data flows and sensitive-data boundaries;
- findings, evidence, remediation and retest state;
- coverage state and explicit unknowns;
- proven attack paths and failed hypotheses.

### Future Security verdict

For an eligible proposed change, LightUp should report which attack paths are newly introduced, disappear or become more severe; which code/config/IAM/infra change introduced the delta; whether each claim is hypothesized, observed or validated; the recommended remediation; and whether the remediation passed automatic retest.

This future-security layer does **not** replace present-day pentesting. It extends it with predictive, pre-merge/pre-deploy adversarial validation.
