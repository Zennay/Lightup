# Security coverage matrix

LightUp must optimize for **known coverage plus explicit unknowns**, not for claiming complete security.

Each engagement should eventually report which relevant domains were assessed, which were not applicable, which were out of scope and which remain unknown.

## Coverage domains

| Domain | Examples of concerns | Initial lane |
| --- | --- | --- |
| External attack surface | domains, subdomains, exposed services, forgotten assets, staging/admin surfaces | external-attack-surface |
| Web applications | authentication, authorization, sessions, input handling, uploads, business logic, configuration | web-baseline |
| APIs | object/function authorization, tokens, response exposure, inventory, integrations, abuse controls | api-baseline |
| Identity & access | MFA, SSO, recovery, privilege boundaries, service identities | identity-access |
| Cloud & IAM | permissions, public storage, network policy, managed services, control-plane exposure | cloud-iam |
| Networks & hosts | service exposure, segmentation, hardening, patch posture, remote access | network-services / host-hardening |
| Containers & Kubernetes | images, registries, RBAC, workload identity, cluster configuration | containers-kubernetes |
| CI/CD | pipeline permissions, deployment credentials, branch controls, artifact trust | cicd |
| Software supply chain | dependencies, SBOM, package risk, build integrity, third-party components | supply-chain |
| Mobile | storage, transport, platform integration, authentication, hardening | mobile |
| Desktop clients | local storage, update flow, IPC, privileges, backend trust | desktop-client |
| Email & domains | spoofing resistance, mail/domain configuration, account security posture | email-domain |
| Secrets | tokens, API keys, config leakage, backups/log exposure | secrets |
| Databases & storage | access controls, encryption, backups, exposure, tenant isolation | database-storage |
| SaaS & third parties | OAuth grants, webhooks, integrations, trust boundaries | saas-third-party |
| Business logic | workflow abuse, role transitions, approvals, billing/credits | business-logic |
| Abuse & fraud | automation abuse, enumeration, resource abuse, unwanted mass actions | abuse-fraud |
| Multi-tenancy | cross-tenant data/function access and isolation failures | multi-tenancy |
| Logging & detection | security telemetry, alerting, auditability, incident visibility | logging-detection |
| Backup & recovery | recoverability, restore controls, resilience | backup-recovery |
| Cryptography | key handling, TLS posture, randomness, certificate lifecycle | cryptography |
| Privacy & data exposure | personal/sensitive data handling, unnecessary exposure, retention | privacy-data |
| AI/LLM systems | prompt injection, tool permissions, data leakage, agent boundaries, AI supply chain | ai-llm |
| IoT/embedded | firmware, device identity, updates, backend trust | iot-embedded |
| OT/industrial | specialist control-system assessment | ot-lab |
| Social engineering | human-layer simulation | social-engineering-lab |
| Physical integrations | access-control and device integrations | physical-security-lab |

## Attack-path reasoning

Findings should not be treated as isolated rows. The AI should maintain hypotheses about how weaknesses could combine.

A later attack-path graph can represent:

```text
observation -> hypothesis -> required control -> authorized validation -> evidence -> finding
```

If a validation step is outside scope or above the approved risk level, it remains an **unverified path** and must not be executed.

## Coverage states

Every domain in a report should have one of:

- `assessed`;
- `partially_assessed`;
- `not_applicable`;
- `not_authorized`;
- `unknown`.

A report with zero findings and large unknown coverage is not equivalent to a clean bill of health.

## Evaluation

Agent improvements should later be benchmarked on isolated labs using at least:

- valid findings;
- false-positive rate;
- coverage achieved;
- evidence quality;
- reproducibility;
- scope/policy violations;
- human interventions;
- time and compute cost;
- remediation quality;
- retest correctness.
