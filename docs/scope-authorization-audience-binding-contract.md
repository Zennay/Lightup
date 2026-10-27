# Scope capability audience binding — offline acceptance contract

Status: proposed fail-closed acceptance contract; **not** a deployed authorization mechanism.

## Boundary

A grant's audience identifies the single intended execution boundary (service or adapter) where a named capability may be invoked. Target host, tenant ID, engagement ID, capability name, action mode, and audience are **separate** authorization dimensions. A matching target alone must never substitute for a matching audience. A request's self-asserted audience is untrusted; the trusted dispatcher must determine its own immutable audience identity.

## Required decisions

1. Missing, empty, null, non-string or oversized grant audience: deny.
2. Missing, empty, null, non-string or oversized dispatcher audience: deny.
3. Audience equality is exact, case-sensitive and Unicode-codepoint-sensitive; no trimming, casefolding, URL decoding, aliases, suffix matching, globbing or prefix matching.
4. Only an explicitly registered, trusted, service-side dispatcher audience can satisfy the binding; model output, client parameters, findings, callbacks and plans must not select it.
5. Replay of a valid grant at a different adapter/audience must deny, even when tenant, target and capability match.
6. A change to the trusted adapter identity invalidates an earlier authorization snapshot; revalidate immediately before dispatch and between steps.
7. Audit the denial with non-secret reason code `audience_mismatch` or `audience_invalid`; never include raw grant, credentials or arbitrary untrusted labels.
8. Audience matching is necessary, never sufficient: all existing tenant, explicit human consent, risk, scope, live-grant lineage, expiry and revocation gates still apply.
9. This contract grants **no** network capability or real-target permission.

## Offline example vectors

| Grant audience | Trusted dispatcher audience | Expected |
| --- | --- | --- |
| `lab.http-baseline.v1` | `lab.http-baseline.v1` | audience-only match, still requires other gates |
| `lab.http-baseline.v1` | `lab.tls-baseline.v1` | deny |
| `lab.http-baseline.v1` | `LAB.HTTP-BASELINE.V1` | deny |
| `lab.http-baseline.v1 ` | `lab.http-baseline.v1` | deny |
| `lab.http-baseline.v1` | `lab.http-baseline.v1/child` | deny |
| empty / null / non-string | any | deny |
| any | empty / null / non-string | deny |

## Integration ownership and proof

Production grant issuance, immutable dispatcher identity, execution admission and per-step revalidation belong to production executor owner PR #107. Existing revocation and release-proof PRs remain independently owned. The reference tests accompanying this contract intentionally **do not** import production executor code or assert production correctness. Before promotion: owner-approved integration, negative-path production tests, exact-head hosted CI and permanent VPS offline evidence. Never perform external scans or enable active real targets to validate this contract.
