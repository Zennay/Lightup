# Authorization promotion evidence record — blank template

> Template only. All fields are intentionally **UNVERIFIED** until backed by immutable run evidence. This document never authorizes target operations.

## Identity and ownership
- Integration pull request: UNVERIFIED
- Exact integration HEAD SHA (40 hex characters): UNVERIFIED
- Production source owner: UNVERIFIED
- Independent reviewer (must differ from author): UNVERIFIED
- Reviewed approval timestamp (UTC): UNVERIFIED
- In-scope sidecar PRs and their exact SHAs: UNVERIFIED
- Out-of-scope or conflicting PRs: UNVERIFIED

## CI provenance (one row for each required workflow)
| Check | Workflow URL | Run ID | Trigger SHA | Runner identity | Conclusion | Tests pass/fail/skip |
| --- | --- | --- | --- | --- | --- | --- |
| Hosted offline preflight | UNVERIFIED | UNVERIFIED | UNVERIFIED | UNVERIFIED | NOT RUN | UNVERIFIED |
| Canonical permanent self-hosted VPS | UNVERIFIED | UNVERIFIED | UNVERIFIED | UNVERIFIED | NOT RUN | UNVERIFIED |
| Security negative regressions | UNVERIFIED | UNVERIFIED | UNVERIFIED | UNVERIFIED | NOT RUN | UNVERIFIED |
| Canonical positive controls | UNVERIFIED | UNVERIFIED | UNVERIFIED | UNVERIFIED | NOT RUN | UNVERIFIED |

For **every** check, compare the workflow's actual trigger SHA with the integration HEAD; do not reuse a green result from an ancestor commit. Record exact command, environment, log/artifact URL and any skips. A queued, timed-out, cancelled, neutral, skipped or unknown run is **not** success.

## Scope-authorization checks
| Gate | Outcome (PASS / FAIL / NOT RUN) | Immutable proof URL / rationale |
| --- | --- | --- |
| G1 — ownership, overlap and exact SHAs | NOT RUN | UNVERIFIED |
| G2 — exact canonical interaction/risk types | NOT RUN | UNVERIFIED |
| G3 — tenant/engagement/asset/capability/exclusion | NOT RUN | UNVERIFIED |
| G4 — independent approval, revocation and expiry | NOT RUN | UNVERIFIED |
| G5 — live snapshot monotonic narrowing | NOT RUN | UNVERIFIED |
| G6 — canonical evidence sink, no forged execution | NOT RUN | UNVERIFIED |
| G7 — negative and positive offline tests | NOT RUN | UNVERIFIED |
| G8 — exact-head, permanent VPS CI | NOT RUN | UNVERIFIED |
| G9 — no target interaction or external probing | NOT RUN | UNVERIFIED |
| G10 — independent human release approval | NOT RUN | UNVERIFIED |

## Decision
- Decision: **HOLD** (default; must not auto-upgrade)
- Explicit written active-target authorization: **NOT PROVIDED**
- Authorized tenant, target assets, capabilities, risk, exclusions and time window: **NOT PROVIDED**
- Production deployment approved: **NO**
- Reviewer signature / decision rationale: UNVERIFIED

**Promotion rule:** only a named independent reviewer may change HOLD to APPROVE, after G1–G9 are individually PASS with linked exact-head evidence. APPROVE here addresses software release only; real-world active tests additionally require separate explicit signed target authorization and a fresh runtime scope check. Absence of evidence always fails closed.

Related contract: [release evidence gate](scope-authorization-release-evidence-gate.md). Executor/source integration remains owned by PR #107. No application, runner, deployment or target behavior is modified by this document.
