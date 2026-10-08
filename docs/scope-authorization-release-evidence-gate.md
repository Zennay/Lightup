# Scope-authorization release evidence gate

Status: **acceptance checklist only** (not evidence of a passing release).
Owner: scope-authorization integration/release reviewer.
Last reviewed: 2026-10-08.

## Purpose

LightUp must remain passive-first. No real-world target interaction is authorized by a green unit test alone. This checklist is an evidence contract for integrating scope-authorization changes from independent RED acceptance branches. It does **not** grant permission, create an engagement, trigger execution or deploy.

## Release gate (all items required)

| Gate | Required evidence | Fail-closed result |
| --- | --- | --- |
| G1. Ownership | Record the production source owner, exact integration PR(s), and reviewed commit SHA(s). Identify duplicate or overlapping sidecars before integration. | Missing owner or unclear scope = no merge. |
| G2. Canonical request | Offline regression shows only exact supported interaction and risk enum values enter a positive policy path; reject booleans, raw integers, foreign enums, strings and unknown interaction kinds. | Unrecognized identity/type = deny. |
| G3. Scope integrity | Exact client/tenant, engagement, asset and capability identities must match approved immutable scope; exclusions and approval boundaries remain effective. | Any mismatch = deny before dispatch. |
| G4. Approval integrity | Independent reviewer identity, non-self-approval, approval status, revocation and expiry are verified at decision time. No stale approval may be revived by mutation. | Unknown/revoked/stale approval = deny. |
| G5. Live revalidation | Compare immutable run snapshot to current same-id authorization; live authority may **narrow**, never add assets, capabilities, higher risk or a wider validity window. | Broader live authority = deny before handler/evidence mutation. |
| G6. Evidence integrity | Evidence sink remains the expected canonical store, records denied decisions without leaking sensitive authorization material, and never reports execution that did not happen. | Missing or fabricated evidence = release not approved. |
| G7. Negative-path tests | Run security-focused in-memory regression tests including malformed fields, boundary times, revoked grants, cross-tenant attempts, and concurrency/state mutation cases. Include positive canonical controls. | Any unreviewed RED test = no release. |
| G8. Runtime validation | On the designated GitHub self-hosted runner, capture exact workflow URL, run ID, SHA, test command, environment and exit status. Review failures and skipped checks. | Queued, cancelled, skipped or unknown is **not** green. |
| G9. Scope of operation | Confirm no network scans, DNS probing, real target access, capability dispatch, or active tests ran as part of this evidence collection. | Unexpected external I/O = incident review, not a pass. |
| G10. Approval | A human reviewer records an explicit acceptance decision with linked proof for G1–G9 before marking integration ready. | No decision = draft/hold. |

## Evidence record (copy per integration)

- Integration PR / exact head SHA:
- Source owner and reviewer:
- Acceptance sidecars included / excluded:
- Negative tests (command, SHA, number passed/failed/skipped):
- Positive controls (command and outcome):
- Runner workflow URL / run ID / environment:
- G1–G10 result (PASS / FAIL / NOT RUN, one per gate):
- Evidence timestamp (UTC):
- Human release decision (APPROVE / HOLD) and rationale:

**Interpretation:** `NOT RUN`, pending CI, a draft PR, or a locally reasoned contract is never a PASS. This file is a release-process aid and cannot substitute for code review, tests, explicit written target authorization or actual independent approval.

## Existing work boundaries

- Issue #119 owns RiskLevel type confusion; do not fork its production fix.
- Issue #986 owns unknown interaction kinds; issue #987 owns passive-public risk enum identity.
- PR #107 and the associated #948–#954 sidecars own ToolExecutor live-grant/evidence integrity, including monotonicity.
- Keep this checklist independent of `src/lightup/execution_policy.py`, executor, state store, scans and deployment automation.

## Safe validation of this document

Review the rendered Markdown and confirm the checklist references the correct integration PRs at release time. No checks are claimed to have run from creating this file.

## Evidence collection worksheet

Use the [blank promotion evidence template](scope-authorization-promotion-evidence-template.md) for every candidate integration. Its defaults are HOLD / NOT RUN; filling it is not proof until independently reviewed against exact-head hosted and permanent-VPS results. A release approval does not substitute for separately approved target scope.
