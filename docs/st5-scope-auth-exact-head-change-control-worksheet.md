# M7/ST5 scope authorization — exact-head change-control worksheet

Status: **non-authoritative integration aid**. This worksheet cannot approve grants, scans, target dispatch, or deployment. Use with the ten-gate release checklist in PR #1020; leave it draft while any source-owner, CI, or human gate is outstanding.

## Freeze and evidence binding

1. Record the immutable head commit **H** of the integrated branch and the parent commit **P** used for the comparison. Verify that PR #100 is integrated (or explicitly account for the stacked parent of #107). If either H or P changes, discard all prior test promotion claims and start a fresh evidence row.
2. For each acceptance suite, record the source paths and tests used, the exact H, workflow file/ref, job URL and conclusion. A green unrelated PR, branch name, latest-main run, previously green SHA, or queued/in-progress/cancelled/skipped conclusion is **not** sufficient.
3. Preserve two independent execution-provenance entries: hosted/offline validation and the canonical permanent self-hosted VPS lane. Validate actual runner identity/labels `[self-hosted, zcloud, vps]` from the completed job, not only a caller-supplied JSON label. A GitHub URL alone is not attestation.
4. Compare the latest commit on PR #107 with its pinned parent #100. Any restack or parent change invalidates prior exact-head proofs, including previously green child runs; run the integrated negative suites again on the new H.

## Required source-owner answers (all must be explicit)

| Gate | Evidence to collect | Fail-closed decision |
| --- | --- | --- |
| Production execution | Which exact source commit integrates live grant revalidation from #107 and the negative tests? | No runtime safety claim while reference-only or RED tests are unintegrated. |
| Enum identity | Where are exact `InteractionMode` and risk-enum type checks enforced? Link regressions for #986 and #987. | Reject truthy values, numeric aliases, subclass/duck objects and mismatched enum instances; zero handler calls. |
| Authorization identity | Which durable grant, tenant, engagement, request revision, actor approval and target identity are read **at dispatch**? | Mismatched, revoked, stale, or missing claims deny before side effects; no cross-tenant fallback. |
| Scope contraction | Which tests prove persisted scope, narrower host/path/risk limits, and closed-then-reopened engagement override cached authority? | Cached broader scope and historical grants never restore authority. |
| Human release | Who independently reviewed source and exact-head CI, and who made the separate final release decision? | Author/self-approval or ambiguous reviewer identity is not an approval. |

## STOP / rerun triggers

- **Head changed:** mark all old test rows stale and re-run every affected suite on the new exact H.
- **Permanent VPS run queued/cancelled:** record as pending or inconclusive; do not substitute hosted green.
- **Failure or unexpected handler/network contact:** stop promotion, preserve sanitized logs, notify source owner; no automatic activation or implicit override.
- **Unresolved source-owner comments or RED contract:** retain draft; an offline reference passing is *not* production policy enforcement.
- **No explicit scope/consent for real target:** keep real-target execution disabled irrespective of CI outcomes.

## Suggested evidence record (human-entered; not verification)

```text
integration_head_sha:
parent_base_sha:
source_owner:
reviewer_independent_of_author:
hosted_workflow_job_url:
hosted_job_head_sha:
hosted_conclusion:
vps_workflow_job_url:
vps_job_head_sha:
vps_runner_labels_verified:
vps_conclusion:
negative_suites_integrated_on_head:
zero_side_effect_evidence:
human_release_decision:
real_target_activation: DISABLED
```

Do **not** store secrets, bearer tokens, customer identifiers, live target details, or privileged logs here. Cross-check evidence with the GitHub workflow API and production source owner rather than treating this checklist as a machine-verifiable receipt.
