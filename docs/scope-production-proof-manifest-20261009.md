# Scope authorization: production proof manifest (owner handoff)

Status: **HOLD / non-executable**. This document describes acceptance evidence; it does not authorize targets, change policy, or assert production readiness.

## Exact implementation identity
Fill in only from observed CI/owner evidence:

| Field | Evidence |
| --- | --- |
| Reviewed implementation SHA | TBD |
| ToolExecutor owner PR / review | TBD (#107) |
| Trusted destination-metadata integration | TBD (#1093) |
| Destination argument binding | TBD (#1092) |
| Persistent grant source and revision | TBD |
| Hosted Python 3.11 / 3.14 workflow + SHA | TBD |
| Permanent VPS runner workflow + SHA | TBD |
| Negative I/O trace artifact | TBD |
| Positive local-lab trace artifact | TBD |

**Release rule:** all evidence must refer to the same immutable implementation SHA. A queued, cancelled, skipped or successful *other-SHA* run never satisfies the gate.

## Instrumented acceptance scenario
Run exclusively with an isolated offline lab and instrument the real production `ToolExecutor.execute` boundary. Stub or deny DNS resolution, sockets, subprocesses, HTTP clients, retries, persistence writes, and queue submission; count invocation attempts at every boundary, not only successful responses. Never use a real target.

1. Instantiate a persisted tenant-scoped, asset-scoped, capability-scoped grant with a trusted issuer, revision, risk approval and validity interval. The caller must not be able to substitute or mutate this stored record.
2. Negative cases (separately): missing grant; mismatched tenant/engagement/asset/capability; issuer mismatch; risk escalation; expired or not-yet-valid grant; revoked grant; stale revision; corrupt validity timestamps; crafted endpoint/host/port/port-set arguments that diverge from the authorized asset; caller-declared destination roles.
3. Revalidate the grant and destination binding **immediately before each dispatch attempt**; introduce a deterministic revocation between planning and dispatch, then between first attempt and retry/redispatch. All attempts after revocation must deny.
4. For every denied case assert: **zero handler calls, DNS calls, socket opens, HTTP calls, subprocesses, retry submissions, queued work, action-evidence writes and target-side effects**. A minimal sanitized denial-audit record is allowed and must never be counted as action evidence.
5. Positive control: an exact-match, owner-approved *loopback-only lab* grant dispatches exactly once through the instrumented executor; observe evidence semantics without external connectivity. Removing this control invalidates proof because blanket-deny is not the acceptance goal.
6. Independently verify parameter metadata and values: only registry-owned immutable destination roles are authoritative; exact built-in primitive types, finite numeric values, canonical identities and bounded port sets are checked pre-I/O.

## Failure modes and acceptance
- A missing trace counter is **unknown**, not zero.
- Any uninstrumented I/O escape is a failed test, not a skipped assertion.
- Any stale grant cache/replayed request after revocation fails the gate.
- Approval in a header, planner output, model response or request body is not issuer provenance.
- Passing mock/reference tests alone does not prove the real executor's enforcement.
- The production owner must review the exact changed code, and CI must prove both hosted Python versions plus the canonical self-hosted VPS lane on that exact SHA.

## Ownership and non-interference
This is a documentation-only reference pack. Do not merge or deploy it as production authorization. Do not modify #107, #1092, #1093, other workers' branches, or canonical runner scheduling from this lane. Real target activation stays disabled until explicit human authorization and all proof gates are satisfied.

## Machine-readable evidence state

The companion JSON manifest remains `release_gate: HOLD` with unknown/null evidence. The offline checker accepts `release_gate: REVIEWED` only **after** independent source-owner review and evidence links have been populated and authenticated. Even a fully evidenced `REVIEWED` fixture must keep `real_target_activation: false`: this is a release-evidence assessment, **not** an authority issuance or real-target activation mechanism. No actor may transition a manifest to REVIEWED solely on the basis of this offline checker; linked run URLs and artifacts must be verified independently against the exact SHA and trusted providers. Synthetic acceptance fixture URLs do not provide genuine proof.

CI statuses `queued`, `cancelled`, `skipped` and `failure` never count as success. A missing counter or boolean masquerading as a zero integer fails closed. Missing revocation, destination metadata, positive lab or negative executor artifacts also fails closed. This checker deliberately performs no URL fetch, network I/O, scope grant updates or dispatch.

The offline evidence checker additionally requires **three distinct canonical GitHub Actions run URLs**, one for each hosted 3.11, hosted 3.14, and permanent VPS proof lane. Reusing a single green run across separate lane fields is rejected. Run identifiers and URL shape are syntactic checks only: reviewers still must inspect GitHub's authenticated run/job metadata, runner labels, exact SHA and actual Python-version coverage. A single workflow run with two version jobs may require a future schema version carrying job IDs instead; do not fabricate separate run URLs to pass this reference gate.

## Schema v2: job-level CI evidence
Hosted Python 3.11 and 3.14 may legitimately share **one workflow run URL**. They must carry distinct positive integer `job_id` values to identify separately reviewable execution jobs. The permanent VPS job must have its own run URL and another distinct job ID. The offline validator only checks structure and equality; source-owner review must verify each job through authenticated GitHub Actions API, including the exact implementation SHA, runner label, Python version, job conclusion, and actual artifacts. Never fabricate job identifiers. Schema v1 evidence is rejected until explicitly migrated.

## Review URL and cross-repository provenance hardening
The offline checker now accepts a canonical HTTPS `github.com/<owner>/<repo>/pull/<number>` review URL and requires every CI run URL to belong to **that exact repository path**. It rejects lookalike hosts, user-info redirects, query additions on the review reference, and cross-repository run substitutions. This is **lexical validation only**: an untrusted actor can still type plausible GitHub URLs and successes into JSON. The production owner must independently retrieve GitHub's authenticated review and job evidence and verify identities, approvals and runner provenance before any release decision. The manifest remains HOLD and does not grant permission to scan real targets.

## Closed evidence-envelope shape (schema v2)
The offline schema-v2 validator now refuses **unknown top-level properties and missing required properties**, even when all other values in an otherwise valid synthetic manifest pass. This prevents silently ignoring caller-supplied fields such as `review_override` that could be mistaken for authorization by a downstream consumer. It does not yet reject unknown nested properties or authenticate linked evidence; these remain owner-owned follow-up checks. A passing synthetic fixture is never release approval. Release remains HOLD, with target activation disabled.

Nested evidence dictionaries are now also closed: CI jobs allow only `sha`, `conclusion`, `run_url`, `job_id`; negative and positive traces allow their defined counters; revocation and metadata artifacts allow only `sha` and `artifact_url`. Unexpected keys are denied, not silently ignored. This remains a local structural test, not independently verified GitHub evidence.
