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

## Artifact URL admission
The offline validator now requires unambiguous HTTPS artifact references with a hostname and non-root path, rejecting credentials-in-URL, explicit ports, query/fragment ambiguity, control characters and `.invalid` fixture domains. These checks **do not prove** ownership, availability, artifact integrity, safe DNS routing, or trusted issuance; no network fetch occurs here. Production review must verify artifact provenance via trusted GitHub/job APIs rather than dereferencing attacker-controlled URLs.

## Trusted-job verification boundary
Do not treat a JSON field containing `conclusion: success`, a well-formed job ID, or a plausible GitHub URL as authenticated evidence. Before changing release status, an independent reviewer must obtain the run and job objects from the trusted GitHub API, check repository owner/name, immutable head SHA, matching run/job IDs, completed success status, actual Python version and expected permanent runner identity, and compare artifact provenance. Fail closed on API errors, absent jobs, or mismatches. This document and its structural offline validator deliberately do not perform external requests or authorize real targets.

## Offline job-ID lane regression
An additional fixture now tests valid-looking evidence across three CI lanes and explicitly rejects duplicate job IDs and string-coerced IDs. The fixture exercises only syntactic schema binding; it cannot authenticate GitHub records or establish the actual Python interpreter version. No scanning or production mutation occurs.

## Observed CI job separation (2026-10-09)
GitHub's job endpoint showed run `37929812167` with hosted preflight jobs Python 3.14 (`113817670080`) and 3.11 (`113817670400`), both in progress at observation. Their names explicitly say `not VPS proof`. Another CI run `37929812148` had 3.14 (`113817493189`) and 3.11 (`113817493479`) jobs queued. This is observational evidence only, not green CI or confirmed permanent-runner execution. Re-query authenticated job/run metadata for any later release decision; never promote hosted results to canonical VPS proof.

## Regression fixture repair (2026-10-09)
Fixed two previously contradictory positive fixtures which used `example.invalid` as their artifact source even though the URL predicate correctly rejects `.invalid` domains. Positive controls now use the syntactically accepted `evidence.example.org` example. Also corrected the newline adversarial case to use a real escaped newline rather than a literal backslash-and-n. This only repairs the offline test oracle; example URLs are synthetic and do not authenticate artifacts, approve grants or authorize scans.

## Canonical artifact authority hardening
Offline admission now rejects uppercase, trailing-dot, internationalized/Unicode and backslash-ambiguous artifact authorities. It requires a lowercase ASCII DNS hostname, no embedded port or userinfo, and a non-root HTTPS path. This is only syntactic filtering: independent reviewers must still verify trusted artifact provenance and avoid dereferencing untrusted URLs.

## URL parser ambiguity correction
The artifact URL predicate now explicitly rejects any backslash in the raw URL and percent-encoded bytes in the authority component. Relying only on a parsed hostname can overlook disagreements between URL parsers. This remains offline lexical filtering; trusted source provenance still requires authenticated verification.

## Observed job matching reference
The offline `verify_observed_ci_jobs` predicate now compares a structurally complete manifest with explicitly provided job snapshots: same SHA, run URL and job ID; completed success; explicit Python version and hosted/permanent-VPS runner class. Missing and mismatched snapshots deny. **This is not an authenticated fetch**: caller-provided labels and conclusions are not trusted CI attestations. Do not use it for release or real-target activation without independent GitHub API source verification and production-owner review.

## Observed-job positive and negative controls
The job comparison now has a synthetic passing case covering hosted Python 3.11/3.14 and a distinct permanent VPS record. Negative controls mutate interpreter version, runner classification, completion status, result, SHA and job ID individually and require denial. These are in-memory fixtures, not externally authenticated attestations, and the production release gate remains HOLD.

## Snapshot lane completeness
Offline observed-job validation now requires exactly the three declared lanes, rejects missing or unknown lanes, rejects extra fields in each lane and detects swapped Python records. This is only structural comparison of supplied snapshots; independent authenticated GitHub provenance remains mandatory before source-owner review or release.

## Snapshot type-integrity regression (2026-10-09)
The supplied-job comparison now requires exact runtime field types for job ID, run URL and commit SHA before comparing them with the manifest. This closes Python equality-coercion ambiguity such as `True == 1` or `11.0 == 11` when comparing purported job IDs. Regression cases cover boolean and floating IDs as well as malformed status/version/classification fields. The validator still only checks untrusted, caller-provided snapshots. The mandatory authenticated GitHub API attestation and real-executor zero-I/O tests remain separate owner gates; no real-target authority is issued.

## Snapshot field exact type enforcement
The structural observed-job checker also requires exact built-in strings for status, conclusion, runner class and interpreter version. Polymorphic equality or custom string subclasses cannot satisfy these fields by comparing equal to a trusted literal. This is still only an offline comparison of caller-provided snapshots, not verified CI provenance.

## String-subclass snapshot regression
The latest reference regression constructs a fully populated synthetic job evidence set, confirms its offline positive control, and mutates each observed text field into a `str` subclass with identical text. The comparison must deny polymorphic values for `status`, `conclusion`, `python_version`, `runner_class`, `run_url` and `sha`. This does not authenticate GitHub records or authorize real-target activity; exact-head CI and production-owner review remain required.

## Proof-manifest polymorphic value hardening
Run-level SHA and conclusion, and all artifact-trace SHA fields now require exact built-in strings before any equality check. A same-text `str` subclass is rejected even if its comparison equals the expected SHA or `success`. The synthetic acceptance fixture tests each run and trace lane independently. These offline checks do not authenticate artifacts, replace owner approval, or enable targets.
