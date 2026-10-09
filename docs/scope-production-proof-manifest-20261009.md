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

## Gate-state exact identity tests
Synthetic positive fixture and negative controls now verify that `REVIEWED` cannot be supplied by a `str` subclass and schema version cannot be a boolean, while an activated target flag or polymorphic implementation SHA is denied. The checker remains local-only; source-controlled evidence and real-target authorization are independent.

## HOLD immutability and fabricated CI evidence (2026-10-09)
Added regression coverage that a held, incomplete persisted manifest remains unchanged after observational checks, and cannot be promoted by caller-supplied `completed/success` snapshots. This specifically separates observation from authorization. Verified GitHub API run/job provenance, same implementation SHA, permanent VPS execution and owner review remain unfulfilled release gates. No active targets, dispatch or production executor changes.

## Actual GitHub job observation and VPS false-positive guard
Observed GitHub Actions run `37931523743` reports jobs `113823282481` (Python 3.11) and `113823282961` (Python 3.14), both explicitly named `Offline preflight Python ... (not VPS proof)` and in progress at observation time. These are **not permanent VPS proof**. The offline snapshot comparison now additionally requires `job_name`, and rejects an explicitly `not VPS proof` job if assigned to the VPS lane. This negative guard is not positive VPS attestation: a label can be forged in a caller-provided snapshot. Reviewers still need authenticated GitHub job metadata, verified permanent runner identity and exact-SHA success.

## Hosted preflight is never permanent-runner attestation
The offline checker now rejects `offline preflight` job names in the `permanent_vps` lane even if the words `not VPS proof` are omitted; regression tests also deny a job with a superficially VPS-looking name when its runner class is hosted. This is negative classification only, never affirmative runner identity. Permanent runner identity requires independently authenticated GitHub job/run records and owner acceptance.

## VPS job-label regression refinements
The negative VPS classification suite now explicitly rejects uppercase `OFFLINE PREFLIGHT` labels and blank names. The check is case-insensitive and deliberately deny-only: it cannot authenticate runner identity or prove VPS execution. Require exact-head authenticated GitHub job provenance and permanent runner-owner approval before any change to HOLD.

## Observed run-ID linkage
The offline CI snapshot comparison now requires an exact built-in integer `run_id` in every observed job and checks it against the canonical integer run ID encoded in the manifest's GitHub Actions run URL. It rejects a mismatched VPS run ID and Python boolean masquerading as a numeric ID. This is consistency validation, **not independently authenticated GitHub attestation**. Production activation remains disabled until verified GitHub provenance, permanent VPS execution and owner review are complete.

## Interpreter label consistency (2026-10-09)
Offline supplied CI job snapshots now reject contradictory Python interpreter labels: an observed record declaring `python_version: 3.11` cannot simultaneously claim `Python 3.14` in its job name. The parser checks the interpreter value type before concatenation, so malformed types fail closed. This is a negative consistency check, not authenticated interpreter or runner attestation. The observed hosted run `37932067203` contained a successful Python 3.11 preflight job (`113825051340`) and a Python 3.14 job (`113825051835`) still in progress at observation time; neither is permanent VPS proof.

## Interpreter label substring-spoof regression
An observed Python 3.11 job must not pass merely because its name contains that substring inside `Python 3.110` or `MyPython 3.11`. The offline consistency predicate now checks token boundaries with escaped version text and deny tests for those misleading labels. A matching job label is still not authenticated proof of interpreter selection or a permanent VPS runner.

## Exact-SHA hosted job classification helper
A separate offline reference `classify_supplied_hosted_run_jobs(run, jobs, expected_sha)` accepts a caller-supplied workflow-run snapshot only when its head SHA and completed/success state match; hosted Python 3.11 and 3.14 must each have one distinct completed/success job belonging to that run with the exact hosted preflight job name. Missing, duplicate, failed, queued, wrong-run, or mismatched-name records deny. The helper **never returns permanent VPS proof**. Its name refers to the intended authenticated API source: the function itself cannot authenticate the caller or API payload and is not release authority. Existing HOLD and no-real-target gates remain in force.

## Workflow and job result type-integrity
The hosted-run classifier now requires exact built-in string status/conclusion fields at the workflow and individual job levels, rejecting same-text `str` subclass values. Synthetic regression fixtures cover both levels. This remains offline classification of caller-supplied records, not API authentication or VPS proof.

## Full-run job identifier uniqueness
Hosted job classification now rejects duplicate numeric job IDs anywhere in a caller-supplied job snapshot, including unrelated jobs outside the selected Python lanes. Duplicate identity is ambiguous evidence, so the classifier denies rather than silently selecting two apparently valid interpreter records. This consistency check still requires independent API authentication and confers no VPS or real-target authority.

## Full-snapshot malformed job denial
The offline hosted-job classifier now rejects a workflow snapshot containing any non-object job record or any job without a valid positive integer ID, even if two expected interpreter jobs otherwise look successful. This avoids selecting an apparently valid subset from partially corrupted input. This remains a consistency check on caller-provided data, not an authenticated GitHub API attestation and not VPS proof.

## Cross-run contamination denial
The hosted-job classifier now requires that every job in the supplied workflow snapshot, not only the Python 3.11/3.14 selected jobs, declares the same integer `run_id` as the parent run. A stray job from another run rejects the full evidence set. This is offline consistency checking, not independent GitHub provenance; release remains HOLD.

## Whole-run completion acceptance
Hosted CI classification now refuses a workflow snapshot if *any* included job is queued, failed, incomplete, or lacks an exact successful conclusion, even if the two Python preflight jobs individually passed. Negative fixtures include an unrelated third job in each invalid state. This deliberately requires a full successful run rather than a cherry-picked subset, but still cannot authenticate caller-provided GitHub snapshots or prove VPS identity.

## Malformed names in unrelated CI jobs
The hosted workflow classifier now rejects empty, whitespace-only, non-string or missing job names anywhere in the supplied run snapshot, not only in the selected Python jobs. Regression cases cover null, blank, numeric and boolean names on an unrelated successful job. This remains offline evidence consistency validation; independently authenticated API provenance and permanent VPS proof are still required.

## Unrelated job polymorphic status safeguards
Regression tests now explicitly reject `str` subclasses used for status or conclusion in unrelated CI jobs. The classifier treats the entire caller-supplied run snapshot as untrusted data and requires exact primitive success fields, not equality-coercible surrogates. GitHub API authentication, permanent VPS identity and owner release review remain separate gates.

## Provenance and pagination contract (2026-10-09)
The reference classifier has been renamed from `classify_authenticated_run_jobs` to `classify_supplied_hosted_run_jobs`, because it cannot independently authenticate API provenance. Its new `all_pages_verified` parameter is deliberately **False by default**; only the explicit boolean `True` permits classification. This is a caller-attested completeness precondition, not proof that pagination really was exhausted. GitHub connector job lookup currently exposes **only the first page for the latest attempt**. Therefore its response alone cannot establish complete run-job coverage and must not be used to set `all_pages_verified=True`. Genuine release evidence must come from authenticated, fully paginated GitHub job/run inspection tied to the exact SHA. Until then, HOLD and real-target activation=False remain mandatory.

## Pagination completion type boundary
Regression controls now reject absent, false, numeric, textual, list and object values for `all_pages_verified`; only the literal built-in `True` permits offline hosted classification. The duplicated result-type pass was removed while preserving the full-run exact-string success check. This flag must never be set from the first-page-only connector response without independently proving all job pages were retrieved. No VPS or target authorization follows from a passing fixture.

## Partial-page regression
A single passing hosted Python job (a plausible truncated first-page snapshot) cannot classify as full hosted CI evidence, even if a caller incorrectly asserts `all_pages_verified=True`; both distinct 3.11 and 3.14 successful job records are required. This does not independently establish pagination completeness, and the source remains untrusted unless authenticated externally.

## Duplicate interpreter-lane evidence
Regression coverage now rejects a second successful Python 3.11 hosted preflight job even if it carries a distinct job ID. A complete workflow snapshot must contain exactly one matching successful 3.11 job and exactly one matching 3.14 job. This is local structural validation, not GitHub authentication or permanent VPS evidence; release remains HOLD.

## Symmetric hosted interpreter lane regressions
The hosted job classifier regression matrix now covers duplicate Python 3.14 records with distinct job IDs as well as a truncated job list containing only Python 3.11. These are offline negative tests of lane cardinality; they do not prove GitHub API provenance, pagination exhaustion or permanent VPS execution.

## NUL-contaminated job names
The supplied hosted-job classifier now fails closed on job names containing an embedded NUL, including otherwise valid interpreter labels. Regression coverage prevents such malformed raw text from being mistaken for a valid CI job identity. This remains caller-supplied structural evidence, not GitHub API authentication or VPS proof.

## First-page connector safety adapter
`classify_first_page_only_jobs` explicitly models the GitHub connector's first-page-only job-list limitation. It never asserts verified pagination, so it always denies complete hosted CI classification even for two apparently successful synthetic jobs. The paired positive control demonstrates that a *separately established* completeness assertion would be required; the supplied adapter itself cannot establish that assertion. Real-target release remains HOLD.

## Contiguous paged-job snapshot validation
Added an offline `validate_paged_job_snapshot` reference that requires contiguous 1-based page indices, consistent `has_next` markers and each job's exact run ID before combining pages. Incomplete or contradictory lists fail closed. **This does not retrieve pages or authenticate the `has_next` markers**: a fabricated single final page can still appear consistent. Only trusted GitHub API pagination responses showing exhaustion may supply such metadata. The first-page-only connector remains insufficient and release remains HOLD.
