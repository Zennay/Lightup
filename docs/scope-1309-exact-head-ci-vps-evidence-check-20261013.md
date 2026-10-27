# #1309: opt-in exact-head hosted + permanent VPS evidence verifier

**INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD/NO MERGE/NO DEPLOY.**

This standalone reviewer command only GETs public GitHub Actions run metadata from a **fixed** `api.github.com/repos/Zennay/Lightup/actions/runs` origin. It does not import LightUp policy/executor, call models, resolve target names, issue permits, run GitHub Actions, scan, deploy or touch customer data.

```sh
python3 scripts/check_scope_ci_evidence_optin.py \
  --pr 1308 --head 3978e3725df1cadde3bed675fcd7e22d5030b609 \
  --hosted-run 38478609048 --vps-run 38478609055
python3 -m unittest discover -s tests -p 'test_scope_ci_evidence_optin_1309.py' -v
```

As observed 2026-10-13 around 22:38 UTC, that hosted run has **4 completed successful Python 3.11/3.14 unit+producer jobs**, while separate permanent VPS jobs are **QUEUED**. The expected read-only result is therefore **HOLD**, not an approval.

Fail closed for mismatched immutable SHA or run ID, incomplete listing, duplicate/missing/extra job, queued/failed/canceled jobs, wrong hosted label, wrong permanent self-hosted label or unexpected registered runner `zcloud-vps-1`. Run-list paging beyond 100 is considered **incomplete**, not implicitly successful. `GITHUB_TOKEN` is an optional environment variable for API rate limits; not written into the output. External API errors return an opaque constant. The output contains only aggregate gate names and four hardcoded false flags: `authorization_verified`, `permit_issued`, `execution_enabled`, `release_approved`.

**Important:** `EVIDENCE_COMPLETE_NOT_AUTHORIZED` is only metadata consistency, **not** a release gate, signature attestation, log inspection, proof of self-hosted runner trust, human approval, customer consent or security. The GitHub API/runner metadata themselves can be forged if the upstream trust is compromised. The original #1306 fourteen failing authorization tests remain unrelated and unsolved; original owners #107/#100/#156, independent security/privacy, latest-main compatibility, permanent registered VPS job completion, raw logs and explicit human release are mandatory. No production effects.

Source ownership: three newly created paths only on dedicated #1309 branch from pinned main `05b80319cd0581fed21fe9d8f565bcb0a56cd2df`. All pre-existing source, other worker branches and CI workflow configuration remain untouched.

## W2–W4 implementation hardening

- Every individual job must bind to the exact submitted run ID **and latest run attempt**. Old successful jobs cannot prove a fresh rerun.
- Runs must identify the original `Zennay/Lightup` repository and PR event, with the exact GitHub workflow ID, display name and path; unrelated workflows cannot substitute matching job names.
- GitHub API HTTP redirects are denied, including when a `GITHUB_TOKEN` is configured, to prevent forwarding that credential outside the pinned origin.
- Tests use synthetic GitHub metadata only. The Python test suite does not contact GitHub, the user's VPS, clients, lab hosts or any target. There is no release token, approval or live execution.

## W5: current PR-head binding

The command now **requires** `--pr` and uses a fifth read-only GitHub API GET for the current PR. The PR must remain open and DRAFT, belong to the canonical `Zennay/Lightup` head/base repositories, and its CURRENT head SHA must equal the SHA whose two CI runs are checked. Historical fully successful workflow runs for a superseded PR revision fail closed. This is a reviewer metadata guard, **not** an authorization to merge or activate anything. PR API results are not included in stdout.

## W6: PR provenance and base-commit composition

New fail-closed check for **both hosted and permanent VPS** workflow runs: GitHub Actions `pull_requests` metadata must contain exactly one record for the requested PR number, its immutable source SHA/branch and its exact base branch+SHA. The run `head_branch` must be the current PR head ref. Reject missing/duplicate/mismatched PR associations, stale base SHA and non-`main` base. This makes apparently green CI from an unrelated PR or an older pre-base-update snapshot **HOLD**.

This is **metadata consistency** only: it does not cryptographically attest to the runner, source checkout, test logs or GitHub itself, and it does not authorize a scanner, allow merging or stand in for human security/privacy review. Branches are held as draft.

## W7–W8: opaque argument and unambiguous metadata admission

The read-only CLI refuses unknown or malformed numeric arguments with an **opaque fixed JSON HOLD**, without echoing untrusted CLI tokens into stdout/stderr (including erroneous `argparse` values). GitHub API input is capped to 512 KiB and parses JSON with duplicate-key rejection **at every object level** and rejection of `NaN`/`Infinity`; conflicting CI evidence cannot be resolved by last-key-wins behavior. Regression tests use entirely synthetic in-memory mocked responses and input canaries, never making network requests.

This strengthens a non-authorizing metadata preview only; no claim of trusted CI provenance, race-free GitHub state, registry permission, release approval or actual scanner safety.

## W9–W10: bounded PR and main consistency snapshots

The verifier reads the current PR **before and after** requesting both workflow runs and their jobs. A changed head, base, closed PR or conversion from draft to ready causes **HOLD**. It also fetches the canonical GitHub `refs/heads/main` at both ends, requiring the PR base SHA to equal current main and refusing a main ref that changes while collecting evidence. This reduces a straightforward metadata TOCTOU replay but cannot provide atomic GitHub state or make PR/test evidence an authorization grant.

All fetches are GETs to fixed `api.github.com` repo endpoints; no checkout, workflow rerun, scanning, deployment or write action occurs. The extra two main-branch GETs require GitHub REST repository metadata availability. Failures emit an opaque non-authorizing HOLD receipt.

## W11 — safety-critical GitHub Actions step completeness (metadata-only)

A GitHub Actions job may report an aggregate `success` even if its job metadata is not a sufficient record that required unit suites and safety guards actually ran. The optional evidence checker now requires all critical named steps to appear **once** with `status=completed` and `conclusion=success`. For hosted unit jobs it pins checkout/setup, compile+unit and repeated activation/web canaries; for hosted integration jobs it additionally requires real producer integration and the state-boundary step. Permanent self-hosted jobs must show **Guard permanent VPS runner**, checkout, setup, compile, unit, real producer integration and isolated activation/web canaries. Missing, duplicate, skipped, failed, malformed and truncated step arrays produce a permanent metadata HOLD; a green aggregate job cannot override it.

**Non-guarantee:** matching displayed step names do not prove the original underlying workflow commands ran or were reviewed, nor that the VPS machine is trustworthy. Raw exact-SHA logs, workflow source review, independent security/privacy/source-owner checks and explicit human signoff are still separate release gates. No change to installed workflow files.

## W12 — refuse self-modified verification contracts

Even valid workflow labels and displayed step names are not independent evidence when the submitted pull request can change the workflow that produced them. The optional tool now queries the actual PR changed-files listing, requires **all files** to be present in a single bounded page, and cross-checks `changed_files`. Any change to `.github/workflows/*` or `scripts/check_safety_canaries.py`, including a rename **away** from a protected path, forces `HOLD` for separate independent source-security review. Duplicate file identities, unknown statuses, incomplete >100-file PR listings and malformed change records also HOLD. This is an intentionally conservative opt-in evidence checker, not GitHub's actual branch-protection or security policy.

This neither validates the workflow code behind a displayed step nor proves the absence of race conditions or tampering in arbitrary non-guard source; review and exact-head raw logs remain separate requirements.

## W13 — reject workflow reruns while collecting evidence

After the initial GitHub Actions run/job reads and the final PR/main snapshots, the opt-in verifier fetches **both** hosted and permanent VPS run metadata again. The stable run fields include workflow/repository/PR provenance, branch, immutable SHA, `run_attempt`, status and conclusion. Any changed or missing metadata forces `HOLD`, even if the earlier job list indicated success. Synthetic tests cover a new run attempt, altered PR link, suddenly queued VPS and unavailable second read.

This is deliberately non-atomic best-effort metadata consistency, not proof that GitHub cannot change between requests. It does not trigger or approve reruns, and never returns an execution token. Permanent runner + human review remain required.

## W14 — strict step sequence and step-number provenance

Beyond verifying critical step names and success, the opt-in checker now requires GitHub Actions step `number` fields to be exact positive integers, unique and strictly increasing in the returned sequence. Each required critical step must also appear in the original workflow's precise ordered pipeline: the permanent VPS hostname guard precedes checkout, then interpreter setup, compile, unit tests, producer integration and final safety canaries. Hosted preflight and integration jobs have separately pinned ordered step sequences. Rearranged safety execution, missing, duplicate or Boolean step numbers cause `HOLD` even with an aggregate successful job.

The numbered step metadata is **not** independent attestation that the shell commands executed on a trusted runner. Review of original immutable workflow source, raw logs and real VPS completion remain mandatory. No installed workflow configuration, customer target or production code was modified.

## W15 — transport-level GitHub endpoint restriction

The underlying HTTP helper itself now requires an exact canonical URL match against the **only** metadata families used: `refs/heads/main`, `pulls/{id}`, `pulls/{id}/files?per_page=100`, `actions/runs/{id}` and `actions/runs/{id}/jobs?per_page=100` on the fixed `https://api.github.com/repos/Zennay/Lightup/` prefix. It rejects alternate schemes/origins, userinfo, fragments, query substitutions, path traversal and arbitrary strings or object types **before** creating an opener or adding the optional `GITHUB_TOKEN` header. Redirect following remains forbidden. Tests prove both positive known URL admissions and blocked malicious destination attempts without any network traffic.

This is a preventive defense-in-depth against future incorrect reuse of the internal helper, **not** proof of GitHub server provenance, runner integrity, log attestation, customer authorization or release approval.

## W16 — bounded UTC timeline coherence

The CI evidence checker now insists on syntactically canonical `YYYY-MM-DDTHH:MM:SSZ` timestamps and validates each actual GitHub Actions run lifecycle `created_at ≤ run_started_at ≤ updated_at` and each completed job `created_at ≤ started_at ≤ completed_at`. Missing, contradictory, malformed, fractional, non-UTC or non-string timestamps are **HOLD** regardless of aggregate job success. These metadata checks are read-only and cannot prove clock accuracy, trusted infrastructure or release authorization; they supplement workflow/job exact-head, review and raw-log checks.

Regression fixtures model both good and impossible run/job timing, including malformed Gregorian calendar dates and Boolean type confusion. All endpoints stay fixed GitHub GETs.

## W17 — reject ambiguous HTTP transport responses

The underlying fixed-origin GitHub API helper now refuses any response that is not an exact HTTP `200` with an explicit JSON media type (`application/json` or `application/vnd.github+json`, optionally with parameters). Non-200 or HTML/missing media types are rejected **before reading or parsing** the response body. This adds a read-only independent fail-closed transport layer on top of the W15 endpoint allowlist, no-redirect rule and bounded/duplicate-key-aware JSON parsing. Local mocked-response regression tests verify successful canonical JSON and refusal of provisional/HTML/missing-header responses.

Response metadata does not attest to a trusted GitHub server or a registered runner. No customer authorization, scan permit or release can be granted by this checker.

## W18 — job and safety-step timelines must fit enclosing workflow

The metadata checker now requires each completed mandatory job to occur during its corresponding run: GitHub Actions `run.created_at <= job.created_at`, `run.run_started_at <= job.started_at <= job.completed_at <= run.updated_at`. Each ordered mandatory safety step has a real UTC `started_at`/`completed_at` pair, must fit inside its job and must not overlap backwards with its preceding mandatory safety step. These are real CI metadata consistency checks, **not** trusted execution attestations. Forged, missing or impossibly ordered records force `HOLD` even if all outer job statuses are green.

## W19 — stable registered runner ID, not merely VPS labels/name

Both permanent Python matrix jobs must report the **same positive integer** GitHub `runner_id` and same canonical nonnegative `runner_group_id`; missing, Boolean, zero or mismatched values fail closed. Hosted jobs also require valid positive runner IDs. The runner name `zcloud-vps-1`, expected labels, exact SHA and canonical required workflow steps remain separately mandatory. This can stop obvious accidental runner alias confusion but it does **not** cryptographically prove that a trusted physical runner executed the commands or that the machine is secure.

**Actual blocker observed:** permanent VPS CI #38483217027 later returned cancelled with two cancelled jobs, with `runner_id=0` and empty runner names (no registered runner execution). It is emphatically **not passing VPS evidence**. The GitHub connector does not expose a repo-runner registration listing or a VPS restart action; manual independent runner restoration is outside this branch's scope. Do not replay hosted tests as permanent runner proof.

## W20 — immutable repository + PR number-to-ID provenance

Run-level workflow metadata previously correlated only human-readable repository names and PR number. The checker now additionally pins GitHub repository immutable numeric ID `1401523136` and matches the current PR's GitHub numeric ID with both workflow-linked PR IDs and their head/base repository IDs. The run's own `repository.id` and `head_repository.id` must equal that pinned repository ID. Invalid or Boolean IDs, different linked PRs or fork-like numeric identity changes force `HOLD`. This is metadata-consistency validation and not proof that the source is authorized to scan a customer.

## W21 — distinct jobs and exact workflow/branch/run identity

Each of the six required GH Actions job records must have a **positive unique** numeric `id` and canonical `url`, matching `run_url`, `workflow_name` and `head_branch`. Missing/duplicate/replayed job identities or mismatched run and branch labels cause `HOLD` regardless of aggregate green status. The prior run-ID, head SHA, runner ID, required step/time ordering and source workflow checks continue to apply.

### VPS evidence status

A cancelled queued VPS CI run (even after source jobs pass on GitHub-hosted) is **not** proof that the permanent runner executed the tests. The user or authorized ops worker must independently restore/verify the registered `zcloud-vps-1` runner, and a new exact-HEAD **two-job SUCCESS** must be inspected before any release review. These code additions neither rerun nor repair infrastructure.
