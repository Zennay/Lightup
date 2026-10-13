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
