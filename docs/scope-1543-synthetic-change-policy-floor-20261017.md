# LightUp #1543 — isolated synthetic change-review policy floor

**INCUBATE M3/M7 — PLAN/LAB ONLY — DRAFT/HOLD. No merge/deploy/scan/target/authorization/handler/release.**

## Why this is a distinct scope-authorization review concern

The source owner of PR #1538 (SHA 26dd88d33c8735658ae819c7e017b2f36493a039)
introduced inferred-only change review. Its ChangeReviewPolicy.from_mapping is
intentionally configurable: a caller can set a CRITICAL severity verdict to
PASS, suppress every file with ignore_paths=["*"], set min_confidence=1,
or reduce the incomplete-coverage verdict. Such configuration **cannot create
LightUp authority**, but a consumer treating the resulting reported PASS as
security-release evidence would be dangerously mistaken.

This contribution does **not** rewrite the source-owner's review-policy parser.
It adds an independent opt-in reviewer for fictional policy snapshots which
explicitly refuses weakening against an independent conservative floor.
The output is always only REVIEW_ONLY (exit 3), or HOLD (exit 2). It cannot
represent a security pass, authenticated GitHub provenance, client consent,
operator consent, revocation proof, CI success, or permission to merge.

## Implementation ownership

New exclusive branch: chatgpt/scope-1543-policy-floor-offline-20261017
from original source-owner #1538 exact commit 26dd88d33c8735658ae819c7e017b2f36493a039.
Only three wholly NEW files:
- scripts/review_scope_policy_floor_offline_1543.py
- tests/test_scope_1543_policy_floor_offline_20261017.py
- docs/scope-1543-synthetic-change-policy-floor-20261017.md

Original source, owners' tests, workflows, runners, deployments and release
conditions are untouched. This is not wired into LightUp or GitHub Actions.

## Exact fictional JSON input

Pipe a JSON policy specimen on standard input. For example:

    python3 -I -S -B scripts/review_scope_policy_floor_offline_1543.py <<'JSON'
    {
      "schema": "lightup.scope.synthetic_policy_floor.v1",
      "policy": {
        "severity_verdicts": {
          "critical": "BLOCK",
          "high": "REVIEW_REQUIRED",
          "medium": "PASS_WITH_WARNING",
          "low": "PASS_WITH_WARNING",
          "info": "PASS"
        },
        "surface_change_verdict": "REVIEW_REQUIRED",
        "incomplete_coverage_verdict": "REVIEW_REQUIRED",
        "ignore_rules": [],
        "ignore_paths": [],
        "min_confidence": 0
      }
    }
    JSON

This is a **fictional, unauthenticated, non-authorizing specimen**. The complete
exact JSON object must include all six policy fields, with all five severity
entries. Extra authority-like fields, duplicate keys, non-string enum values,
NaN/Infinity, nonempty suppressions and positive confidence cutoffs are HOLD.
A policy may only raise (never lower) the minimum severity. Network/IAM surface
and unanalyzed file coverage are required to be at least REVIEW_REQUIRED.
Accepts at most 16 KiB of strict UTF-8 JSON. No file path input, no Git config,
no subprocess, no network, no contact with clients or scanners.

The receipt includes eight fixed, false authorization, consent, grant,
dispatch, merge, deployment and release flags regardless of its status.
Exit code zero is **never** returned for valid review or malformed input.

## Expected review evidence

- Ordinary tests cover strict baseline, stronger policies, each severity,
  both coverage verdicts, both suppression paths, scalar coercion, duplicate
  JSON keys, infinite/NaN input, Unicode schema impersonation, overlarge/
  recursive payloads, real CLI subprocess exit codes and identical privacy-
  minimal receipts.
- Source-integrated characterization pins the original source owner's actual
  opt-in parser's downgrade capability without modifying it.
- One explicit original-source expected-RED shows how a future strict parser
  would reject a CRITICAL downgrade. That red contract is **not a defect fix**
  and may need a distinct owner policy decision: customization might remain
  available if non-authority is clearly enforced by release gates.
- Test runs are isolated Python standard-library tests; no network, grant or
  real-world authorization occurred.

## Unresolved promotion requirements

Independent source-owner signoff for policy admissibility, no trust in inferred
PASS for grants/merges, actual separate authenticated client and operator
consent with live at-use revocation, independent security/privacy review,
complete hosted Python 3.11/3.14 and exact approved release SHA permanent
self-hosted VPS GitHub Actions evidence, and explicit HUMAN GO.

The synthetic reviewer is advisory only; never integrate a REVIEW_ONLY receipt
as an execution or release permit.

## W2 — real transport RED-to-GREEN and affected original-suite evidence

- First committed owner-isolated SHA 3fd30dc47edb6037bd4e9fe40046d870a0121996: 19 tests = 18 ordinary PASS + one intentionally unresolved source expectedFailure.
- Newly added real fail-closed transport tests initially **ERROR** when stdin raised OSError and **FAIL** when stdout wrote fewer characters than requested but the CLI still returned exit 3. Both corrected within the exclusively owned CLI without source-owner changes. Now 21/21 executed = **20 ordinary PASS + one intentionally outstanding expectedFailure**; strict SyntaxWarning-as-error test command completed successfully on connected zSSH Python 3.14.4.
- Existing source-owner test modules passed separately: test_change_review.py 26/26, test_change_review_store.py 4/4, test_github_changes.py 9/9, test_change_semantics.py 6/6 — **45 ordinary existing tests**. github_changes.py initially lacked a package import under Python -I without installation; rerun with PYTHONPATH=src (only this isolated checkout) passed. This is an invocation artifact, not a code defect.
- A full repository unittest discovery was attempted in the same checkout, but the zSSH individual command hit its **30-second deadline** before completion; no full-suite success is claimed. Pre-existing #1535 SyntaxWarning is still present at this source-owner base. Do not promote to release.
- No new or existing workflows/runner services started. No real targets, scans, customers, grants, handlers, merges, or deployment.
