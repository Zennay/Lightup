# Scope-authorization expected-RED debt review — isolated 2026-10-15

**INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.** This is a separate read-only,
non-authorizing quality-control reference for the *existing open* source-owner
defects #1147, #301, #1454, #1173 and other test-only expected failures.
It does **not** claim ownership of the original issues, source or other workers'
test files. It never issues permits or releases.

## Purpose

A Python `unittest` test marked `@expectedFailure` can appear in an otherwise
green workflow **while its actual source defect remains unresolved**. An
`unexpectedSuccess` is **not** reliable fix acceptance without an explicit
owner-reviewed ordinary passing test. Hosted CI green is independent of the
permanent registered VPS requirement and actual customer/operator permission.

## Offline usage

```sh
printf '%s' '{"schema_version":1,"complete":false,"cases":[{"issue":1147,"test":"test_duplicate_key_red","outcome":"expected_failure","owner_pr":1462}]}' | python scripts/scope_xfail_debt_review_20261015.py
python -m unittest discover -s tests -p 'test_scope_xfail_debt_review_20261015.py' -v
```

Only synthetic caller-provided stdin JSON is reviewed. The snapshot is not
authenticated, and `complete:true` explicitly remains
`SELF_ASSERTED_UNVERIFIED`. UTF-8 input up to 64 KiB, at most 512 distinct
issue/test pairs. Each case has exactly `issue` (positive integer), `test`
(conservative ASCII method identifier), `outcome` (passed, expected_failure,
unexpected_success, failed, error, skipped) and `owner_pr` (positive integer
or null). Duplicate JSON keys, ambiguous types, nonfinite constants,
polymorphic or malformed cases and unknown fields cause opaque HOLD.
No user-supplied test name, issue number or target is echoed.

**All paths exit 2 with HOLD** and hard-false permission, grant, scan, merge,
release and execution flags. Valid data aggregates count only. No subprocess,
GitHub API, DNS, requests, targets, CI configuration, live tokens, runner,
source files or production ledger are read by the script.

## Real promotion gates

Owner fixes the real source defect and replaces each owned expectedFailure
with strict ordinary passing negative/positive runtime controls. Validate
before handler, network and ledger effects; preserve live tenant, scope, grant,
revocation, risk and lab constraints. Test exact integrated SHA on hosted
Python 3.11/3.14 (unit and producer), separately on permanently registered
VPS runner, then independent security/privacy plus real customer/operator
consent and explicit human GO. This script alone proves **none** of those.
