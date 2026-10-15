# Offline scope-authorization ownership audit — 2026-10-15

**LightUp phase:** INCUBATE M3/M7, PLAN/LAB ONLY, DRAFT/HOLD.

This tool gives parallel workers a reproducible, private, **non-authorizing** ownership check before selecting an open scope-authorization issue. It is complementary to the existing per-branch path-ownership work (#1312/#1313) and exact CI evidence work (#1309/#1310), not a replacement for either.

## Invocation

Supply a locally exported, independently verified JSON snapshot from stdin. The tool itself never contacts GitHub, Notion, a VPS, customers, or targets:

```sh
python scripts/scope_issue_ownership_audit_20261015.py < snapshot.json
```

The strict JSON shape is:

```json
{
  "issues": [{"number": 101, "open": true, "lane": "scope-authorization"}],
  "prs": [{"number": 201, "open": true, "draft": true, "issues": [101], "paths": ["tests/scope_example.py"]}]
}
```

The exit code is **always 2 (HOLD)**, including when the input is well formed. A snapshot must never be interpreted as permission to work on someone else's branch, merge, release, deploy or scan. Every `can_*` permission flag is literally false. `claimed_open_issues` only means *someone said a PR covers an issue*; independent source-of-truth checks remain required. `unclaimed_open_issues` are work-discovery hints, not proof of available ownership. Duplicated issue claims, duplicate changed paths and claims on missing/closed issues are surfaced for human adjudication.

## Explicit limitations

- JSON is supplied by the caller and may be stale or fabricated. No GitHub authentication, review identity, activity timestamps, dependency readiness, CI status or permanent VPS state are asserted.
- Exact **file-path** collisions are reported; semantic overlap between different files, directory-level ownership and overlapping code functionality are not inferred.
- Reports contain issue and PR numbers plus changed-file paths; no grant IDs, customer names, target hosts, secrets or scan execution.
- No branch mutation, change publication, site/network I/O, target-active tool handler, consent decision or automatic issue claiming exists.
- Human operator, independent security/privacy review, production authorization enforcement, explicit GO and exact-head permanent registered-runner CI remain unsatisfied release prerequisites.

## Verification

```sh
python -m unittest discover -s tests -p 'test_scope_issue_ownership_audit_20261015.py' -v
```

The included 19 deterministic synthetic tests cover issue/PR claim mapping, duplicate assignment, exact path collision, closed/unknown claims, unsafe paths, duplicate keys, type confusion, malformed/oversize input, generic non-leaking HOLD and the CLI's always-nonzero behavior. No production source, active PR files, other lane, runner or workflow is changed.
