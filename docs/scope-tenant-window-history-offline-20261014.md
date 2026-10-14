# Offline tenant lab test-window history review

**LightUp INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD · NO MERGE/DEPLOY/REAL SCANS.**

The opt-in `scripts/check_scope_tenant_window_history_offline.py` reviews
a **self-reported** sequence of UTC tenant-network test plans. Every
intermediate plan must pass the independent strict network/time
collision checker, and each adjacent transition must preserve tenant
scope identity and only *narrow* CIDRs and time intervals. A temporary
earlier start, later end, moved/expanded CIDR, reintroduced or reassigned
tenant scope, or overlapping test plan produces **whole-history HOLD**,
even if the final submitted version reverts to an earlier valid plan.

## Input

Exactly `{"schema_version":1,"versions":[plan_1,plan_2,...]}`.
Require **2–4** plan objects, each with the exact format from
`docs/scope-tenant-window-conflicts-offline-20261014.md`:
1–32 distinct self-declared tenant/scope IDs, canonical RFC1918 or
assigned IPv6 ULA CIDRs, exact strict ASCII
`YYYY-MM-DDTHH:MM:SSZ` UTC times, positive intervals no longer
than 24 hours, at most **32768 total input bytes**.

```sh
python3 -m unittest discover -s tests -p 'test_scope_tenant_window_history_offline.py' -v
```

Output contains only a fixed non-identifying HOLD or REVIEW_ONLY
reason and five authorization/permit/execution/merge/release flags
**all false**. Neither input targets, timestamps nor tenants are
echoed. Every status has a nonzero CLI exit code (REVIEW_ONLY=3,
HOLD=2) so `check && scan` never grants permission.

**Critical limitations:** This is not a tamper-evident audit
trail. Both sequence, ordering and contents are controlled by
the caller; omitted revisions are undetectable. No ownership,
permission, verified tenant binding, safe route, DNS resolution,
live grant, capability, risk, consent, revocation or execution
time is checked. No sockets, network requests, real scans, DB
writes, workflows, deployments or original source-owner edits.
The true execution permission gate remains owned by
[PR #100](https://github.com/Zennay/Lightup/pull/100).
Independent human security/privacy/source-owner review,
exact-head hosted + permanent registered VPS test proof and
explicit release approval are required before integration.

**DRAFT/HOLD · NO MERGE/DEPLOY/REAL TARGETS.**
