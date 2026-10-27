# Tenant lab window and network narrowing (offline review only)

**INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD · NO MERGE/DEPLOY/SCANS.**

The opt-in `scripts/check_scope_tenant_window_narrowing_offline.py`
reviews a proposed change to a self-reported tenant lab CIDR/time-window plan.
It uses the independent collision review on BOTH untrusted versions first,
then verifies that each retained `(tenant_id,scope_id)`:
1. existed in the earlier text plan (no new or reassigned tenant/scope);
2. retains its IP family and has a CIDR subnet of the earlier CIDR;
3. has `starts_at >= previous.starts_at` and
   `ends_at <= previous.ends_at`.

Removing whole scopes, retaining scope/time, or shortening the window/CIDR
is REVIEW_ONLY, **not** actual authorization. Even a one-second earlier
start or later end, shifted window, network move, IP-family swap, newly
added or reassigned scope, or invalid/overlapping plan yields HOLD for
the *entire input*.

## Bounded strict JSON contract

One ASCII JSON document, at most 32768 bytes, exact root fields
`schema_version:1`, `previous`, `proposed`. Both nested plans must
have the format documented by
`docs/scope-tenant-window-conflicts-offline-20261014.md`.
They must contain 1–32 canonical RFC1918/assigned ULA CIDRs with
non-overlapping pairwise CIDR/time combinations and exact
`YYYY-MM-DDTHH:MM:SSZ` timestamps. No untrusted extra permission fields.

```sh
python3 -m unittest discover -s tests -p 'test_scope_tenant_window_narrowing_offline.py' -v
```

Receipts deliberately exclude customer IDs, networks, times and input
values. All five authorization/execution/permit/merge/release flags
are hard-false. **REVIEW_ONLY exits 3, HOLD exits 2**, meaning even
syntactically narrowing plans cannot become a shell success signal.

**This is not trusted chronology.** An attacker can fabricate the
previous schedule as readily as the proposed one. No attested user,
tenant, lab custody, customer consent, live grant, revocation,
real time-of-execution check, production enforcement, socket, DNS,
target probe, persistent state or deployed tool is involved.
Original runtime source-owner [#100](https://github.com/Zennay/Lightup/pull/100)
retains the real authorization boundary. Independent latest-head
hosted+registered permanent VPS evidence, source/security/privacy
review, current-main compatibility and explicit human approval are
mandatory before any merge or actual target work.

**DRAFT/HOLD · NO MERGE/DEPLOY/REAL SCANS.**
