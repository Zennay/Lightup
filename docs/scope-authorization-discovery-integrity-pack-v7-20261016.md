# Passive-discovery admission integrity pack v7 — issue #932

**Status:** INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.

**Exact ancestor:** v6 issue #930 head `923939c59a5d49fee2b148474f1f9ae402c2b8d7`.
**Original installed source:** owner draft [#175](https://github.com/Zennay/Lightup/pull/175)
at `df9eac879bbe232cd1e50fd6e9dfe12ff38f8469`.
Original `src/lightup/discovery.py` and all earlier composition branches remain unchanged.

## Composed original contracts

| Issue | Admission/review contract |
| --- | --- |
| #915 | Canonical exact float confidence |
| #916 | Exact outer ProspectSignal before caller validation |
| #921 | Exact SignalCategory identity |
| #923 | Exact nonblank signal source |
| #925 | Constructor/list-mutation cannot bypass add_signal |
| #927 | Signal collection cannot be replaced to bypass admission |
| #929 | Prospect identity cannot be rebound after accepted signal |
| **#931 (new)** | Prospect id and organization name exact built-in nonblank str at construction |

The v6 pack is inherited *unchanged*. The v7 delta consists of a copy of
the original [#931 test contract](https://github.com/Zennay/Lightup/pull/1470)
(17 top-level tests; 4 normal controls + 12 deliberately open source
expected failures + 1 strict replay oracle), its original repair handoff, and
this composition manifest. Because source-owner #175 has not implemented the
#931 constructor gate, all 12 expected REDs are *known unremediated hazards*,
not security success. The oracle rejects skipped tests or accidental
unexpected successes until the owner explicitly reviews and converts them.

## Collision/review boundaries

- Only entirely new v7-owned tests/docs paths; no source, workflow, runner,
  main, v6 or other worker branch changes.
- No in-memory prospect identity is customer consent or an authorization grant.
- This composes test artifacts, not permission to deploy, merge or run scanners.
- All test identities and signals are fictional and offline. No DNS, sockets,
  real customers, grants, target-active handlers or remediation effects.
- Release demands independent source-owner #175 + #929 integration, correct
  type/provenance ordering, full exact-head Python 3.11+3.14 hosted suite,
  genuine permanent registered self-hosted VPS CI, independent security/
  privacy review and explicit human/customer authorization.

**DRAFT/HOLD. NO MERGE, DEPLOY, REAL GRANTS, SCANNING OR TARGET ACTIONS.**
