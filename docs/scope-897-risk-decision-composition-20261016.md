# #897 — Pinned risk-decision integrity acceptance composition

**LightUp posture:** INCUBATE M3/M7, PLAN/LAB ONLY, DRAFT/HOLD. This branch is **non-authorizing**. Existing source issues remain open; the acceptance suite is not a production security fix.

## Immutable source parent

Exact **PR #146 source-owner HEAD** `33c67f8e8b17bd9214c29d02fc52954cc42655da`, untouched. PR #146 exclusively owns `DomainStore.decide_risk_elevation` source. Do not merge/rebase this composition into its active branch without source-owner review.

This isolated #897 composition imports **six unchanged original file blobs** and adds only this receipt:

| Contract | Test file | Contract doc | Original exact source HEAD |
| --- | --- | --- | --- |
| #791: exact caller approval identity | `tests/test_scope_authorization_risk_decision_approval_identity.py` | `docs/scope-authorization-risk-decision-approval-identity.md` | `80b2aeefedb1cfb0105c14acf9ccb7bcc02c5b33` |
| #796: persisted canonical requester | `tests/test_scope_authorization_risk_requester_provenance.py` | `docs/scope-authorization-risk-requester-provenance.md` | `8820b848fd379e7517b38938a26e71c2c4e788e4` |
| #807: no stale audit on PENDING | `tests/test_scope_authorization_risk_decision_audit_coherence.py` | `docs/scope-authorization-risk-decision-audit-coherence.md` | `489bd042564aca10a9eb1a88ed63a35b1e2f8022` |

The six original blobs are preserved exactly, no source or existing files are modified. This composition has **11 unique original test methods** (four #791, three #796, four #807). All tests use in-process DomainStore and throwaway local SQLite only. No real customers, targets, network or capability handlers are exercised.

## Defect-first required behavior

- **#791:** an input with different SQLite bind identities must be rejected **before any adaptation**; failed input cannot approve another person's or its reviewer's own request. Exact built-in nonblank `str` only, unchanged durable records on denial.
- **#796:** a BLOB or blank legacy `requested_by` must fail closed before decision mutation; legitimate same-reviewer self-approval remains denied; canonical independent reviewer approval is preserved.
- **#807:** PENDING with *either* `decided_by` or `decided_at` already present is incoherent and must be refused without overwriting status/audit fields; untouched PENDING remains decidable.

Preserve independent current guardrails: transaction serialization, single-row decision identity, self-approval exclusion, destructive-risk rules, client/engagement provenance, grant/revocation and all production execution boundaries. The test fixtures mutate only temporary synthetic SQLite rows to reveal the expected existing-source weaknesses.

## Verification protocol and interpretation

1. Verify child HEAD against the pinned PR #146 SHA: **seven added paths only** (six verbatim imports + this document), 0 changed/deleted existing paths, no branch ownership overlap, zero behind.
2. Verify each imported blob against its original SHA, not merely matching filenames.
3. The original tests on the unrepaired #146 implementation may be **intentionally RED**; do not claim all PASS, silently mark expected failure as remediation, or trigger its already congested permanent runner to report green. Once owners repair the source, explicitly verify previously RED safety invariants as ordinary PASS on a new exact SHA.
4. After owner-approved integration, a separate full hosted plus registered `[self-hosted,zcloud,vps]` matrix, independent security/privacy review, actual customer+operator approval, durable live grant/revocation proof and explicit human GO remain mandatory before a release.

**No branch/PR of another worker modified, no production code changes, no external DNS/network requests, scans, real grants, real target handlers, deploys, remediation, verdict or attack-path operations.**
