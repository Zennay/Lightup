# Scope-authorization release gate: pre-I/O owner checklist (2026-10-09)

Status: **HOLD / no active-target activation**. This document does not grant consent.

## Owner acceptance sequence

1. **Trusted provenance:** load persisted client, engagement and authorization grant from a trusted store. Verify issuer signature/identity and active engagement; never derive authority from request headers, URLs, client-supplied booleans or descriptive owner/reference strings.
2. **Exact dispatch binding:** match authenticated tenant, client, engagement, asset, requested capability, environment and grant revision to this dispatch. Missing or mismatched identifiers deny. Validate type and length before comparison.
3. **Time integrity:** reject absent, malformed, naïve/aware-mixed, reversed, equal-instant and expired time windows. Normalize timezone-aware instants to UTC and enforce `start <= now < end`; invalid clock source fails closed.
4. **Revocation and races:** consult durable revocation immediately before I/O; use an atomic revision/lease or equivalent fence so consent withdrawal between planning and dispatch denies execution.
5. **No side effects on denial:** instrument tool-handler, network adapter, evidence writer and queue producer; every denial asserts **zero invocations** before any target I/O. Audit denial metadata may be recorded without leaking secrets.
6. **Migration:** turn all ten `expectedFailure` tests in PR #1127 into normal passing fail-closed producer-integration tests. Remove permissive legacy expectations rather than treating XFAIL as successful remediation.
7. **Proof:** run both hosted Python 3.11/3.14 unit plus real-producer jobs and canonical `[self-hosted,zcloud,vps]` CI on the **same final commit SHA**. Obtain scope source-owner review, then reassess draft status separately.

## Ownership / boundaries

- Production pre-dispatch integration is owned by PR #107 and issue #1128; this reference file does **not** modify their code.
- PR #1127 is an isolated, offline characterization/test branch. Passing synthetic reference tests, a green hosted workflow or an allowlist entry alone **never** establishes signed authorization or safe production dispatch.
- Preserve `TARGET_ACTIVE=OFF`. No third-party targets, live DNS/network traffic, scans, credentials, deployments or permission issuance are authorized by this checklist.

## Explicit release verdict

**FAIL / HOLD** until all seven items are evidenced on the exact integrated release SHA. The ten outstanding RED/XFAIL contracts are known security gaps, even where unit CI exits successfully.

## Automation-safe CLI exit contract

The offline `scripts/check_scope_release_evidence.py` is *not* a trustworthy grant or GitHub provenance verifier. Exit code `3` means **structurally complete synthetic claims only**, and must never unblock release or target activity. Exit code `1` means syntactically incomplete/denied evidence, and `2` means invalid input or CLI usage. **No exit code from this utility authorizes production**. A separate trusted source-owner validation must independently verify persisted consent, GitHub API runs and source SHA before any release decision.
