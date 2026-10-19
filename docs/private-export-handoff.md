# LightUp PRIVATE finding export handoff (non-authorizing)

**Release posture: INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.** This additive candidate is stacked on the held, original source-owner Unicode-guarded tenant CSV service at [PR #1611](https://github.com/Zennay/Lightup/pull/1611), not on `main`. It does not install an entrypoint, handler, workflow, scanner or scheduler. No production use or client data handled during development.

## What operators can do

The original `DomainStore` password prompt verifies a stored account and retrieves an up-to-date `AccessContext`; original tenant/engagement membership is rechecked by `render_client_findings_csv`. The held parent then applies its full-batch bounded Unicode/formula-aware finding export guard. Instead of writing sensitive CSV to terminal history, a new **explicit opt-in** command writes a single 0600 **UNENCRYPTED, private ZIP**, with the original five-column CSV, exact SHA-256 checksum / source declaration manifest, and a prominent non-authorizing notice. An existing filename cannot be overwritten. The output is constructed privately on the same filesystem and published with an atomic no-replace link; there is no partial public output on an invalid late finding.

```sh
python -m lightup.private_export_handoff create --db /path/to/local-domain.sqlite \
  --email operator@example.invalid --client-id KNOWN_EXISTING_CLIENT \
  --engagement-id KNOWN_EXISTING_ENGAGEMENT \
  --output /path/to/private/handoff.zip --ack-private-plaintext
```

The same local command also supports an **offline intake and management loop**, which never reauthenticates or claims to do so. It detects extra, duplicate, missing or over-budget ZIP entries, a changed CSV digest, changed row count, invalid schema/headers, malformed UTF-8/CSV, unrecognized severity/status labels, and authority flags that are not literally false. Read-only inspection prints only aggregate counts; it never echoes source findings, names or notes:

```sh
python -m lightup.private_export_handoff inspect /path/to/private/handoff.zip
```

A separate output produces a **scriptless, local, source-derived human brief** without original finding IDs, client/engagement identity, targets, note text, remediation, evidence or source digest. It gives severity and retest-label counts, with explicit wording that a source-claimed 'fixed' status is not verified remediation. HTML is published as a new 0600 file with no clobber and a restrictive inline CSP (no scripts or connections). Small-group aggregates may still reveal private information, so human recipient review is mandatory:

```sh
python -m lightup.private_export_handoff report /path/to/private/handoff.zip \
  --output /path/to/private/human-aggregate.html --ack-private-plaintext
```

### Security/privacy boundaries

- Archive is **not encrypted**. The checked digest proves byte consistency inside the locally obtained archive; it is **not** a signature, proof of customer identity, issue authenticity, review, current permission, retest or successful fix. Do not send via an unapproved channel. Use the separately reviewed encrypted transfer mechanism for sensitive deliveries.
- There are no network requests, target touches, scan execution, remediation commands, grant/consent creation, real-world facts asserted by the summary, or browser storage. The source PDF/CSV contents remain confidential. Human review must verify both original client/context and independently authenticated recipient.
- The archive is privately materialized into an existing parent directory with POSIX mode 0600; the caller controls the destination directory's separate access policy and lifecycle. Original `DomainStore.authenticate` may persist normal failed login attempts/lockout as part of existing authentication design. The writer will not modify any finding or retest state.
- All original exact-head hosted/permanent named VPS CI requirements, original source owner and independent privacy/security review, actual separate authenticated client/operator consent, at-use revocation, issues #177/#182/#829 and explicit **HUMAN GO** remain mandatory before any broader release. Existing parent PR #1611 has failed hosted acceptance due to old unchecked-CSV assumptions; that is **not resolved** here and must not be bypassed.

No new QA, regression, or test suite was added or run. Only source syntax and the additive offline feature build are inspected within the current execution policy.
