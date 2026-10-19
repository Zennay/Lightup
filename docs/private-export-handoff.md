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

## Original-source continuity — second concrete operator workflow

Two separately created PRIVATE ZIP exports can be compared **locally** without modifying either source. The command strictly reopens both archives, checks their original CSV/manifest shapes and digest consistency, demands an explicit human confirmation of real shared client/engagement, and rejects any disagreement in the two *declared* client/engagement labels. The label check is NOT an independent identity check. The standalone module produces a private, scriptless HTML report with original source additions, disappearances, changed/unchanged records, field-change counts and severity/retest **source-label** transitions. It never infers closure/fix from disappearance.

```sh
python -m lightup.private_export_continuity earlier-private.zip later-private.zip \
  --output /path/to/private/source-delta.html \
  --acknowledge-same-client --ack-private-plaintext
```

An explicitly private investigation brief can additionally include original finding IDs and field names, without including customer descriptions, evidence or remediation text:

```sh
python -m lightup.private_export_continuity earlier-private.zip later-private.zip \
  --output /path/to/private/source-delta-ids.html \
  --acknowledge-same-client --ack-private-plaintext --include-original-ids
```

The first default report is ID-free; small counts may still be sensitive. Neither mode updates a source, owner decision, original stored finding, or previous HUMAN evidence/casework state. A changed source digest or record requires a separately authenticated and reviewed human decision before re-binding any old evidence or status.

## PRIVATE HUMAN Evidence Workdesk — interactive offline product

The original authenticated tenant archive can now be turned into a **portable, source-bound, self-contained HUMAN workdesk** with the actual source finding IDs, titles, severity, source-claimed retest status and remediation. This is for locally trusted operators; the produced 0600 HTML is **unencrypted/private** and contains original customer information. It is neither a client-facing public report nor evidence of authorization, consent, a verified fix or a performed retest.

```sh
python -m lightup.private_export_workdesk /path/to/PRIVATE-handoff.zip \
  --output /path/to/private/HUMAN-workdesk.html \
  --ack-private-plaintext --ack-original-identifiers
```

Open the local HTML in a modern browser. Severity-prioritized finding cards support quick local search, severity and HUMAN-stage filters, editable human owner aliases, provisional follow-up dates and private coordination notes. **No fixed/approved state exists** in the authoring control. No remote calls, form submissions, persistent browser storage, scanners, grants or other network assets. All source descriptions render through browser `textContent` and the generated single inline script/style use their own exact SHA-256 CSP hashes, with all external content blocked.

Click **Export PRIVATE HUMAN JSON** to explicitly save the source-bound, unsigned private draft. The browser intentionally does not autosave it. To resume a draft, return to the source-bound CLI with the exact original ZIP and exported JSON:

```sh
python -m lightup.private_export_workdesk /path/to/PRIVATE-handoff.zip \
  --resume /path/to/LightUp-PRIVATE-HUMAN-Workplan.json \
  --output /path/to/private/resumed-workdesk.html \
  --ack-private-plaintext --ack-original-identifiers
```

Resume uses Python duplicate-key-rejecting JSON admission and requires the original source digest and declared client/engagement labels to match, exact original finding-ID membership, bounded text and recognized non-authorizing stage values, literally false authority flags and a fresh no-clobber 0600 output. A changed source cannot silently inherit old notes or mark absent findings as fixed. Private values and labels require separate real human source/recipient verification. This offline workdesk does not replace original authenticated Casework, the existing source-owning HUMAN Operations Hub, or any product/release gate.

### Extra import hardening

The original ZIP intake now also validates every imported exported field using the parent original Unicode presentation-boundary guard, requires all formula/redaction presentation cells to already be canonical, rejects NFKC-equivalent duplicate IDs and requires byte-for-byte match with the original quoted CRLF source CSV serializer. An attacker cannot simply rehash a hand-written or altered CSV and claim it was emitted by the guarded original service. This is a data-format acceptance rule, not cryptographic source authenticity.

## Original CSV revision: explicit, safe HUMAN note carryover

When a newer separately authorized original CSV has changed, exact-source `--resume` correctly refuses it. The new **explicit original-source migration** command preserves HUMAN coordination only for findings whose *entire original five-column record* (including original identity, title, severity, source retest status and proposed remediation) remains identical. Every changed/new record starts unassigned with **no migrated owner, due date or private note**; absent records are never called fixed. It does not rebind any evidence, consent or authenticated client identity.

Use only after a human independently verifies that both original archives come from the **same real client and engagement**, not merely because their self-declared labels match:

```sh
python -m lightup.private_export_workdesk NEW-PRIVATE.zip \
  --carry-forward-from OLD-PRIVATE.zip \
  --carry-forward-plan OLD-PRIVATE-HUMAN-Workplan.json \
  --ack-same-real-client --ack-review-carryover \
  --ack-private-plaintext --ack-original-identifiers \
  --output /path/to/private/NEW-HUMAN-workdesk.html
```

Both archives and the previous human draft are independently admitted first, with strict duplicate-key rejection, source digest, exact finding membership and authority flags. The new workdesk displays total unchanged carried records, newly reset, changed/reset and absent previous records. Its fresh unsaved local annotation state references only the **new** original source digest; the old JSON remains unchanged. No automatic source equality = true fix, consent, owner authenticity, active scan/retest release or security proof. Output is a new private 0600 HTML and all old notes remain private in the original old file.

## Unified local operator console (all existing guarded workflows)

Run `python -m lightup.private_export_console` in a **foreground interactive terminal** to access all seven original-source workstreams from one menu: original password-authenticated tenant ZIP, local integrity inspection, aggregate HTML, new PRIVATE HUMAN Workdesk, exact-source workplan resume, two-snapshot source continuity, and explicit HUMAN unchanged-record migration. Each sensitive action asks for a typed literal `YES` before dispatch; passwords still use the original DomainStore/getpass path, not a new account provider. The menu never stores typed paths, passwords or source data, and it does not start a background job, web service, target scan, grant, retest, or deploy.

The console is deliberately a UI on top of the **same source-bound validators** and 0600 no-clobber atomic output rules, not a substitute for independently authenticated client/operator consent, source-owner review, or delivery approval. The offline HTML and ZIP remain unencrypted and are not automatically opened, uploaded or shared. Operators must manually protect and transfer private artifacts.
