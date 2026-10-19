# LightUp PRIVATE Evidence Operations Hub

**Status: INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.** No approved main merge or production deploy. No active targeting, scanners, authorization, verified security fixes or retesting.

## Use the integrated offline product

1. Download the generated [PRIVATE Evidence Hub ZIP](LightUp-PRIVATE-Evidence-Hub.zip), move it to your approved PRIVATE workstation and unpack it. Open **`remediation-operations/index.html`** in your browser (not a web server). No account, third-party domain, storage, installation or network is required.
2. First import the **original supported source** into **Artifact Ledger** (upstream PR #1642). It has its own source-bound PRIVATE requests and human response handoff.
3. Use **Response Reconciliation** (upstream #1643) to compare the same original request membership with unverified human owner responses. These are responses, not independently authenticated fixes.
4. Use **Evidence Handoff Inbox** (upstream #1644) for whole-finding original workplans, including findings with no evidence requests. Only explicitly matching original-source identities may be paired. Never forge packet transformations.
5. Use **Runbook Editor + Owner Return** (upstream #1645) to prepare original-finding human tasks, brief individual self-declared owners, reconcile their replies, and plan human follow-ups.
6. Return to the new **Operations Hub** to mark local preparation, human input and self-declared handoff progress. Record only human planning notes; export PRIVATE local JSON for later restoration or scriptless HTML for a human discussion. All workflows operate separately; transferring files requires a human action and the source-owner app's exact accepted format.

**Use the packaged ZIP rather than saving the launcher HTML alone:** it contains the four original source-owned HUMAN applications, the seven-app encrypted Handoff Vault composition, and the full cross-app coordination desk. For a checkout, open the launcher at `remediation-operations/index.html` directly; same relative links.

## NEW: source-pinned seven-app vault and local encrypted HUMAN transfer

The original independently owned [Remediation Handoff Vault PR #1640](https://github.com/Zennay/Lightup/pull/1640) at exact `1a1ec2b95db5fdb15716e5c7dde21d22322bbb54` is physically bundled **unchanged** in `remediation-vault/`. Open [seven-app starter](../remediation-vault/START-HERE.html) or the [PRIVATE encrypted vault](../remediation-vault/standalone.html) directly. Existing original Casework Calendar, Evidence Review, Owner Reply, Dependency, Capacity and Funding standalone partner apps remain unchanged and are not merged into proprietary schemas. Original #1640 has its own encrypted PRIVATE selection, recipient handoff, ciphertext receipts and offline revision comparison; labels/hashes never authenticate source, client/operator consent, security findings, fixes or authorization. Its original separate portable ZIP is retained inside this complete combined bundle for exact original reference.

## NEW: full ORIGINAL-finding human coverage across four applications

Open [PRIVATE Cross-app HUMAN Inbox](triage.html) (also accessible from the main landing page). **Start with the exact original Handoff Inbox / Runbook input `lightup.private_human_original_finding_workplan` JSON** and optionally import the original Ledger's `lightup.private_artifact_ledger`, Runbook Editor's `lightup.private_human_remediation_runbooks`, and Response Register's `lightup.private_human_response_reconciliation` JSON exports. It reads these existing source-owned formats directly and never converts or overwrites them. Additionally it can import the ORIGINAL five-column findings CSV through the unmodified original Casework parser, computing the canonical source SHA-256 with original Casework code before displaying original **source-claimed** title, severity, remediation and retest status. A mismatched source SHA or original finding set is rejected atomically; missing CSV leaves severity/title as **unknown**.

The all-finding desk shows listed evidence fingerprints, original response requests/replies, human runbook step counts, unassigned human owners, tentative HUMAN due dates and clarification-needed markers. Choose the original-finding/user-search, missing-file/runbook, unanswered and owner filters. Source join **refuses** mismatched canonical original source SHA, client/engagement labels, source counts, unknown/duplicate finding IDs or non-false authority flags; every optional import is admitted atomically. An unimported optional dataset appears as **unknown**, not as an evidence/fix gap. A full workplan replacement forgets all linked optional records.

Export a scriptless PRIVATE printable HUMAN team agenda, owner-minimized HUMAN brief (requires selected declared owner), source-binding membership receipt, or anonymous counts-only CSV. Browser processes in memory only: do not close before exporting source files from their original apps. Original owner identities, findings, evidence, authorization, exact-source authenticity and client/operator consent remain **UNVERIFIED**. The human inbox never marks a security issue fixed or authorizes an action.

## Offline package integrity check

The included `remediation-operations/verify_local_bundle.py` is a human-operator utility, not a QA or regression suite: it can check local extracted source files against the bundled SHA-256 inventory or inspect the archive in-place without extracting or running source. Run `python3 remediation-operations/verify_local_bundle.py` from your extracted workspace, or `python3 remediation-operations/verify_local_bundle.py --zip remediation-operations/LightUp-PRIVATE-Evidence-Hub.zip`. It rejects duplicate/unsafe archive entries, invalid JSON identities, missing source applications, changed source bytes, incorrect source lengths and non-false release assertions; it performs no network calls or source execution. Matching content integrity does NOT authenticate GitHub ownership, signatures, CI, permission or human approval.

## Offline source-revision change review

The included [PRIVATE Source Change Review](compare.html) accepts two local `remediation-operations/MANIFEST.json` files from separately obtained integration ZIPs. Its browser-only UI validates exact source inventory membership/schema, duplicate JSON keys, original PR head strings, per-file SHA-256 and declared false authority; then shows added, removed and changed file content with optional scriptless PRIVATE HTML handoff. Everything stays in memory. A matching checksum is NOT an authenticated signature or release permission; original owner approval and CI are still mandatory.

## Content and integration contract

This branch *copies unchanged* five separately owned PR source directories from **the exact pinned PR heads** below (four HUMAN evidence apps plus the seven-app Vault), then adds only `remediation-operations/` integration/packaging code. No edits to original-owner branches, runtimes, authentication, scanners, CI configurations or QA suites.

| Original PR | Original head at integration | Preserved source path |
| --- | --- | --- |
| [#1642](https://github.com/Zennay/Lightup/pull/1642) | `6a8cd3baf6535705a7baca77dc3dc5067f862b3d` | `remediation-artifact-ledger/` |
| [#1643](https://github.com/Zennay/Lightup/pull/1643) | `58ad10f0b8cfb949287d4751b782221fc4ff9948` | `remediation-response-reconciliation/` |
| [#1644](https://github.com/Zennay/Lightup/pull/1644) | `933a0a4e278c957bbeaa564c3effcab6d1ae8a31` | `remediation-handoff-inbox/` |
| [#1645](https://github.com/Zennay/Lightup/pull/1645) | `f08fb96f7094d021493a39aa5d1a3eed025509f3` | `remediation-human-runbooks/` |
| [#1640](https://github.com/Zennay/Lightup/pull/1640) | `1a1ec2b95db5fdb15716e5c7dde21d22322bbb54` | `remediation-vault/` |

The original product paths remain individual sources of truth. Changes upstream require intentional source-owner review and a new pinned integration revision; copying files does not transfer source ownership. The **`MANIFEST.json`** enumerates each packaged file and SHA-256 digest, exact pinned upstream heads, and non-authorizing release status. SHA-256 is an integrity fingerprint, not authenticated provenance, consent, attestation or approval.

To regenerate ZIP and manifest from the checked-out integrated code (standard Python library only):

```sh
python3 remediation-operations/build_bundle.py
```

This command only reads local source files and creates a deterministic, fully portable local ZIP and manifest. No remote calls, scanners, builds of target code, or QA/regression tests. Files are size-bounded and symlinks/hidden files are refused.

## Operator desk privacy and limitations

- Markers: not started / local preparation / needs HUMAN input / *self-declared* handoff; nothing in those states approves execution or declares a security finding fixed.
- Four source-owner workflow IDs are fixed. Local annotations are **PRIVATE**, capped at 512 characters each. The standalone hub does not store anything in cookies, localStorage, IndexedDB or a server. Export before closing.
- PRIVATE JSON restore is all-or-nothing: 64 KiB max, fatal UTF-8 decoding, duplicate JSON key rejection, exact 4 IDs/order, exact pinned source-app heads, all 12 authority fields literally false, bounded notes, user confirmation before replacement. Imported text is never used as HTML source.
- PRIVATE discussion HTML has no scripts or connections and escapes all notes. Verify recipient identity and safe transport independently. No external identity is authenticated by the app.
- The landing page never reads casework or scans targets; the dedicated Cross-app HUMAN Inbox optionally parses the locally chosen original CSV using the **unmodified original Casework parser**, then joins only exact SOURCE-SHA/ID-matching exported HUMAN evidence metadata. Original files, grants, permissions and security findings are never modified. No unsupported cross-app data conversion is claimed.

## Release HOLD (unchanged)

**Do not merge this PR to `main` or production-deploy it** without authentic original exact-head hosted and permanently named VPS CI, original source-owner review, independent privacy/security review, currently authenticated separate client and operator consent with revocation rechecked at action time, original #177/#182/#829 and explicit HUMAN GO. Active execution remains disabled. All output is offline HUMAN planning, not a security assessment or fix verification.
