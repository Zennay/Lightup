# LightUp PRIVATE Evidence Operations Hub

**Status: INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.** No approved main merge or production deploy. No active targeting, scanners, authorization, verified security fixes or retesting.

## Use the integrated offline product

1. Download the generated [PRIVATE Evidence Hub ZIP](LightUp-PRIVATE-Evidence-Hub.zip), move it to your approved PRIVATE workstation and unpack it. Open **`remediation-operations/index.html`** in your browser (not a web server). No account, third-party domain, storage, installation or network is required.
2. First import the **original supported source** into **Artifact Ledger** (upstream PR #1642). It has its own source-bound PRIVATE requests and human response handoff.
3. Use **Response Reconciliation** (upstream #1643) to compare the same original request membership with unverified human owner responses. These are responses, not independently authenticated fixes.
4. Use **Evidence Handoff Inbox** (upstream #1644) for whole-finding original workplans, including findings with no evidence requests. Only explicitly matching original-source identities may be paired. Never forge packet transformations.
5. Use **Runbook Editor + Owner Return** (upstream #1645) to prepare original-finding human tasks, brief individual self-declared owners, reconcile their replies, and plan human follow-ups.
6. Return to the new **Operations Hub** to mark local preparation, human input and self-declared handoff progress. Record only human planning notes; export PRIVATE local JSON for later restoration or scriptless HTML for a human discussion. All workflows operate separately; transferring files requires a human action and the source-owner app's exact accepted format.

**Use the packaged ZIP rather than saving the launcher HTML alone:** it contains all four original source-owned standalone apps and their required files. For a checkout, open the launcher at `remediation-operations/index.html` directly; same relative links.

## Offline source-revision change review

The included [PRIVATE Source Change Review](compare.html) accepts two local `remediation-operations/MANIFEST.json` files from separately obtained integration ZIPs. Its browser-only UI validates exact source inventory membership/schema, duplicate JSON keys, original PR head strings, per-file SHA-256 and declared false authority; then shows added, removed and changed file content with optional scriptless PRIVATE HTML handoff. Everything stays in memory. A matching checksum is NOT an authenticated signature or release permission; original owner approval and CI are still mandatory.

## Content and integration contract

This branch *copies unchanged* the four pre-existing separately-owned product paths from **the exact pinned PR heads** below, then adds only `remediation-operations/` integration/packaging code. No edits to original-owner branches, runtimes, authentication, scanners, CI configurations or QA suites.

| Original PR | Original head at integration | Preserved source path |
| --- | --- | --- |
| [#1642](https://github.com/Zennay/Lightup/pull/1642) | `6a8cd3baf6535705a7baca77dc3dc5067f862b3d` | `remediation-artifact-ledger/` |
| [#1643](https://github.com/Zennay/Lightup/pull/1643) | `58ad10f0b8cfb949287d4751b782221fc4ff9948` | `remediation-response-reconciliation/` |
| [#1644](https://github.com/Zennay/Lightup/pull/1644) | `933a0a4e278c957bbeaa564c3effcab6d1ae8a31` | `remediation-handoff-inbox/` |
| [#1645](https://github.com/Zennay/Lightup/pull/1645) | `f08fb96f7094d021493a39aa5d1a3eed025509f3` | `remediation-human-runbooks/` |

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
- The hub never directly reads original casework, original grant, owner evidence or findings. Only original apps can parse their own input files. No synthetic original-source joins or cross-app conversions are claimed.

## Release HOLD (unchanged)

**Do not merge this PR to `main` or production-deploy it** without authentic original exact-head hosted and permanently named VPS CI, original source-owner review, independent privacy/security review, currently authenticated separate client and operator consent with revocation rechecked at action time, original #177/#182/#829 and explicit HUMAN GO. Active execution remains disabled. All output is offline HUMAN planning, not a security assessment or fix verification.
