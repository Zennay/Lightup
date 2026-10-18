# LightUp Offline Scope Workbench

**Status:** INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD · REVIEW_ONLY.

This independent preview brings nine already authored draft LightUp browser products into **one downloadable offline folder/ZIP**. It does not merge their original pull requests or promote any security-sensitive logic to `main`. It cannot authenticate anyone, record legal consent, issue/revoke a grant, dispatch tools, scan hosts, schedule real assessments, persist web sessions or deploy.

## Use

1. Download [LightUp-offline-workbench.zip](LightUp-offline-workbench.zip).
2. Unzip it in a private directory and open `LightUp-offline-workbench/index.html` in a modern desktop browser. **Do not open directly inside the ZIP**; browser file references need the extracted folder.
3. Choose a journey and follow its suggested order. Alternatively search the component cards. Browser tabs and the nine apps remain independent.
4. **New local document tray:** add up to 24 supported DRAFT/HOLD JSON files (source Studio exports max 64 KiB, other supported review files max 256 KiB, total max 2 MiB). The tray uses fatal UTF-8 decode, bounded duplicate-key-rejecting JSON parsing, raw-byte SHA-256, a literal-false authority-field fence and atomic multi-file selection. It shows source/review type, generic proposed risk/counts, matching original source presence, an actionable count of missing Studio source files/high-risk drafts and compatible target app links; it flags contradictions between already-loaded original Studio risk/mode/counts and attached review metadata (never a receiving-app authorization verdict); it never silently supplies documents to another component. Use **Download original bytes**, open the relevant application and select the file again through that app's own input. A source match or inventory entry does **not** validate the receiving app's actual import contract or grant rights.
5. The tray exists only in the current page memory, with no cookie, localStorage or indexedDB and no network I/O. Remove individual files or **Forget all**, or close the tab. Filename/asset strings, original JSON data and contact notes do **not** appear in the optional SHA inventory; the inventory does contain correlatable document fingerprints. Explicitly confirm before exporting and restrict circulation.
6. Store sensitive downloaded proposals/replies/exports locally; avoid cloud-sync folders and shared public computers. Some locally generated JSON can contain source fingerprints and entered private data. The launcher temporarily holds manually selected JSON bytes only in tab memory, and never sends them to a network destination.
7. For STOP/revocation: **use the genuine externally authenticated incident/authorization channel first**. The local Withdrawal Desk cannot stop a running job or revoke consent.

## Included pinned source snapshots

| Product | Upstream PR | Local browser entry |
| --- | --- | --- |
| Scope Planning Studio | [#1567](https://github.com/Zennay/Lightup/pull/1567) | `apps/studio/studio/index.html` |
| Scope Briefing | [#1580](https://github.com/Zennay/Lightup/pull/1580) | `apps/briefing/scope-briefing/standalone.html` |
| Permission Brief | [#1578](https://github.com/Zennay/Lightup/pull/1578) | `apps/permission/scope-permission-brief/standalone.html` |
| Schedule Board | [#1572](https://github.com/Zennay/Lightup/pull/1572) | `apps/schedule/studio/scope-schedule-board.html` |
| Handoff Register | [#1579](https://github.com/Zennay/Lightup/pull/1579) | `apps/handoff/scope-handoff-register/standalone.html` |
| Readiness Workspace | [#1573](https://github.com/Zennay/Lightup/pull/1573) | `apps/readiness/coordination/scope-readiness-standalone.html` |
| Withdrawal Desk | [#1577](https://github.com/Zennay/Lightup/pull/1577) | `apps/withdrawal/withdrawal-desk/standalone.html` |
| Private Packet Vault | [#1574](https://github.com/Zennay/Lightup/pull/1574) | `apps/vault/scope-vault/standalone.html` |
| Assessment Review Desk | [#1576](https://github.com/Zennay/Lightup/pull/1576) | `apps/assessment/assessment-review/standalone.html` |

The Studio source snapshots are also copied to the Schedule Board folder so its relative siblings resolve. The Readiness Workspace's static page refers to sibling Studio-v1 network, fingerprint and planning modules: those **exact upstream bytes** are copied under its own component directory. Original source branches and file paths remain unchanged; the current preview pins each source to a **specific Git commit**, not a moving branch.

## Strict separation

- Every original component stays under its own `apps/<component>/` directory with the original file tree and scripts; the launcher only links to the browser entry paths and offers navigational advice.
- **No cross-origin/multi-app localStorage, service worker, shared authentication, shared grants or shared runtime capabilities.** This is a combined download rather than a merged permission service.
- A Studio "authorized_assessment" *request mode* is merely untrusted draft text, not authenticated authority.
- `manifest.json` lists the original PR number, exact upstream commit hash, every copied original path, byte length and SHA-256. Those hashes are integrity/correlation fingerprints only — not signatures, ownership, consent or approval.
- The launcher has a restrictive CSP with `connect-src 'none'`. Its opt-in document tray temporarily accepts local files only in the current tab memory, never persists them, and never transfers files to a component automatically. Each included original app retains its own source CSP and import controls. Users should review the source-specific README/docs before importing confidential material.
- These original apps are not guaranteed compatible with each other's local handoff formats beyond the documented import paths. Never infer an export is accepted without its target app successfully validating it.

## Repeatable packaging

From an isolated checkout containing the nine pinned commit objects:

```
python3 scope-suite/package.py
```

This uses only Python's standard library and local `git show`/tree inspection to copy **exact Git source blobs** into `scope-suite/apps/`, write `manifest.json` and produce `scope-suite/LightUp-offline-workbench.zip`. The build does not access targets or start CI. Change a source version only by explicitly editing its pinned commit SHA and reviewing compatibility. This packaging path deliberately does **not** track owners' draft branches automatically.

**No QA/regression/tests written or executed for this work package.** A direct script syntax check and packaging build only attest that the snapshot was generated; they do not prove safe operation or deployment readiness.

## Mandatory boundaries

Before any real release/merge/deployment, preserve canonical exact-head hosted and permanent registered VPS CI, original independent privacy/security review, source owners #177/#182/#829, separately authenticated client and operator consent with at-use revocation, and explicit HUMAN GO. Draft apps cannot replace these gates.

**Never treat a green build, local checkbox, version hash or copied PR as authenticated authorization.**
