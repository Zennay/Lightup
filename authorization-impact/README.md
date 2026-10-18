# LightUp · Scope Impact Map — original-source operator companion

**INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.** This is an offline human source-review product. It is **not** the authorization system, not a grant issuer, not client or operator consent, not a STOP/revocation check, not a security release gate and not permission to scan or dispatch.

## Product

The [portable offline Scope Impact Map](standalone.html) consumes **one original source-bound, previously password-authenticated** `lightup.auth_casebook.v1` tenant export from the unchanged [original Casebook source-owner PR #1620](https://github.com/Zennay/Lightup/pull/1620). This held feature branch is anchored to the original owner HEAD `fa3a260234daa1178b5f6e4fc95cbd36e12d61fd` without modifying source-owner files.

What an operator can actually do:

1. Navigate recorded **request → stored grant → engagement → recorded risk decision** edges and inspect any selected record's transitive related source records. The interface now displays each exact shortest reference path and its hop count, including backwards links, so sibling requests connected only by a shared engagement are not mistaken for a direct approval.
2. Prioritize source-observed HOLD, PENDING and out-of-window rows. Explicitly surface **referenced IDs missing from the imported snapshot**, while never describing missing rows as revoked, cleared, fixed or authorized.
3. Record local self-declared reviewer label, human follow-up stage, action, date and private note per exact original source ID. Review the **human follow-up schedule** across all recorded notes, filter by self-declared stage and see dates before the device UTC day as reminders. Notes live only in browser memory; device time is untrusted.
4. Export a **counts-only anonymous aggregate JSON** with no original IDs, hosts, targets, paths, contacts, notes or per-item outcomes.
5. Export a **PRIVATE** notes handoff only after a recipient confirmation. It contains original IDs, tenant, notes and SHA-256 of the exact source file bytes; recipient import restores notes only against that exact byte-for-byte original source revision. Bad, stale or mismatched files leave prior review state unchanged.
6. Prepare a portable private workspace with the Python standard-library-only [packager](prepare.py): 0700 new directory, original private JSON plus app/instructions as 0600 files, SHA-256 manifest written last, exclusive no-overwrite, fsync and cleanup after ordinary failures.
7. Inspect a received private bundle with the separate stdlib-only [recipient inspector](workspace_inspect.py), which rejects modified files, unsafe symlinks/permissions, unexpected contents, inconsistent manifest/byte digests or unsupported source metadata. This is **only self-consistency against an untrusted local manifest**, never proof of sender or permission.

This is intentionally a *relationship impact/work coordination viewer*, not another source owner, casebook replacement, client consent UI or inferred validity gate. It only follows exact original keys `requests.request_id`, `grants.approved_request_id`, `grants.engagement_id`, `engagements.engagement_id`, `risk_approvals.engagement_id`. A request is **not** linked directly to an engagement absent its stored grant relationship.

## Newly delivered operator workflows

**Connected impact dossiers:** select any original request, grant, engagement or risk decision to see the exact shortest recorded reference paths. The new selected-source actions offer either an **anonymous selected impact aggregate** (counts only, without original identifiers) or a **recipient-confirmed PRIVATE standalone HTML / structured JSON dossier** with original tenant, exact source SHA-256, paths, source observations and saved human-only notes. The portable HTML has no executable scripts, no external links/assets and a deny-by-default Content Security Policy. These exports are source-reference interpretation, not authentication, consent, revocation or approval.

**Human group follow-up drafting:** select a source row and prepare bounded follow-up entries for the connected component's *unassigned* source-HOLD/pending/out-of-window rows, records with unresolved source references, or no-grant engagement observations. Choose non-approving human stage, self-declared reviewer, next action and proposed follow-up date. After one explicit confirmation the application adds those actions to the **local browser memory only**. Existing human notes are never replaced. These entries appear in the schedule and are transported only by the existing recipient-confirmed PRIVATE notes handoff.

**Original source admission alignment:** the private CLI packager now validates whole Casebook source families, duplicates, counts, caseboard engagement membership and per-engagement recorded grants/risk rows, request/engagement/grant/risk shapes and source-declared HOLD/expiry/pending totals before publishing. A packet that cannot satisfy this original-source contract is refused **before** creating a workspace. Recipient inspection uses the same admission function to detect malformed or contradictory source files. Neither tool performs account authentication, changes the source database nor claims private file integrity proves issuer authenticity.

**Keyboard-accessible offline source graph:** the selected original source's connected component now also appears as an interactive four-column SVG (requests, stored grants, engagements, risk decisions). Recorded links are drawn without network requests or external assets; absent original referenced rows are dashed and never clickable. For large connected graphs, the visual caps at 22 positions per family and explicitly reports omissions. The full original exact shortest-hop source path table is not truncated by this visual limit. Graph nodes can be activated by mouse or keyboard and cannot approve anything.

**Source-byte integrity and loss prevention:** the browser now reads an imported source file as original bytes, rejects a UTF-8 BOM or malformed UTF-8 instead of silently replacing or stripping bytes, and computes SHA-256 over the **original ArrayBuffer**, not decoded/re-encoded text. Rejected sources leave the current snapshot unchanged. The human-only return handoff uses the same strict UTF-8 admission. Any unsaved reviewer fields are offered for a local save before navigating away, replacing/importing sources, creating exports or drafting bulk follow-ups; invalid fields HOLD without silent data loss. Switching source requires a separate explicit confirmation because previous private notes are revision-bound and cleared.

## Single-open private room with original reviewer notes

The owner-private packager now integrates all three existing delivery formats into one **usable recipient directory**. Its first-choice `PRIVATE-ready.html` opens the exact Casebook source immediately and selects the first original record requiring human attention (or the first original record when no attention markers exist), showing the recorded graph and original-link review instead of an empty selection. With the optional `--review` source-bound native private return, **the same ready page** also restores the original reviewer stage, reviewer label, due dates, next actions and human-only notes automatically after verifying both original source SHA-256 and reviewer-note SHA-256 and the original per-record schema. No separate file picker is necessary in this recipient flow.

The generator uses two distinct inert HTML templates containing Base64-encoded source bytes and (when present) Base64-encoded private human notes, never executable text or dynamic HTML. It does not substitute browser-side script code; its script stays the original CSP SHA-256-pinned one. Both templates are cleared from the page after loading; encoded bytes remain as regular private information in the on-disk ready HTML, not as encryption. **The ready page is 0600 inside a 0700 workspace and must not be uploaded or shared publicly.**

The [recipient-side inspector](workspace_inspect.py) requires any ready page to regenerate *byte for byte* from its companion original `casebook.json`, exact `standalone.html` and optional `PRIVATE-review.json` files; handoff changes, missing original rows and mismatched revisions HOLD. The original manual `standalone.html` flow remains a fallback. Neither a previous original review, a human note, a ready-page hash nor an old snapshot is a live grant, consent, revocation, STOP check or release. In the event of a failed ready-source admission, the app preserves any independently selected manual source and refuses to apply embedded private review notes. There is no browser persistence.

## Open the private Impact Map immediately — no manual source import

Both supported private creation paths now produce **`PRIVATE-ready.html`** next to `casebook.json`, `standalone.html`, private instructions and the SHA-256 manifest. After original password + tenant authentication, the operator opens **`PRIVATE-ready.html`** directly from the private 0700 workspace instead of separately choosing the source JSON in a browser file picker. It is a complete offline browser workspace, not a public website.

- The offline packet builder uses only exact validated original Casebook **bytes**. A [deterministic generator](ready_room.py) inserts their Base64 representation into one inert HTML `<template>` element and pins the expected original source byte SHA-256. Base64 encoding prevents original identifiers, record text, scripts or HTML from becoming active markup.
- The standard browser JavaScript reads the inert **`template.content`** only on startup, decodes UTF-8 fatally, computes SHA-256 over original byte values, requires an exact match with the embedded expected source fingerprint, and applies the same all-false original Casebook validation before populating the UI. If unavailable/contradictory it stays **HOLD** and can only be opened through an explicitly selected original source file instead. The template payload is immediately cleared from the DOM following admission, while the working snapshot remains in ephemeral tab memory.
- The received packet's `PRIVATE-ready.html` must reproduce **byte-for-byte** from its separately included unchanged `standalone.html` and exact `casebook.json`; the recipient [workspace inspector](workspace_inspect.py) computes this before accepting the packet. It also checks owner-only file permissions and the final manifest. A digest is not a digital signature or proof of a permitted recipient.
- The original manual **`standalone.html`** + `casebook.json` workflow remains available, e.g. when the browser environment cannot expose local WebCrypto/SHA-256. No data is uploaded, no source grant/STOP/revocation is read live, and no client/operator authorization is inferred.
- The private ready HTML **contains the entire original private casebook in encoded form**. Never publish, attach, share or place it in webroot, cloud public folders or source control. Treat it exactly like `casebook.json`, because Base64 does not encrypt data. It is only for the authorized private recipient. The new ready file is 0600 and the containing directory 0700.

## Preferred: one original-authenticated command

The independent [authenticated workspace CLI](authenticated_workspace.py) now joins the **unchanged original** `lightup.auth_casebook.authenticated_casebook` to this review-only packaging workflow. It uses the original persisted-account password, lockout and operator/client tenant selector once, obtains one original query-only source snapshot and builds the full owner-private offline Impact Map in a previously nonexistent destination. **No intermediate plaintext export path, second login, new authentication mechanism or special grant.** Use an interactive private terminal:

```bash
PYTHONPATH=src python3 authorization-impact/authenticated_workspace.py \
  --database /private/path/lightup.db \
  --email existing-operator@example.test \
  --client ORIGINAL-EXACT-CLIENT-ID \
  --workspace /private/path/NEW-impact-room
```

For a **client** identity, omit `--client` to use the original account's enforced persisted tenant. An **operator** must provide an exact original client ID. To discover permitted original tenant IDs, use the original unmodified Casebook command `PYTHONPATH=src python -m lightup.auth_casebook --database ... --email ... --list-clients` separately; it uses original authentication and is not an authority check. Never copy the fictional placeholder email, database path or client ID into real operations.

The combined CLI accepts password input **only via the interactive hidden prompt**, rejects non-interactive terminal execution and does not read credentials from command-line arguments, environment variables or saved files. The existing original DomainStore authentication/lockout is not rewritten. Existing account authentication may update its original lockout metadata according to original source semantics; no grants, risk decisions, approvals, scans or STOP states are written by this companion. Successful private packet creation intentionally returns exit **2 / REVIEW_ONLY**; failed admission returns **3 / HOLD** with generic redacted output. Neither is permission, and a fresh account login does not imply genuine independent client consent or action-time revocation approval. Follow the same [recipient inspector](workspace_inspect.py) and offline browser opening instructions below.

### Alternative: separately exported private original source

If the original authenticated Casebook JSON was **already** created by an authorized operator, use `prepare.py` as documented below; it requires an owner-only regular 0600 source and does not authenticate source freshness.

## Start with genuine original data

Use the unchanged original authenticated Casebook exporter, which applies the existing DomainStore identity/lockout and tenant selection; do **not** fabricate a client grant, source approval, role, or proof. Inspect its supported CLI usage:

```bash
PYTHONPATH=src python -m lightup.auth_casebook --help
```

Produce its original owner-private (0600) JSON export with the supported authenticated flags for an existing permitted tenant. This handoff never logs in or reads SQLite. If your original Casebook is not yet built/approved, only use the clearly marked fictional browser demo.

In an offline local checkout containing this `authorization-impact/` directory:

```bash
python3 authorization-impact/prepare.py /private/path/ORIGINAL-casebook.json /private/path/NEW-impact-workspace
```

The command **must** create a previously nonexistent output directory. It refuses group/world-readable or symlinked input files, malformed/duplicate-key JSON, unsupported original schema, non-false authority flags, record duplicates, mismatched top-level counts and untrustworthy input revisions. It writes private original source bytes to `casebook.json`, standalone app to `standalone.html`, human instructions to `START-HERE.txt`, with `manifest.json` completed last. A successful preparation prints `REVIEW_ONLY` and exits with code **2** (intentionally never an authorization exit 0); refusal prints generic HOLD and exits **3**. Do not treat exit code 2 as a shell command failure requiring a repeat or as permission to activate.

Before opening a received private folder, reconcile local files against their local manifest:

```bash
python3 authorization-impact/workspace_inspect.py /private/path/NEW-impact-workspace
```

The inspector prints a source-redacted `REVIEW_ONLY` and exits **2** for a locally coherent packet, otherwise a generic `HOLD`/exit **3**. The manifest and hashes do not authenticate any sender, signature, customer or grant. Only then open the output `standalone.html` in a local browser (no HTTP server), import `casebook.json` with the browser's file picker, select an original source record and review its relationships. Keep the entire workspace owner-private. No browser upload, remote URL, persistent browser storage, DNS, scan, provider, grant, STOP, policy mutation or database update occurs.

### Carry an exact-source PRIVATE human review with the workspace

The operator who already has the separately exported **original 0600 Casebook JSON** and the recipient-confirmed human review return file can package both into one private workspace **without any live database or new authentication**:

```bash
python3 authorization-impact/prepare.py \
  /private/path/ORIGINAL-casebook.json \
  /private/path/NEW-impact-room \
  --review /private/path/PRIVATE-lightup-scope-impact-review.json

python3 authorization-impact/workspace_inspect.py /private/path/NEW-impact-room
```

The packager validates the original Casebook as before, then checks the PRIVATE return has exact `lightup.scope_impact_private_review.v1` schema, six literal-false authority flags, matching tenant, timestamp, original byte SHA-256, known bounded original record keys, unique human rows, allowed stage/date/reviewer/notes. It rejects malformed or stale review files **before** creating any output directory. The private return is installed as **`PRIVATE-review.json`**, mode 0600, with its SHA-256 recorded in the final workspace manifest. The read-only recipient inspector recognizes both the original four-file format and this five-file option, rechecking the exact source binding. Both modes stay `REVIEW_ONLY` (exit 2) or `HOLD` (exit 3), never actual authorization.

The recipient opens the included `standalone.html`, imports `casebook.json`, then chooses **Restore PRIVATE notes** and selects `PRIVATE-review.json`. Browser file access restrictions intentionally require this manual explicit choice; the application cannot silently read another file from disk. PRIVATE notes are self-reported human activity and must never be treated as customer consent, role verification, grant evidence or an approved finding. A **freshly authenticated new Casebook export** will normally have a different `as_of` and SHA, so old human notes are **not** automatically rolled forward. [Original Change Control PR #1632](https://github.com/Zennay/Lightup/pull/1632) independently owns old/new source-change review; do not infer unchanged authority from a timestamp or checksum.

### Offline transfer workflow

- **Anonymous coordination:** export counts-only JSON and share only through the intended review channel.
- **Private human review:** save per-record notes, explicitly confirm a trusted recipient, export `PRIVATE-lightup-scope-impact-review.json`, and transfer over an authorized private channel. On return, re-import the **exact original Casebook source** then restore PRIVATE notes. The restored annotations are human claims, not source truth, authenticated identities or consent.
- **Refresh:** any new Casebook snapshot must be treated as a new source revision; old notes do **not** silently carry over to altered source bytes. For source-to-source historical change review, use the separately owned Casebook Change Control product [PR #1632](https://github.com/Zennay/Lightup/pull/1632), not this single-snapshot map.

## New operator capability — hypothetical recorded-source unavailability planner

Within the offline app, select up to **20 actual original Casebook source records** (requests, stored grants, engagements or risk decisions) and choose **Mark selected original row hypothetical**. This new read-only sandbox answers a human *planning* question: "Which stored engagement references would deserve follow-up if these source rows became unavailable?" It **does not** revoke anything, approve any grant, invalidate a request or simulate the real execution gate.

Only the original source links are traversed, with deliberately narrow semantics:
- A hypothetically unavailable request considers only **original stored grants explicitly referencing that request**, then only their original recorded engagement references. Sibling requests are never assumed to authorize those grants.
- A hypothetically unavailable grant points only to its original engagement reference.
- A hypothetically unavailable engagement points only to that original engagement identity.
- A hypothetically unavailable risk decision points only to its original engagement reference.
- A referenced engagement that is absent from the original source is explicitly **MISSING ORIGINAL SOURCE**, not a valid/revoked engagement. It cannot be opened as a real engagement row.

The planner groups overlapping references by engagement, lets reviewers navigate existing original rows, keeps human notes and the original Casebook snapshot unchanged, and supports two separate outputs: **anonymous what-if aggregate JSON** containing counts only, or a **recipient-confirmed PRIVATE scenario JSON** containing the original tenant, exact source-file SHA-256, recorded source keys and follow-up reasons. Both carry six literal-false authority flags and `REVIEW_ONLY` status. The what-if plan is local ephemeral browser memory and is cleared on source replacement. It is explicitly not an assessment of current permission, revocation, actual customer consent, or anything permitting active work.

## Portable app code integrity

The actual self-contained `standalone.html` now declares a restrictive Content Security Policy with **exact SHA-256 pins for its one executable JavaScript block and its primary CSS stylesheet**. Inline HTML style attributes have a narrowly separate style-attribute directive, while external scripts, external styling/images, network connections, form submissions and objects are forbidden. The original app's JavaScript is now **not** admitted by broad `script-src 'unsafe-inline'`.

The new production-source [`app_integrity.py`](app_integrity.py) validator is used by both `prepare.py` and the recipient `workspace_inspect.py`. It reads the actual local offline app bytes, recomputes the script/style hashes, requires the restrictive nonduplicated CSP directive set and rejects unpinned or rewritten executable content **before** issuing a private handoff. The digest is an integrity check relative to the supplied local artifact, not an authentication signature or security approval. This does **not** replace the repository's real release CI/security/privacy approvals. The original, separately owned Casebook app/source are never altered.

## Trust, limits, privacy and work ownership

- Up to 512 KiB per original JSON, up to 200 original records per family. Import rejects duplicate object keys and inconsistent declarations atomically. PRIVATE review import has a 256 KiB ceiling and source-SHA bind.
- The browser is script- and style-self-contained with SHA-256-pinned inline executable code, no external assets, network API, persistence, or DOM insertion of untrusted HTML; all source fields enter using text nodes. Only confirmed PRIVATE exports contain tenant/row IDs or free-text human fields.
- A SHA-256 of raw imported file bytes **does not** authenticate the issuer, guarantee data freshness, verify a signature, or prove a currently valid client/operator grant.
- The Python helper requires local OS no-follow file support; it never reads source from stdin, logs raw private data, overwrites an output or runs a command. Its source path parent should reside in a trusted operator-controlled directory.
- Original Casebook remains owned by #1620. Original STOP #1619, request/grant source #177/#1570, risk #182, tenant lineage #829, execution gates, original CI and other workers' files are unchanged.
- This PR cannot merge to `main` or deploy until original source-owner acceptance, independent privacy/security review, canonical exact-head GitHub-hosted and permanently registered named VPS CI, genuine independently authenticated client and operator consent with action-instant revocation, and explicit **HUMAN GO**. Existing mandatory gates must not be bypassed. No QA/regression suite added or run under 17 October execution policy.

**No live client source, authentication, target or authorization was used when authoring this product.** Syntax/build inspection is not authorization evidence.
