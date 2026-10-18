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

### Offline transfer workflow

- **Anonymous coordination:** export counts-only JSON and share only through the intended review channel.
- **Private human review:** save per-record notes, explicitly confirm a trusted recipient, export `PRIVATE-lightup-scope-impact-review.json`, and transfer over an authorized private channel. On return, re-import the **exact original Casebook source** then restore PRIVATE notes. The restored annotations are human claims, not source truth, authenticated identities or consent.
- **Refresh:** any new Casebook snapshot must be treated as a new source revision; old notes do **not** silently carry over to altered source bytes. For source-to-source historical change review, use the separately owned Casebook Change Control product [PR #1632](https://github.com/Zennay/Lightup/pull/1632), not this single-snapshot map.

## Trust, limits, privacy and work ownership

- Up to 512 KiB per original JSON, up to 200 original records per family. Import rejects duplicate object keys and inconsistent declarations atomically. PRIVATE review import has a 256 KiB ceiling and source-SHA bind.
- The browser is script- and style-self-contained with no external assets, network API, persistence, or DOM insertion of untrusted HTML; all source fields enter using text nodes. Only confirmed PRIVATE exports contain tenant/row IDs or free-text human fields.
- A SHA-256 of raw imported file bytes **does not** authenticate the issuer, guarantee data freshness, verify a signature, or prove a currently valid client/operator grant.
- The Python helper requires local OS no-follow file support; it never reads source from stdin, logs raw private data, overwrites an output or runs a command. Its source path parent should reside in a trusted operator-controlled directory.
- Original Casebook remains owned by #1620. Original STOP #1619, request/grant source #177/#1570, risk #182, tenant lineage #829, execution gates, original CI and other workers' files are unchanged.
- This PR cannot merge to `main` or deploy until original source-owner acceptance, independent privacy/security review, canonical exact-head GitHub-hosted and permanently registered named VPS CI, genuine independently authenticated client and operator consent with action-instant revocation, and explicit **HUMAN GO**. Existing mandatory gates must not be bypassed. No QA/regression suite added or run under 17 October execution policy.

**No live client source, authentication, target or authorization was used when authoring this product.** Syntax/build inspection is not authorization evidence.
