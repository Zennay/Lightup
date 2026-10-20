# LightUp · PRIVATE HUMAN scope delivery kit

**Posture: INCUBATE · M3/M7 PLAN/LAB ONLY · DRAFT/HOLD.** This is an offline source-byte distribution. It **cannot** issue permission, authenticate a person, scan a target, approve a client or operator, prove a finding, revoke a grant, or release software.

## Delivered, standalone operator product

[Download the complete prebuilt private offline delivery ZIP](LightUp-PRIVATE-HUMAN-Transfer-DRAFT-HOLD.zip). Extract *all* files to a private directory, open `START-HERE.html` locally, and follow the two-stage flow:

1. **Current original scope workspace** — the complete byte-pinned eight-companion workspace ZIP built from unchanged original integrated #1680 source, with its independent `SOURCE-MANIFEST.json` and `DIST-MANIFEST.json`. Extract the inner ZIP separately and open the original `index.html` locally.
2. **Original PRIVATE disclosure preflight** — unchanged [PR #1686](https://github.com/Zennay/Lightup/pull/1686), SHA `91842b75d9965adca6448b19bf31346c48d1be5c`, copied byte-for-byte under this independent source folder. Open `privacy/disclosure-preflight.html`, manually discover/mask the HUMAN-only text you explicitly plan to share, inspect the entire redacted output, and save the original local receipt. A redacted document is not certified safe or consented.
3. **PRIVATE HUMAN courier** — the independently owned #1682 standalone browser application, embedded byte-for-byte. Choose the original ZIP or selected HUMAN-only files, encrypt locally, and send only to a recipient authenticated separately. Passwords must be exchanged via a separate trusted channel.
4. **Recipient byte review** — `manifest.json` binds all exact package file bytes, sizes and original source-parent SHA. Independently supplied receipt checks are advisable. A matching SHA proves equality of bytes, **never** original operator identity, client consent, HUMAN GO or security review.

Original #1686 receiver `privacy/disclosure-recipient-verify.html` performs a separate local exact-text receipt comparison and content attention review after decryption. Compare original redacted plaintext bytes — do not treat encrypted container bytes or the receipt alone as content assurance. Source masks, byte receipts, encryption and exact matches are not an approval to publish.

The outer ZIP also embeds the original self-contained offline ZIP-byte verification page at `workspace/verify.html` and the current standalone `tools/package.py` inspector and safe `tools/unpack.py` private extractor. After extracting, run `python3 tools/package.py inspect /path/to/original-outer-zip` if desired. To safely materialize the complete original workspace into a new operator-owned private directory, run `python3 tools/unpack.py /path/to/original-outer-zip /path/to/private-parent/new-workspace`. This independently validates exact packaged bytes before publication, rejects link/path/size hazards, and creates owner-only files without overwriting an existing destination. Private recipient publication requires the Linux atomic `renameat2(RENAME_NOREPLACE)` primitive: no TOCTOU replace of an existing destination, including if it appears between preflight and commit. A platform without this primitive refuses to publish rather than falling back to a weaker rename. A script obtained from the same untrusted ZIP must not be mistaken for independently authenticated release evidence. The inspector strictly requires actual JSON `false` authority fields; numeric 0 and truthy/falsy surrogates cannot substitute.

The package retains the original #1680 workspace, #1682 courier, and #1686 disclosure/recipient standalones byte-identically and packages only separately owned original bytes. The new `scope-offline-delivery/` folder is an additive companion; existing owners' directories, domain authorization, scanner, live handlers, CI and tests were not edited.

## Build / inspect without tests or network

Python 3.11+ stdlib; run from the cloned source workspace on a **clean, independently owned checkout**:

```sh
python3 scope-offline-delivery/package.py build
python3 scope-offline-delivery/package.py inspect scope-offline-delivery/LightUp-PRIVATE-HUMAN-Transfer-DRAFT-HOLD.zip
# If the sender gave a verified digest separately:
python3 scope-offline-delivery/package.py inspect PRIVATE-RECEIVED.zip --expected-sha256 64_lowercase_hex_digits
```

The delivery builder now enforces hardcoded SHA-256 byte locks for the **exact native original 483,223-byte ZIP, SOURCE-MANIFEST, and DIST-MANIFEST**, in addition to original source-parent and the two byte-identical current disclosure standalones. Re-issuing forged self-consistent receipt content cannot silently replace the known original product in this exact builder; independently authenticated code provenance remains a separate requirement.

The build invokes existing #1682 `scope-current-bundle/build.py` to rebuild the **current** original workspace in temporary directories; the existing #1680 tracked stale ZIP is not taken as the source of truth. Original pinning preserves its original SHA. Both native original binary manifests and the full workspace's embedded source record must match byte-for-byte. The outer archive uses canonical fixed member names, fixed metadata and stored original bytes, with an unsigned manifest. Invalid JSON fields, changed size/digests, ambiguous member names, unsafe/missing files, altered source flags, source drift or an already-existing different output lead to **HOLD** and no overwrite. Output is mode 0600 and built without credentials.

A receiver should use `inspect` with the independently obtained copy of this script, not assume that an untrusted copy of the script in an untrusted ZIP proves provenance. For a lost or misdirected ZIP, local file-byte equality does not revoke any exported copy, credential or grant.

## Ownership and stop conditions

- Existing original #1680 [offline workspace](https://github.com/Zennay/Lightup/pull/1680), pinned source `0f76f2f90a89f5b64bc8033aa2e2ee6ec2fc49cc`.
- Existing original #1682 [PRIVATE HUMAN courier](https://github.com/Zennay/Lightup/pull/1682), pinned source `c6ae2c19ad432b924137185313b7331d1dbf148a`.
- This is **non-authorizing** distribution only. No real clients, targets, service access or background actions. No CI, QA, tests or deployments are invoked.
- Original exact-head hosted Python and permanently registered named VPS CI, original source-owner and independent security/privacy/browser reviews, #177/#182/#829, **real separate current client/operator authenticated consent with action-time revocation**, and explicit HUMAN GO remain mandatory. No merge to main or deployment under the present HOLD.

## Standalone browser-native recipient check (no Python needed)

Download [the separate built recipient HTML](PRIVATE-receive.html) **before** obtaining the source package, from an independently authenticated original distribution channel, and open it locally. The builder also embeds byte-identical HTML inside the ZIP. The web page is rebuilt from the separately committed `recipient.js`, `recipient.css` and `recipient.template.html`, with **hash-pinned CSP** for its exact script and style bytes. Select one original outer ZIP or encrypted HUMAN file (up to 2.5 MiB), and paste the SHA-256 received through an authenticated *different* channel. No upload, browser storage, auto-execution or plaintext display occurs. The page reports **BYTE MATCH / REVIEW ONLY** only when selected bytes exactly equal the provided digest; file changes clear the previous answer immediately. Lack of a separately authenticated expected digest is HOLD, not a matching result. This is a byte-equality usability feature, not independent user authentication, revocation, consent or safety review.

## Selective original-component recovery in the browser

The offline standalone browser receiver has a second, explicit operation **Inspect known original ZIP sources** that becomes available only after matching the *entire outer ZIP* against an expected SHA-256 received through a separate authenticated sender channel. The browser does not import or execute ZIP contents. It checks bounded stored-ZIP structure, member paths, duplicate/unsafe names, contiguous local headers and exact names/lengths, then confirms **seven original source byte pins** (unchanged original scope workspace, its exact SOURCE and DIST manifest JSON plus original byte verifier, unchanged encrypted HUMAN courier, unchanged original private disclosure editor, and unchanged original recipient redacted-text desk). An operator can inspect a local ZIP member-name/size inventory and click **Save** for one of the seven original product files. No automatic opening, extraction, scan, sending, source code execution or status promotion occurs.

A mismatching original byte pin or malformed ZIP remains HOLD, even if the outer SHA-256 matches a separately supplied digest. This safeguard is deliberately restricted to exact approved source bytes; it is not a proof that the user really authenticated the sender. The original Python inspector/unpack remains the documented way to materialize the full private package and all manifests. Both embedded tools now resolve the pinned original privacy sources in their actual portable `privacy/` sibling rather than requiring development-checkout-only paths; the packaged CLI remains source-only and cannot issue authorization.

## Offline least-disclosure role packets

The complete outer kit includes `tools/role_pack.py`, a standalone Python 3.11+ operator packager and recipient inspector. It never authenticates a person, grants permissions, runs a scan, contacts a target or sends files. The original complete outer ZIP must have a SHA-256 received through a separately authenticated channel; selected original sources are SHA-pinned and copied unchanged.

```sh
python3 tools/role_pack.py build ORIGINAL-OUTER.zip /private/new/recipient.zip --profile privacy-recipient --expected-sha256 ORIGINAL-OUTER-64-HEX
python3 tools/role_pack.py build ORIGINAL-OUTER.zip /private/new/editor.zip --profile privacy-editor --expected-sha256 ORIGINAL-OUTER-64-HEX
python3 tools/role_pack.py build ORIGINAL-OUTER.zip /private/new/reviewer.zip --profile scope-reviewer --expected-sha256 ORIGINAL-OUTER-64-HEX
python3 tools/role_pack.py inspect RECEIVED-ROLE.zip --expected-sha256 ROLE-64-HEX-FROM-SEPARATE-CHANNEL
python3 tools/role_pack.py unpack RECEIVED-ROLE.zip /private/parent/NEW-REVIEWER-DIR --expected-sha256 ROLE-64-HEX-FROM-SEPARATE-CHANNEL
```

`privacy-recipient` includes only original encrypted HUMAN courier and redacted-text recipient review. `privacy-editor` also includes the original HUMAN manual-redaction editor. `scope-reviewer` includes the original scope offline ZIP, original source/dist manifests and original byte-verifier, but not unrelated HUMAN courier or privacy editors. New outputs require a pre-existing operator-owned private parent (0700), and are created privately (0600) without replacing any file. Each package carries its own scriptless start page, an unsigned literal-false-authority receipt and a copy of its standalone recipient inspector. The recipient must authenticate the sender, intended recipient, approved access and any real consent separately; role filenames and hashes never supply those facts. Encrypt confidential packages before sharing; the included HUMAN courier does not automatically encrypt the new role ZIP.

After separately authenticated receiver byte comparison, the optional standalone `role_pack.py unpack` safely publishes the complete selected role ZIP as a new private 0700 folder with 0600 original files. It refuses all existing destinations and uses Linux atomic RENAME_NOREPLACE (no fallback or writes to another worker). Original selected HTML files are **not executed automatically**; any intentional opening and separate consent remain up to the human reviewer.

### Directly available role ZIPs (original source-only; no real client data)

The following READY offline source-only packages were physically produced by the same role CLI from the exact complete outer ZIP digest `c318e2065441f2cee59935d7ef19b84da4b11cb97908f9b221c9dce622a3d2d2`. They are separate deliverables; the full outer source kit does not silently include or transmit them.

- [PRIVATE-privacy-recipient-DRAFT-HOLD.zip](PRIVATE-privacy-recipient-DRAFT-HOLD.zip) — 55,564 bytes; SHA256 `acd722df636ec2a1a1c2b21f53e11d6a17732465caa63265b41bb41b348b74af`.
- [PRIVATE-privacy-editor-DRAFT-HOLD.zip](PRIVATE-privacy-editor-DRAFT-HOLD.zip) — 91,212 bytes; SHA256 `1afa377b99cd97eaf9201ebc08267f628eddf37098a4ae3fd8211b5c784ac8bf`.
- [PRIVATE-scope-reviewer-DRAFT-HOLD.zip](PRIVATE-scope-reviewer-DRAFT-HOLD.zip) — 538,114 bytes; SHA256 `55986f0d454f894c5437c5cadeb262fec903d62c0c3db8f366f9265daa7bbd87`.

SHA-256 values on this same public page are **not** separately authenticated when copied from the downloaded ZIP. Obtain the exact expected digest by an independent trusted channel before recipient inspection, and encrypt any confidential role packet before sharing. No automatically generated signer, consent record or authority is asserted.

### Browser-only role ZIP reception

The same [single-file local browser receiver](PRIVATE-receive.html) now recognizes either the **complete original source ZIP** or one of these **three exact private role ZIP inventories** after a complete ZIP byte-match against a separately supplied trusted SHA-256. It identifies the role from an exact list of source filenames and admits the role only when its original source files individually match their seven fixed original SHA-256 fingerprints. The matched original tools can then be individually downloaded without Python, sharing the full scope workspace, executing content, or sending network requests. Unknown, mixed-role or altered member sets HOLD. The accompanying private role receipt is unsigned; use the native role inspector for complete receipt-shape checks. Filename/role selection does not authenticate people or replace live authorization.

### Browser-native complete role receipt inspection (source-only)

After an independently supplied **whole-ZIP SHA-256** matches, the standalone offline browser now also checks an exact, deterministic Python-produced `PRIVATE-ROLE-RECEIPT.json` before offering original downloads. It rejects ambiguous/noncanonical JSON (including duplicate keys), wrong role/posture/original-head values, altered file sets and per-file digests, unsupported authority keys, non-boolean or affirmative consent/grant/release values, and an unfamiliar pinned `tools/role_pack.py` source. All role members — not just the original HTML tools — must agree with the byte-bound receipt. Original components are additionally pinned to immutable LightUp source digests. This closes the previous browser-only receipt verification gap; the native Python inspector remains available.

**Important:** All checks verify structure, deterministic source equality and local bytes **only**. The receipt is unsigned; even an exact match does not authenticate a person, protect confidential material in transit, check real client/operator permission or replace independent security review. Files stay local until a separate HUMAN chooses an explicit download; no content is automatically executed.

### PRIVATE local inspection receipt (one-click browser workflow)

For a separately matched, structurally admitted and original-source-pinned **role ZIP**, the browser now offers **Save PRIVATE role inspection receipt**. This manually downloads a small source-only `lightup.scope_private_local_inspection.v1` JSON with the selected exact role, SHA-256 and byte size of the entire received ZIP, plus every original role member's name, length and SHA-256 as admitted by the byte-canonical original receipt. No original source material, passwords, reviewer notes or contact details are included. The in-memory receipt is cleared on any file, digest or selection change and is unavailable for unknown ZIPs, malformed receipts or unmatched sources. It is **unsigned, locally produced, and REVIEW_ONLY**: human recipients and transfer channels must still be authenticated independently, and the receipt cannot assert consent, grant, release, client authority or confidentiality.

### Zero-install offline role kit preparation — complete browser feature

In the **standalone original offline [recipient page](PRIVATE-receive.html)**, select the **complete source-only outer ZIP** and supply its whole SHA-256 via a separately authenticated channel. After the browser checks the strict original stored ZIP layout, seven immutable original source digests and the pinned native source inspector, a new **Prepare a minimum-disclosure recipient ZIP locally** workflow becomes available. Select exactly one role:

- `privacy-recipient` — original encrypted HUMAN courier and source-redacted recipient text viewer only;
- `privacy-editor` — the same courier + original local manual redactor and receiver;
- `scope-reviewer` — original unchanged offline scope workspace ZIP, source and distribution manifests, and original byte verifier only.

The browser creates a byte-canonical, Linux-compatible stored ZIP and an exact native `lightup.scope_private_role_handoff.v1` **unsigned non-authorizing receipt** (file byte counts, SHA-256, original parent source digest, every authority flag exactly `false`) entirely in memory. The original source components and the original native role inspector are copied unchanged; the browser builds only the role's own static, scriptless start page and instructions. A generated SHA-256 is shown, and a HUMAN has to explicitly confirm a separate **Save role ZIP** action. Change the role, source ZIP, or supplied digest and the pending role disappears; nothing is stored, sent, unzipped, opened, scanned or authorized automatically. The original Python CLI remains an equal alternative; a native recipient may use `tools/role_pack.py inspect/unpack` against the saved browser-created ZIP with an **independently authenticated** supplied role digest.

**Browser convenience is NOT encryption, recipient authentication, client/operator consent, clearance to share confidential material, trusted signing, revocation or HUMAN GO.** Encrypt confidential files with the original, separately validated encrypted HUMAN courier and verify the recipient and channel separately before any transfer. The entire LightUp release remains **DRAFT/HOLD / PLAN-LAB ONLY**.

### Role unpack stability under local file replacement

The native role inspector now reads an archive into **one bounded O_NOFOLLOW original byte snapshot**. The exact same captured bytes are used for SHA-256 admission, canonical member/receipt validation and PRIVATE unpack (no second untrusted pathname lookup). The role builder similarly rechecks the entire original parent ZIP byte snapshot against the independently supplied original SHA before selecting the exact original source components. This fixes a real check/use byte-substitution risk. The actual user-owned output directory is published once with atomic Linux NO_REPLACE. No live grant, review approval or release is implied.
