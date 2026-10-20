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

The offline standalone browser receiver has a second, explicit operation **Inspect known original ZIP sources** that becomes available only after matching the *entire outer ZIP* against an expected SHA-256 received through a separate authenticated sender channel. The browser does not import or execute ZIP contents. It checks bounded stored-ZIP structure, member paths, duplicate/unsafe names, contiguous local headers and exact names/lengths, then confirms **four original source byte pins** (unchanged original scope workspace, unchanged encrypted HUMAN courier, unchanged original private disclosure editor, unchanged original recipient redacted-text desk). An operator can inspect a local ZIP member-name/size inventory and click **Save** for one of the four original product files. No automatic opening, extraction, scan, sending, source code execution or status promotion occurs.

A mismatching original byte pin or malformed ZIP remains HOLD, even if the outer SHA-256 matches a separately supplied digest. This safeguard is deliberately restricted to exact approved source bytes; it is not a proof that the user really authenticated the sender. The original Python inspector/unpack remains the documented way to materialize the full private package and all manifests.
