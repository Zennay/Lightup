### Large-original-batch memory handling (19 October 2026)

The browser matrix still structurally admits and displays **2–8 original files of up to 8 MiB each**. For batches exceeding the 24 MiB encrypted full-workroom export cap, it now releases the additional *raw source-byte cache* after admitting the source (the parsed, PRIVATE in-memory results remain available for HUMAN comparison). This avoids unnecessarily retaining up to 64 MiB of duplicate input bytes when the complete encrypted vault cannot be used. The vault explains the size cap without hiding the normal source set or preventing HUMAN-only export, and the operator can still import a smaller batch. The original results never leave the browser and the complete encrypted export never silently truncates sources.

**Latest exact source [2480886](https://github.com/Zennay/Lightup/commit/2480886be480b4faf8eed77ad87be18cee868bd5)** (previous commits in older sections are milestones). Connected permitted zSSH direct source inspection found the combined production JavaScript syntax valid, Python standalone builder syntax valid, the exact committed HTML **111,572 UTF-8 bytes**, matching CSP SHA256 for the sole inline script and stylesheet and no external assets. No QA suites, actual customer imports, browser E2E approval, crypto audit or production release claimed. Original DRAFT/HOLD release gates unchanged.

---

## Complete encrypted PRIVATE lab workspace (19 October 2026)

**New standalone product behavior on this existing DRAFT/HOLD branch:** The same local one-file browser application can now securely **package original PRIVATE lab-result JSON bytes together with all HUMAN planning choices**, including their source-byte fingerprints, as *one locally encrypted, portable workroom*. This is different from the existing lightweight HUMAN-only plan: a complete workroom includes PRIVATE original targets, evidence and report text inside the ciphertext.

### Export current complete PRIVATE workroom

1. Independently obtain and open your **already-produced** original PRIVATE lab result files using the unchanged strict 2–8 file admission workflow. The original records are structurally checked, never trusted as signed evidence or live scan authority.
2. Optionally edit HUMAN-only stage/reviewer-group/next-question selections.
3. In **Keep the whole offline workroom together**, set a local passphrase of 12–256 characters and explicitly confirm **Download complete ENCRYPTED workroom**. WebCrypto generates a fresh random AES-GCM nonce and PBKDF2 salt for this export, encrypting the original source *bytes* (not reserialized reconstructed JSON) plus the bounded exact SHA-256-source-bound sparse HUMAN plan. Only encrypted bytes and the decryption algorithm parameters go into the downloaded file. There is no user account, external connection, browser persistence, cloud sync, API or key escrow. Passwords are cleared after processing.
4. Keep that file private and protected. **The original source reports, target literals and evidence are all inside the encrypted workroom.** This format contains substantially more confidential content than the HUMAN-only plan; do not share casually. A good passphrase and an uncompromised device are essential. No password recovery exists.

**Bounds:** Each original lab JSON must be 1–8 MiB or smaller, with 2–8 existing sources. To prevent browser memory exhaustion, full-workroom encryption supports up to **24 MiB of combined original source bytes** (48 MiB maximum encrypted plaintext; 65 MiB maximum uploaded encrypted envelope). Larger original sets remain supported by the ordinary separate-source-plus-plan workflow; encrypted complete export will explicitly hold instead of silently truncating anything.

### Restore a complete PRIVATE workroom from one file

1. On a trusted offline device, open the single self-contained [standalone.html](standalone.html); select **one complete ENCRYPTED workroom** and enter its passphrase.
2. First the browser strictly parses the bounded outer format and authenticates/decrypts the AEAD ciphertext. It then validates the decrypted source inventory, all original raw JSON files, original run/scenario/endpoint membership, original findings/evaluation and each SHA-256 fingerprint, and the exact serialized private HUMAN plan. Any wrong password, changed original bytes, invalid grant/authority flags, mismatch or oversized structure HOLDS the entire replacement.
3. **Only after all files and HUMAN fields are admitted**, the operator explicitly confirms replacing the current in-memory selection. Original lab bytes and matched HUMAN stages/groups/questions then reopen together; the regular matrix, endpoint distribution and HUMAN comparison desk are populated. Existing in-memory work is kept if admission fails or the operator cancels. No security assessment is run, no client or asset contacted, and no original-source or grant data is modified.
4. You can export only HUMAN notes separately afterward, or forget all in-memory originals/choices. This does not delete any previously downloaded file; protect and remove such files according to your local private retention policy.

### Trust boundaries and source code

New separate module `workspace-vault.js` handles bounded base64 transport of encrypted original file bytes and the atomic operator workflow. The shared `private-plan-crypto.js` now supports a separate specifically bounded workspace AEAD envelope alongside its preexisting smaller HUMAN-only plan envelope; `human-board.js` exposes strict preflight of a plan against proposed original rows/digests; `app.js` shares one structural admission pipeline between normal local originals and decrypted originals. The Python standard-library `build_standalone.py` embeds all four runtime modules and CSP SHA-256 pins the exact complete inline source. No third-party code or remote assets are required.

**AES-GCM with PBKDF2 does not establish original lab authenticity, validated findings, scan coverage, operator identity, real client/operator consent or authority to access targets.** This has not undergone independent security/cryptographic/browser acceptance. The source hash is an unsigned exact-byte binding, not a trustworthy producer signature. The product remains **INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD**, with the original exact-head hosted + permanently registered named VPS CI, original owner and independent security/privacy/browser approvals, #177/#182/#829, genuine separately authenticated current client/operator consent with revocation at use, and explicit HUMAN GO required for any merge, release, deployment, active scan, or target contact. This change only edits the independently owned `assessment-coverage-matrix/` companion; no QA/regression/test suites added or run.

---

## Optional encrypted PRIVATE HUMAN plans (19 October 2026)

The offline [standalone.html](standalone.html) now supports **both** the earlier unencrypted PRIVATE JSON workflow and a new optional encrypted plan export/import path, without changing original lab evidence, source hashes, assessments, grants or other worker branches.

**To create an encrypted plan:** open your already-created original PRIVATE lab inputs, edit HUMAN categories, enter a strong local passphrase of 12–256 characters, then click **Save ENCRYPTED PRIVATE plan**. The app serializes the same strict original SHA-256-byte-bound PRIVATE HUMAN plan, encrypts it locally with a *fresh 16-byte cryptographic random salt and 12-byte random AES-GCM nonce*, derives a 256-bit key using WebCrypto `PBKDF2-HMAC-SHA256` (310,000 iterations), and downloads only the AES-256-GCM ciphertext plus required decryption envelope parameters. Plaintext source IDs/hashes and HUMAN choices are INSIDE the ciphertext; none of them is copied to the outer encryption metadata. Passphrase inputs are cleared after the operation. No credential is sent anywhere, recorded in browser storage or recovered for the operator.

**To resume:** open precisely the same PRIVATE ORIGINAL source files, choose the prior plan (encrypted or legacy plaintext), and enter the associated password only when the file is encrypted. First strictly admit the encrypted envelope (≤5 MiB) and authenticate/decrypt using AES-GCM; then apply the **unchanged** inner bounded strict duplicate-key JSON and exact original source-byte binding, ordered rows, enums, literal-false flags and explicit HUMAN confirmation. Wrong password, tampering, different original source bytes or malformed schema produce a complete HOLD; existing local HUMAN choices stay unchanged.

**To compare two saved plans:** either earlier/later input may independently be encrypted or unencrypted. Provide a distinct passphrase in the corresponding field as required. Both are fully decrypted and admitted independently **before** changing the currently displayed comparison. Changed HUMAN fields and manual conflict choices are never proof of actual security chronology, customer consent, remediation or client authority.

**Security limitations:** This optional encryption protects downloaded plan confidentiality only to the extent your passphrase, browser runtime and storage are trustworthy. PBKDF2/AES-GCM implementation here has **not received independent cryptographic/security review**; it is not a secure communications channel, identity signature, source authenticity attestation, audit log, server-side access control, consent, or authority. Source PRIVATE originals remain unencrypted unless you separately protect them. Weak/shared passwords and compromised endpoints undermine confidentiality. Do not lose the password; there is no recovery service. `sha256` of original inputs inside the encrypted plan remains an **unsigned exact-byte match**, not authentication of original producer or findings. Downloaded ciphertext has no unique client ID, timestamps, evidence or target contents in the envelope metadata; its file size still leaks approximate plan size.

Implementation files: `private-plan-crypto.js` provides a stand-alone, browser-only bounded AES-GCM/PBKDF2 envelope; `human-board.js` admits it for save/resume/both HUMAN history files; `build_standalone.py` embeds the new source with the existing HUMAN workroom and original-only comparison into one CSP SHA256-pinned self-contained browser app. No tests/QA suites written or run. No original source owner, scanner, tenant authorizer, CI, grants or release flags changed.

**Release remains DRAFT/HOLD.** Notion INCUBATE M3/M7 PLAN/LAB ONLY. Original exact-head hosted AND registered named permanent VPS CI, independent source owner/security/privacy/browser review, #177/#182/#829, separately authenticated actual current client/operator consent with revocation at use and explicit HUMAN GO remain mandatory before main merge, deployment, live target or any security assessment.

---

## TWO ORIGINAL-SOURCE-BOUND HUMAN PLANS · private cross-session review (19 October 2026)

The same one-file `standalone.html` now includes a **full HUMAN change comparison / conflict-safe merge desk**. No authenticated event history is inferred or created. Nothing runs a target, validates a finding or confers assessment authority.

1. Manually open the **same** 2–8 already-existing PRIVATE original lab result files as used when saving both HUMAN workplans. The byte hashes and their operator-selected file ordering MUST match; without WebCrypto this feature refuses source binding rather than inventing identity.
2. Explicitly select one saved PRIVATE HUMAN plan as **Earlier (manual order)** and the other as **Later (manual order)**. Each file is ≤3 MiB, strict UTF-8/duplicate-key JSON, *exact original private plan schema*, complete literal-false authority flags and original source digests. **Both** files are independently admitted before replacing any previous comparison. A failed or mismatched file holds the entire new comparison and leaves your current plan unchanged. File modification time and filename are **not timestamps or a trusted chronology**.
3. Review source-original capability/check labels alongside **HUMAN-only changed fields**, earlier categories, later categories, and their current conflict disposition. Search original source labels, filter by locally applicable/fully matched/conflicting, and browse 60 changes per page. These are original source claims and HUMAN planning proposals, **not verified issues/fixes**.
4. The desk performs an original-byte-bound **three-way HUMAN reconciliation**: for every changed field, if the current plan matches the manually selected earlier plan, the later value is eligible; if already equal to later, it is left alone. A third independent current value becomes an explicit **HOLD conflict**. The operator can individually choose **keep current** or **use later** for each conflict. Every conflict must be resolved deliberately before *any* application; invalid or incomplete plans cannot produce a partial merge. Current HUMAN plan changes invalidate prior conflict choices. Final application requires one explicit confirmation and changes ONLY categorical local HUMAN note fields.
5. Download independently (a) **anonymous counts-only CSV and JSON** with aggregate categorical HUMAN stage/review/action transitions and numbers of pending, matched, resolved or unresolved fields; or (b) a separately confirmed **PRIVATE read-only scriptless HTML** with up to 512 selected source capability/check labels and changed HUMAN categories. Any private source label can be sensitive; the latter must stay in a protected human-approved exchange channel. The HTML embeds neither original target URLs nor private evidence/raw source hashes and has a no-script/no-network CSP.
6. Clear the comparison independently of your current HUMAN plan. On loading a different original lab batch, both saved-plan histories and current planning are forgotten after explicit confirmation. This creates no browser history, account, shared service, persistent storage, server process or audit evidence.

The **source hash is only an unsigned exact-byte binding**, never authenticates who produced a source/plan, authorizes a scan, demonstrates client/operator consent, proves a chronology, or verifies any finding or remediation. The original release posture remains **INCUBATE · M3/M7 PLAN/LAB ONLY · DRAFT/HOLD** and all existing exact-head hosted/permanent named VPS CI, independent original owner/security/privacy/browser approvals, issues #177/#182/#829, actual separate authenticated client/operator consent and action-time revocation, and explicit HUMAN GO remain required before merge/deploy/active target operations. No QA tests/regression suites added or run; direct production-source syntax and static HTML inspection only.

---

## Endpoint declaration distribution — added 19 October 2026

The browser now shows a standalone **source-reported endpoint-appearance table** for the original 1–16 literal target declarations, aligned to **the first operator-selected original file's target order**. Additional original source files may list the exact same targets in different order; counts remain aligned by *exact target literal*, never positional guessing or DNS. An explicit **unmatched original finding target** slot is included. Selecting any endpoint ordinal or unmatched slot filters the private main matrix without contacting a target.

The HUMAN attention board detects **per-literal-check endpoint distribution movement even when the total original check finding count is unchanged**. It also retains warnings for changed source count, declared severity and unmatched reported targets. This is a non-authorizing declaration-diff, not proof of a new vulnerability, fixed problem, target ownership, completeness or risk reduction. Source-declared zero remains **unknown**, not clean.

The explicit anonymous JSON counts export now additionally includes `source_reported_endpoint_appearances`: numeric vectors in original local source-file order, with the final ordinal representing unmatched source target strings. No target names, raw URLs, evidence, original scenario IDs, run IDs, check/capability labels or source file names are exported. **Small-cell counts and source-slot occurrence patterns may still reveal sensitive correlations. Keep exports private.** CSV keeps numeric literal check-group appearance totals without endpoint names.

This addition changes only the separately owned `assessment-coverage-matrix/` browser UI, JS, generated CSP-pinned HTML and this operator README. It does not run any scan, perform DNS resolution, contact client targets, modify original source-owner or add QA/tests/CI changes. Original project posture and independent release gates remain **DRAFT/HOLD**.

---

## PRIVATE HUMAN workroom and exact-source continuity (19 October 2026)

The same offline [standalone.html](standalone.html) now includes a **real human triage workroom**, not just a check-count table.

- Select per literal source-declared capability/check group: HUMAN-only **stage** (needs review, queued, discussing, documented as a human note, blocked), **review group** (unassigned, scope, findings, evidence, remediation, privacy), and next proposed **HUMAN question**. None is a verified finding state, engagement authority, risk reduction, remediation or client consent. Source fields and source bytes are immutable.
- Search and page the private workroom (64 work items/page), filter on local HUMAN status, and open the original untrusted declaration on demand. The main comparison matrix independently renders **100 rows/page**, to avoid a large file set freezing the interface with thousands of DOM rows. Count exports still include **every currently filtered row**, not merely the visible page.
- **Bulk HUMAN routing** applies chosen stage/group/action to up to 512 locally filtered groups after an explicit human confirmation. A complete group larger than 512 is refused, never silently truncated. **Undo last bulk change** restores those local choices; manual updates, reset or private resume invalidate bulk undo.
- **Save PRIVATE plan** downloads original SHA-256-byte-bound source-slot fingerprints, the exact anonymous original sorted matrix row count, and only non-default categorical HUMAN choices indexed by source-local row ordinal. It contains no target addresses, raw findings, source labels, evidence, tenant/client or file path. **It is private and not encrypted**: SHA digests may be identifying; do not publish. File contents are neither encrypted nor signed, and matching the bytes is not proof of authentic original producer, operator identity, ownership or consent.
- To **resume**, first manually re-open the **same original source files in the same selection order**. Then select the saved PRIVATE plan. Every original input hash must match byte-for-byte; the entire plan must have the exact bounded schema, false authority flags, sorted unique canonical row ordinals and enum values. If not, the whole restoration is held and current HUMAN choices remain intact. Even when valid, an explicit second human confirmation is required before replacement. Browser environments without WebCrypto continue to allow in-memory HUMAN planning and source-free briefing but disable byte-bound save/resume rather than inventing a digest.
- **Counts-only HUMAN briefing** produces a self-contained `.txt` with stage/group/question totals **without original source labels, SHA hashes or targets**. A separate human-confirmed **PRIVATE read-only HTML handoff** includes up to 512 explicitly filtered HUMAN-planned source capability/check labels, local row ordinals and categorical choices. That scriptless document uses a restrictive no-network CSP, escapes source-supplied text, excludes target/evidence/raw result bytes and is not source-authenticated or an executable instruction. It **is PRIVATE** because original check labels may reveal sensitive information; exchange separately using an approved protected channel. Missing declarations never imply a fix or clearance.
- **Forget local data** clears the in-memory original files, fingerprints, human notes and selected views. No user accounts, localStorage, browser persistence, cloud sync or networking were added. The application warns on navigation away from a loaded workroom.

### Standalone packaging

`build_standalone.py` now embeds both `human-board.js` and `app.js` (in that order) plus `style.css` into the one-file offline HTML, pinning the **combined** JavaScript and CSS with SHA-256 Content Security Policy hashes. The generated `standalone.html` is committed in this held draft branch. This integrity convenience is **not an independent security audit, review verdict or provenance signature**.

### Non-negotiable posture

**Incubate · M3/M7 PLAN/LAB ONLY · DRAFT/HOLD** remains unchanged. Original source owner, independently reviewed privacy/security/browser source, complete exact-head hosted AND named permanent VPS CI, #177/#182/#829, separate genuinely authenticated current client/operator consent including revocation at action time, and explicit HUMAN GO still remain mandatory before any main merge, live scan, grant, client action, deploy or release. No QA, regression or test suite created or executed as part of this implementation; only production JavaScript syntax and source packaging were inspected directly. No real lab result or target was used.

---

# LightUp · PRIVATE Original Lab Declaration Matrix

**INCUBATE · M3/M7 PLAN/LAB ONLY · DRAFT/HOLD — human source-declaration review only.**

[Open the standalone offline app](standalone.html) · [Source HTML](index.template.html) · [Source JavaScript](app.js) · [Source style](style.css)

This is an **independent add-only** assessment-runtime product in `assessment-coverage-matrix/`. It does not change the original source owner, held [lab-assess #1610](https://github.com/Zennay/Lightup/pull/1610), the [one-result review desk #1639](https://github.com/Zennay/Lightup/pull/1639), [benchmark comparator #1515](https://github.com/Zennay/Lightup/pull/1515), an active worker claim, the scanner, grants, CI, domain model, deployment or a real target.

## Operator workflow

1. Download **`standalone.html`**, keep it on a trusted private device, and open it locally with a browser. The package contains all styles and logic. No server, dependencies, account, API, fetch, fonts, trackers, source files, test runner or internet is necessary.
2. Obtain **2–8 already-generated original private lab-assess JSON results** from a separately approved lab owner. This tool does not produce, authorize or run lab assessments. Files must be distinct declared run IDs, each ≤8 MiB, and claim the **same literal scenario ID and exact declared endpoint set** (target order may differ). They must follow the pinned original result schema. Same declaration does **not** prove shared ownership, permission, genuine isolation or source integrity.
3. In the browser, select all originals in your desired left-to-right order. Import is **whole-batch**, strict UTF-8 / bounded depth / duplicate-property-rejecting JSON / original evaluation / finding / plan / benchmark-shape admission. An invalid, duplicate or incompatible original holds the *entire new selection*, leaving the prior opened batch intact.
4. Inspect the **literal capability-ID + check-ID matrix**. For each locally selected source, the cell contains only the count and highest source-declared severity for that literal tuple. Click to see private finding statements, endpoint ordinals, source mitigation and source retest proposals. This is not a verified check-run or finding identity comparison. Source-provided text is rendered with `textContent`, never interpreted as HTML.
5. Review the **separate source-reported adverse numeric panel**: the original evaluation claims valid, invalid, missed, unknown coverage, scope violations, policy violations and human interventions for each local source ordinal. Positive adverse values are prominent. **Zero is a source assertion, never evidence of a compliant assessment or policy approval.**
6. Search source literal tuple labels or filter by original severity and endpoint ordinal. **An empty filtered cell means only “not declared under this filter.”** It cannot be interpreted as success, absent vulnerability, full coverage, remediation, valid evidence or a missing scanner check. All original target literals are kept out of the visible matrix. Unmatched original `finding.target` strings receive an *unmatched* endpoint label rather than a guessed assignment.
7. With deliberate human confirmation, download **counts-only JSON or CSV** for the currently filtered rows. Exports contain anonymous row ordinals, counts and (JSON) source-declared severity counts **plus original unverified adverse-counter arrays**, without source IDs. They contain **no** original run/scenario IDs, target URLs, capability/check IDs, finding titles, evidence details, source hashes, file paths or reviewer identities. Small-cell aggregates can still be sensitive; downloads are unencrypted. CSV contains strictly generated nonnegative integer digits, so does not include source-supplied spreadsheet formulas.
8. Choose **Forget local data** to discard all original source objects from this browser workspace. The app has no localStorage, cookies, worker, analytics, DNS, requests, outbound communications or automatic retention. Separately delete any explicit downloaded artifact according to your private retention policy.

### What this is not

The matrix groups untrusted literal labels and the original source-reported adverse metric counters across **already-produced** sources. It does not infer chronology, authenticity, evidence match, completeness, ground truth, negative tests, coverage assurance, client permission, assessment authorization, scanner effectiveness, vulnerability persistence or remediation. A missing source declaration is **never** a fixed issue. Endpoint membership comparison is literal, not DNS-resolved. Severity is source-reported, not independently verified. If original source files disagree on declared scenario/endpoint membership, the app refuses the comparison rather than silently reconciling.

There is **no scan, grant, target probing, model call, dispatch, client contact, human consent collection, file upload or client-facing publication**. This review capability is intentionally useful only for human analysis of already-authorized privately held lab artifacts.

## Rebuild from committed source (optional)

With Python 3 standard library, run from repository root:

```sh
python3 assessment-coverage-matrix/build_standalone.py
```

The builder embeds exactly `index.template.html`, `style.css`, and `app.js` and pins inline JS and CSS hashes in a strict network-free Content Security Policy. The generated `standalone.html` is included in this draft branch. CSP hashes make accidental mismatches visible; they are **not a security audit or provenance signature**. A maliciously supplied complete application could choose its own CSP hashes. Use trustworthy code distribution.

## Original gates — DRAFT/HOLD

LightUp's Notion project phase is **Incubate; M3/M7 PLAN/LAB ONLY**. There is **no green release assertion**, main merge or deployment from this branch. Complete existing original **hosted AND permanent named VPS exact-head CI**, owner acceptance, independent source/security/privacy/browser review, issues **#177 / #182 / #829**, actual distinct authenticated client/operator consent with action-time revocation before any future active work, and explicit **HUMAN GO** remain mandatory. **Do not** use this app to claim authorization, run a test, approve a finding or contact any target. No QA/regression/testsuites are added or run by this implementation.


## Two-stage PRIVATE encrypted workroom admission (23 October 2026)

**Inspect complete ENCRYPTED workroom** decrypts and re-admits all original PRIVATE sources and HUMAN choices locally, but does **not** replace the active original batch. The displayed PRIVATE preview exposes only total byte lengths, original slot count, source-declared row count, and the number of non-default HUMAN workplan rows. The separately confirmed **Apply inspected PRIVATE workroom** performs the replacement only when the source/HUMAN session is still unchanged. **Discard decrypted preview**, selecting another encrypted file, replacing originals, forgetting data, and leaving the page invalidate the preview; staged byte buffers receive a best-effort clear, not certified physical memory erasure. No automatic import, source authentication, consent, grant, scan, or network call. Encrypted exports are also abandoned rather than downloaded if original sources or HUMAN decisions change while browser-side encryption is in progress. A slow unencrypted original batch import cannot overwrite intervening source/HUMAN edits either.

### Recover HUMAN decisions without replacing the ORIGINAL lab files

After inspecting a complete encrypted private workspace, the browser also offers **Restore HUMAN choices only (same original bytes)**. This button is enabled solely if the currently open original set has exactly the same ordered SHA-256 source bytes and row count as the fully admitted staged originals. A separate HUMAN confirmation retains current sources and replaces only current HUMAN planning choices; the staged original plaintext buffers are discarded. If the current originals are different, reordered, absent or changed mid-decryption, the action HOLDs without changing current choices. A source SHA-256 is an unsigned exact-byte check, never an attestation of uploader identity, consent, original finding truth or authorization.
