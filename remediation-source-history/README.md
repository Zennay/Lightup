# LightUp Remediation Source History Studio

**Current posture:** INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD. This is an **offline, local, non-authorizing HUMAN coordination tool**. It never executes remediation, retests, scans, grant creation or network calls. The findings and retest fields are *unverified historic source claims*, not conclusions.

## Open the product

- Open `standalone.html` locally in a modern browser. This generated single-file distribution works without servers, installed packages, or other files.
- Alternatively open `index.html` directly alongside `history-studio.js`, `studio.css` and the original unchanged parent `casework/remediation-engine.js`. If the browser restricts local scripts, use the standalone file; do **not** disable browser security to run the app.
- To rebuild offline using Python: `python3 remediation-source-history/build_standalone.py`. The packager **refuses any alteration** to the original Casework parser and generates exact SHA-256 inline CSP script/style hashes. Source owner SHA `9c73e8468ce271bf8c6bef4cac071e5ad9c1806b` is unchanged.

## Complete HUMAN workflow

1. Obtain original exported LightUp five-column CSV snapshots from an **independently authenticated, approved same client + same engagement** private channel. This product does not authenticate clients, operators or files; client/engagement labels and checkboxes are not consent.
2. Enter two local human context labels; confirm you independently verified the same client and engagement. Import up to **12** chronological source snapshots, each ≤ 1 MiB and ≤ 350 findings. The original Casework parser enforces exact columns and canonical source values.
3. Every admitted snapshot is hashed both as exact imported bytes (SHA-256) and as the original **canonical source record digest**. Identical original canonical content is rejected to avoid misleading duplicate timeline points. Use **↑ / ↓** to correct chronological order and change the optional local revision labels without mutating source. The default labels are generic to avoid leaking original filenames in aggregate exports.
4. Review the visual exact original finding-ID history: source severity + source retest status, full remediation text in per-finding timeline, changes/appearances/disappearances, severity changes and retest label changes. Missing from a later source is **NEVER evidence of remediation**, and `fixed` is **only the original unverified source label**.
5. Filter by original IDs, titles, human owner, critical/high labels or source-change category. Attach tentative local HUMAN owner, next discussion/action and due date. These annotations live in memory and never modify any original finding.
6. Export aggregate CSV source trajectory counts (no original IDs, titles, remediation text or HUMAN notes); or explicitly acknowledge a separate approved PRIVATE recipient/destination and export the currently filtered original-ID HUMAN handoff CSV. CSV formula-like fields are spreadsheet-escaped. Downloads remain private on the operator device and are **not** deleted by the application.
7. For a **source-exact encrypted local save/resume**, tick the private destination acknowledgement, enter a unique passphrase of 14–256 characters, and select **Save encrypted PRIVATE checkpoint**. AES-256-GCM uses Web Crypto, PBKDF2-SHA256 with 600,000 iterations, random 16-byte salt, a unique 12-byte IV and authenticated application-context binding. The encrypted checkpoint stores the original exact CSV bytes, both SHA-256 identities, revision labels and HUMAN notes. Restore requires Forget/empty workspace plus independent re-confirmation of the same exact client and engagement; the application authenticates the local AES-GCM envelope, reconstructs every original source via unchanged `LightUpCasework.parseCSV`, rechecks file-byte **and** canonical-source SHA-256, rejects duplicates/unknown notes and changes in-memory state atomically. The checkpoint does not authenticate the creator/client or confer consent. **Keep the passphrase and encrypted export private; forgotten passwords cannot be recovered.**
8. Click **Forget** to clear imported original records and HUMAN notes from the live app memory. No `localStorage`, cookies, IndexedDB, network, external scripts, telemetry or file uploads.

## Safety / review boundary

The project remains **DRAFT/HOLD** until existing exact-head hosted and permanently named VPS CI, original source-owner and security/privacy review, canonical #177/#182/#829, current separate authenticated client/operator authorization with revocation-at-use, and explicit HUMAN GO. Neither this standalone artifact nor its hashes, human labels, imported original source claims, or spreadsheet exports authorize assessment or establish a verified fix/retest. The product is deliberately isolated to the new `remediation-source-history/` directory; no original source, production API, scanner, risk/grant policy, test suite or CI workflow is changed.

**Privacy:** Original CSVs, downloaded PRIVATE handoff CSVs, and notes may contain sensitive client information. Use only a permitted device, approved recipients and separately authenticated internal context; do not upload or publish those outputs. Aggregate CSV omits finding IDs but may still contain sensitive counts/source digests, so review its recipient.

**No test suites were added or run** as requested; packaging and native syntax inspection are build/source checks only.
