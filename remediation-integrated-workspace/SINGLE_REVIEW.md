# LightUp · One-Cockpit PRIVATE HUMAN Review (source-free)

**INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.** This independently executable offline recipient feature handles **one complete, original, already-delivered, source-free PRIVATE Cockpit**. It never fabricates a second snapshot, "before/after" delta, owner identity, authenticated chronology or verified security result. It is separate from the existing 2–12 packet comparison/series on [PR #1673](https://github.com/Zennay/Lightup/pull/1673).

## Actually usable workflow

On a private Linux account with the original source-free Cockpit and this exact integration branch, create a fresh output inside an existing owner-only 0700 parent:

    python3 remediation-integrated-workspace/single_review.py start --cockpit "$HOME/lightup-private/received-01" --output-dir "$HOME/lightup-private/human-single-01"

Open human-single-01/index.html locally in a trusted browser. The offline HTML has a native pinned SHA-256 CSP for its local JavaScript and CSS. It displays only **original source-free HUMAN reason counts**, original slot ordinals and static original source-owner follow-up advice. For each actually occurring original reason, choose a HUMAN-only follow-up state and add a short private note. The page has **no network, browser persistence, server, cookies, uploads, grants or active target functionality**. Its Save action explicitly downloads a **plaintext PRIVATE JSON** HUMAN journal only after you click. Keep that journal private; do not put client/customer identifiers, secrets or credentials in free-text notes.

To resume, first move the downloaded JSON to an owner-only 0600 local file under a private 0700 directory. Re-admit it with the **same complete original source-free Cockpit**, then publish a new, independent viewer:

    python3 remediation-integrated-workspace/single_review.py resume --cockpit "$HOME/lightup-private/received-01" --journal "$HOME/lightup-private/lightup-human-single-review-private.json" --output-dir "$HOME/lightup-private/human-single-02"

The original unmodified read_cockpit.inspection rejects unexpected members, malformed source-free packet, altered HTML/manifests or semantic contradictions. The saved HUMAN JSON must carry exactly the original manifest/portfolio hash, original slot/reason/count/order, literal false-only authority flags, the original warning, a valid HUMAN status vocabulary and bounded Unicode notes. New report folders and files are native private 0700/0600, exclusively published and never overwrite old folders. No row from one source is attributed to a later different source.

This is unsigned local HUMAN discussion state, not independent source authenticity, actual consent, real remediation/fix, owner acceptance, security decision, retest or a ticket/action authorization. **The exported JSON is not encrypted** and manual sharing still requires separately authenticated recipient approval. Neither the browser nor CLI transmits it. The source-only software installer in PR #1673's earlier 34959cc release does not yet include these new standalone files; use the integration branch with both single_review.py and single_review.js side-by-side.

This addition does not modify original Casework, ledger, consent, grants, scanning, original HUMAN browser owner, CI, QA or deployment. Original exact-head hosted + permanently registered named VPS CI, original source-owner and independent privacy/security/browser review, genuine separately current authenticated client/operator consent including revocation-at-use, #177/#182/#829 and explicit HUMAN GO remain required for any release.
