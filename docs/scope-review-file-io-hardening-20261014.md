# Offline scope review file I/O hardening — W11/W12

**INCUBATE M3/M7 · DRAFT/HOLD · NO MERGE · NO DEPLOY · NO TARGET SCANS.**

## Scope

These independent improvements apply only to the optional local scope review helpers on draft PR #1316. No active LightUp grant resolver, network, scanner, customer account, production runner, CI workflow or release switch is modified.

### W11 — descriptor-relative owner-only reads

With **opt-in** `--require-private-file`, parent path components are opened one at a time via `openat`-style directory-relative `os.open(dir_fd=...)`, with `O_NOFOLLOW | O_DIRECTORY` on each directory and `O_NOFOLLOW` for the final regular file. The pre-existing checks of effective ownership, single hardlink, no group/other access, metadata pre/open/post invariance and zero-on-HOLD receipts remain in place. The mode fails closed on platforms lacking descriptor-relative opens or no-follow directory semantics. A symlink swap after the preliminary `lstat` cannot silently redirect a private file read to a malicious target: the OS no-follow open holds it.

Synthetic tests (11): direct and nested symlinks, deliberately swapping an inspected parent or final component immediately before descriptor-relative opening, simulated missing OS support, demonstration of no FD leak under repeated reads, CLI no-path-leak and compatibility of the separate default path.

### W12 — bounded complete read for regular files

Both packet and batch readers now use a **shared bounded EOF loop** rather than assuming a single `os.read` call returns an entire regular file. Every read requests at most 8192 bytes; total allocation is capped to the declared local file limit plus **one byte** (single packet 16 KiB; batch 64 KiB). Short chunks are assembled to EOF. A file that grows beyond its limit is held with `SIZE_LIMIT`; a file whose accumulated bytes disagree with the original `fstat` size is held with `CHANGED_INPUT`. The existing post-read `fstat` detects observed same-size metadata changes as a fixed-code HOLD.

Synthetic tests (9): one-byte returns on both code paths (with/without private flag), interrupted early EOF, appended content and same-length mutation during read, oversized local inputs, byte budget enforcement and absence of active executor/network imports. This is **not** an immutable filesystem snapshot, transaction, data-signature validation or actual consent check.

## Safety boundary

A successful local read or `REVIEW_ONLY` receipt proves only bounded syntactic consistency of caller-controlled bytes. It never proves origin, customer ownership or current authorization, and its five authority flags remain `false`: `authorization_verified`, `permit_issued`, `execution_enabled`, `merge_approved`, `release_approved`. If a private mount or privileged actor can swap content/metadata without observable changes, these local heuristics are not cryptographic attestations. The real source-owner, security/privacy reviewer and human must independently approve any live admission mechanism and release. Permanently registered VPS CI and hosted CI must correspond to the exact immutable head before review; hosted-only success does not authorize merge or deployment.
