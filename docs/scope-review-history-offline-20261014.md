# Offline scope review history — W10

**LightUp INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD · NO MERGE · NO DEPLOY.**

A previous and final scope-review batch can look syntactically non-widening while an intermediate review version temporarily widened risk, capabilities, or time. This **optional standalone offline helper** checks the whole explicitly supplied history, comparing **every adjacent version** by the W9 fail-closed delta checker. A later restrictive revision cannot hide an earlier out-of-bounds revision in the provided series. This is a **non-authorizing review diagnostic**, not authenticated source history, a signed audit log, a real grant check or a production dispatch gate.

## Usage

```sh
python scripts/check_scope_review_history_offline.py /private/v1.json /private/v2.json /private/v3.json
python scripts/check_scope_review_history_offline.py --require-private-file /private/v1.json /private/v2.json /private/v3.json
python -m unittest discover -s tests -p 'test_scope_review_history_offline.py' -v
```

Only **2–4 explicitly ordered, local, regular JSON batch files**, oldest to newest. Each may contain 1–32 canonical v1 records, at most 64 KiB; the entire invocation accepts at most 128 KiB. The optional `--require-private-file` flag applies the pre-existing owner-only POSIX, one-hardlink, no-parent-symlink, no-`..`, local-file checks to **every** supplied file. It rejects invalid file types, unknown/missing parents, duplicate keys and unsafe JSON via the original validators. No network I/O, remote targets, SQL state, subprocess workers, source-owner components or user data logging.

The helper compares `version[0]→version[1]`, then each successive pair. Any addition or re-addition of a deleted request, changed tenant/asset/requester or supposed authorization/evidence provenance, mode change, risk elevation, capability addition, or widening of exact UTC windows **HOLDs the complete history**. Late failure erases all previously accumulated counters. Success is only `REVIEW_ONLY` with two aggregate counters: `transitions_checked` and `narrowing_events` (per-transition narrowed + removed requests; a request may contribute multiple times). Both counters are zero upon HOLD. Five permission/release flags always remain explicitly false; no request IDs, tenant IDs, paths, addresses, digests, approval references or token values are emitted.

**Critical limitations:** caller-provided versions have no signatures, chain of custody, inclusion proof, continuity, owner attestation, revocation check or trusted timestamp. An adversary could omit a temporarily widened version and supply a clean-looking history. The helper cannot establish that either snapshot was valid authorization or that this is a complete sequence of revisions; the earlier snapshot may be forged. The tool must never enable a scan, create grants, override STOP controls, merge or deploy. Production execution needs independently authenticated scopes and monotonic live grant checks at dispatch, verified issuer and tenant/asset lineage, source-owner/security/privacy review, actual registered permanent VPS raw CI for the exact HEAD, and explicit human release approval.

Seventeen synthetic tests cover unchanged and monotonically narrowed histories, temporary expansion then reversion (risk, capability, time), removal and re-addition, mode and provenance changes, malformed middle/oldest versions, memory/shape bounds, CLI privacy and false-only receipts.

## W11 stronger private-path integrity — descriptor-relative POSIX open

In the optional `--require-private-file` mode, the local file reader now opens parent directory components **relative to already opened directory descriptors** using `O_DIRECTORY | O_NOFOLLOW`, then opens the final regular-file component using `O_NOFOLLOW` and the parent directory descriptor. These checks run in addition to the earlier privacy/owner/hardlink/metadata checks. If a directory is replaced with a symlink **after the initial lstat but before opening**, descriptor-relative no-follow semantics fail with an opaque `INPUT_UNAVAILABLE` HOLD. If the platform lacks descriptor-relative `os.open` or POSIX no-follow capabilities, requesting the stronger private-file mode yields fixed-code `PRIVATE_PATH_UNSUPPORTED` HOLD rather than silently falling back to a weaker check. The default non-private read path retains its original behavior for purely synthetic fixtures.

The new synthetic POSIX regression suite `tests/test_scope_review_dirfd_offline.py` tests real renamed-parent and swapped-final-file race simulations, symlink checks even if the preliminary check is artificially bypassed, old public-file compatibility, unsupported-platform denial, expected descriptor flags, path-safe CLI errors and closure of directory file descriptors. No real target is contacted. Even a successfully read file **does not authenticate its content or confer any grant**. This protects only local path traversal against certain symlink substitutions; it is not a trusted file-origin attestation, complete fix for all namespace/mount races or a substitute for source-owner security review and explicit human release.
