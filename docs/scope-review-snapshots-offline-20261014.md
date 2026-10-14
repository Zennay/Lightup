# Cross-snapshot scope review — offline consistency preview

**LightUp INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD · NO MERGE · NO DEPLOY · NO REAL TARGETS.**

This optional, standalone tool compares **2–4 local JSON review snapshots** in one request. It checks **cross-file** duplicate request IDs, tenant-mismatched authorization/scope reference labels, re-used evidence-digest labels across tenant labels, and overlapping review windows for the same tenant, asset and capability. Each snapshot must separately meet the ordinary single-/batch-packet contract before the merged set is checked. Sorted internal comparison makes the result independent of which historical file is supplied first; a duplicate or one invalid file forces the **entire review to HOLD**. It does not import LightUp active executor, launch tools, query a network or write data.

## Opt-in local CLI

```sh
python scripts/check_scope_review_snapshots_offline.py /private/a.json /private/b.json
python scripts/check_scope_review_snapshots_offline.py --require-private-file --summary /private/a.json /private/b.json
python -m unittest discover -s tests -p 'test_scope_review_snapshots_offline.py' -v
```

Limits: 2–4 files, each at most 64 KiB; combined byte budget 128 KiB; maximum 32 individual packet items across all files. Each source is a local regular file read using the existing bounded single-purpose reader. The optional POSIX privacy mode applies to **every** file, and `--summary` emits fixed aggregate risk/mode counters only on fully consistent snapshots. A rejected file yields the same all-zero histogram even if earlier files were valid. No customer identifiers, asset addresses, input values, file names, approval references or tokens are printed.

Receipt always contains `state` (`REVIEW_ONLY` or `HOLD`), a fixed `reason`, `packets_checked`, `files_checked`, `non_authorizing=true`, and five authority flags that are **always false** (`authorization_verified`, `permit_issued`, `execution_enabled`, `merge_approved`, `release_approved`). Any HOLD resets both counts to zero. A valid shape is **not** a verified grant, evidence attestation, operator approval or release token. CLI exits 0 for review-only, 2 for HOLD.

## Hard limitations

- This is a snapshot comparison, **not** durable scheduling, a lock, a transactional lease, replay prevention or a chain of custody. It cannot detect conflicting past/future files not explicitly included in its one invocation. Independently modified files between read times may present inconsistent views; local stat checks are only heuristics.
- Requester, authorization/scope labels and purported SHA-256 references are **untrusted caller-supplied metadata**. Matching values do not verify owner/tenant identity or legal consent. A would-be attacker can simply supply unique labels.
- Same-asset overlapping intervals are a **review consistency convention** with half-open windows, not authorization windows. Cross-file review cannot widen or narrow live grant authority.
- No scan, target activation, DNS, network, source-owner code, workflow, runner or main branch is changed. Original owners must enforce real grant validity, tenant/asset lineage, revocation, STOP policy and target/capability authorization immediately before dispatch.
- Separate latest-main compatibility, raw hosted and independently registered permanent VPS CI, independent security/privacy/source-owner assessment and **explicit human release** remain mandatory. Do not merge or deploy on the basis of this offline helper.

The 18 synthetic tests include each cross-snapshot denial, order independence, late-batch atomicity, counts zero on error, CLI privacy and no unexpected authority effects. No real targets or customer files are used.
