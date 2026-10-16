# #1499: Offline authority source fingerprint + AST review

**LightUp = INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.** This independent issue and draft change add a **read-only static review helper** for an owner planning a security/code-review handoff. It does not change or run original source, does not scan networks or customers, and cannot issue permits or grants. All changes live in uniquely named #1499 paths, disjoint from open PR #1498 and from original source-owner PRs.

## Actual inspected files

The script reads exactly five built-in files from this repository checkout (no user-provided root/path argument): `scope.py`, `activation.py`, `execution_policy.py`, `models.py`, `engagements.py` in `src/lightup/`. The review pins their original immutable baseline bytes from `main` commit `e73b7445c87ad239bdb03c50a99078ef93163b02` with SHA256 and inspects a small set of AST class/method names, arities, decorators and dynamic interpreter calls. It does **not** import or execute any of these five source files, call an activation gate, validate a live customer, authenticate a reviewer's identity, or verify a target. The original source already contains known security review gaps and open RED canaries.

```bash
python -m unittest discover -s tests -p 'test_scope_static_authority_1499.py' -v
set +e
python tools/scope_authority_source_inventory_1499.py --offline-review-only
status=$?
set -e
test "$status" -eq 2
# Bad/unknown arguments -> generic HOLD, exit 3; no success status 0.
```

The only output is a fixed, versioned JSON object with `status`, `source_count`, `contract=LIGHTUP-SOURCE-AUTHORITY-INVENTORY-1499-V1`, and four **literal false** authorization, consent, dispatch and release flags. `REVIEW_ONLY` / exit **2** means solely **the five selected files match the developer-selected baseline snapshots and limited AST shape**; `HOLD` / exit **3** means something was missing, corrupted, unexpectedly different, unsafe in its type/shape or outside the chosen static snapshot. Neither result allows execution or proves safety.

### Human-owner handoff / remaining blockers

A `HOLD` should trigger offline review of the particular PR and source-owner evidence, not an automatic permit or an attempt to update hashes until the job is green. A `REVIEW_ONLY` is **not a clean bill of health**; it can coexist with the historical #301 RED, unresolved real revocation, an absent permanent VPS, or missing real client/operator signatures. Every hash here is chosen by developers *inside the same untrusted repository*: not signed provenance, binary attestation, authentic CI runner, immutable security authority or evidence of client ownership. Successful hosted CI does not prove `vps-bb300bba` ran anything.

Original issue owners stay responsible for production and test fixes. In particular: [#301](https://github.com/Zennay/Lightup/issues/301) / [draft PR #1452](https://github.com/Zennay/Lightup/pull/1452) owns original datetime corruption, [#1144](https://github.com/Zennay/Lightup/issues/1144) owns permanently registered VPS availability, other active source-owner PRs control their own scope/capability/revocation issues. No modification, merge or ownership takeover of those branches. Actual scope and risk source reviews, trusted client/operator consent, durable revocation at time of use, complete genuine hosted CI + verified registered VPS, security/privacy and explicit human GO remain **mandatory before any real workflow release**.

### CI isolation

The separate read-only workflow runs only own tests on hosted Python 3.11/3.14 and tests both real CLI outcomes; no credentials are persisted by checkout, no secrets, no target scans or production adapters, no existing canonical VPS job/workflow modified. The test suite mutates **in-memory copies only**, including source drift, duplicated symbols, forged argument defaults, dynamic interpreter calls, missing/extra/wrong files, and symlink redirects. Tests do not execute the mutated text. Changing the baseline requires a deliberate independent human-owner review of changes; never automatically bless new hashes.

## W2: Static gate call topology proof (limited, non-executable)

The independent reviewer now also checks that the original `ScopePolicy.decide` source still calls `normalize_host`, `ip_address` and `is_current` in their original lexical order; `ExecutionPolicy.decide` still names `is_current`, `allows_asset` and `allows_capability` in order; and `ActivationGate.issue` still contains the `scope_policy.decide` call, an explicit `if not decision.allowed: raise` branch, and a later `ExecutionPermit` constructor. Tests deliberately delete each check from in-memory copies of the original source and show static HOLD without ever evaluating the changed source or calling any permit method.

This proves **only that named static code patterns and the exact pinned source snapshot are present**. AST presence is not proof of a correct runtime guard, functional policy ordering, fresh revocation, legitimate client approval or absence of bypasses. In particular #301 and other real original source REDs remain open, so even REVIEW_ONLY is NEVER a security GO. The present static pin hashes should be updated only after a reviewed, source-owner-approved original source change and a separate human evaluation of the complete runtime authority boundary.

## W3: fixed-directory nofollow source file access

The CLI now uses Linux/POSIX directory-descriptor-relative `os.open()` of the fixed repository, `src` and `lightup` directories with `O_NOFOLLOW` and `O_DIRECTORY`; each fixed source filename is opened relative to the already-open package directory with `O_NOFOLLOW | O_NONBLOCK`. Only actual regular files are read, at most 131,073 bytes; FIFOs and symlinks are refused. Temporary file descriptors close on errors via `ExitStack`. If the POSIX features are missing, the function fails closed to generic HOLD rather than silently following symlinks. In-memory pure review remains independent of any files or runtime.

New regression cases reproduce symlinked repo roots, redirecting the `lightup` package directory, non-regular FIFO files, and simulated file replacement immediately before a file open. These are hermetic temporary local fixtures; never customer or real target access. This is not a cryptographic filesystem integrity proof, malicious kernel/runner resistance, or release readiness.
