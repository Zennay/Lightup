# Issue #777 · Synthetic producer/direct provenance differential

**LightUp posture: INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.** This is an independent, add-only acceptance artifact; it does not alter `src/lightup/**`, branch `chatgpt/scope-authorization-direct-grant-approval-provenance-red-20261007`, production authority, workflow configuration, or any other worker's PR.

## Why this adds a distinct acceptance signal

Issue [#777](https://github.com/Zennay/Lightup/issues/777) already has a branch-only direct-policy RED acceptance against frozen PR #100. This follow-on tests a *different observable contract* on the current mainline: a disposable real SQLite `DomainStore.record_authorization_grant` producer accepts legitimate padded input and persists its canonical trimmed provenance; the *same* approval values are then evaluated as a canonical direct `AuthorizationGrant`, while modified caller-owned direct objects are asserted not to authorize. It demonstrates the producer/direct mismatch without borrowing or modifying the first RED branch.

`tests/test_scope_777_producer_direct_provenance_differential_20261015.py` performs four ordinary positive/denial controls and fourteen **expectedFailure** direct-authority canaries. The direct canaries separately exercise empty/whitespace-only/padded values and built-in-`str`-subclass impersonation for both `approved_by` and `reference`, plus non-string values (`bytes`, `int`, `None`) and Unicode whitespace padding (em space and non-breaking space). Each canary builds a valid synthetic persisted grant then modifies only an in-memory copy; policy decisions must be non-authorizing **and** side-effect-free. All names and assets are fictional, with `example.test`; there is no network I/O, handler call, customer data, production state or issuance of real permits.

The fourth regular (non-xfail) regression probes all 14 malformed direct-object variants, requiring a typed policy decision without exceptions and no changes to the in-memory object or SQLite state. This independent green control prevents an unexpected exception from being silently reported as an expected security failure.

## Acceptance and interpretation

- **Current baseline:** direct `ExecutionPolicy.decide` checks validity, risk, asset and capability but does not enforce canonical provenance. Fourteen expected failures intentionally flag the gap; green CI including expected failures **does not** mean the gap is fixed.
- **Production-owner closure:** on the integrated source SHA, fourteen xfails must become ordinary passing denial tests, the four ordinary producer/direct-no-crash tests must still pass, and `approved_by`/`reference` must be exactly built-in `str`, nonempty after strip, and stored without leading/trailing whitespace.
- Rejection must be pure; no change to direct grant, original persisted snapshot, queue, evidence, handler, or target.
- Do not merge, run real active assessments, deploy, make grants, assume VPS success, or promote this branch. Require independent owner review, original PR #100 integration, trusted consent, precise destination and per-dispatch revocation, hosted exact-head CI and canonical registered VPS proof followed by human approval.
- Per [#777](https://github.com/Zennay/Lightup/issues/777), retain **branch-only** while the canonical self-hosted runner queue is saturated; this branch has no new PR or manually dispatched runner job.


## Independent offline reviewer (non-authorizing)

The uninstalled `scripts/scope_777_review_provenance_offline.py` is an executable,
standard-library-only *untrusted metadata* reviewer. It accepts only one bounded
UTF-8 JSON object containing exactly `approved_by` and `reference`; each must
be an exact non-empty, non-padded string of at most 128 UTF-8 bytes, with no
control/invisible characters. Its 4,096-byte maximum input is enforced before
JSON parse. BOM, invalid UTF-8, ambiguous/duplicate keys including decoded
escape aliases, unknown fields, nonfinite numbers, malformed or deeply nested
JSON, and spoofed approval flags are generic `HOLD`.

At the actual CLI boundary, input must be a local pipe/FIFO or regular
file; output must be a local pipe/FIFO or real TTY. An inherited socket,
device stdin, regular-file stdout or socket stdout is refused before data is
read or emitted. This is a conservative, uninstalled local preflight, **not** a production
consent or race-proof authorization boundary.
No network connection is made by the reviewer.
Bounded stdin reads use a monotonic two-second EOF deadline, with the fd
restored to its original blocking mode afterwards. A timed-out incomplete
claim receives the same generic HOLD output. Output uses one nonblocking
receipt write of at most 512 bytes and restores the original fd mode, so a
filled pipe cannot hang the program. The admitted input and output descriptors are now checked and pinned
with `os.dup` before untrusted I/O. All reads/writes go to those pinned
descriptors; original-to-pinned identity is checked after admission and again
before output. The tool closes both duplicates, including on failed pinning.
These safeguards do not replace authenticated operator consent, source-of-truth
revocation or real target authorization.

Its *only* receipts are `REVIEW_ONLY` (lexical consistency, exit 3) or `HOLD`
(exit 2), with six literal false authority/permit/dispatch/merge/deploy/release
fields and no echoed input. Both outcomes are nonzero. It never authenticates
an operator, checks a durable grant, mints tokens or writes state. Do **not** use
real customer records, and never treat `REVIEW_ONLY` as consent.

Synthetic-only example:

```bash
printf '%s' '{"approved_by":"fictional-operator","reference":"ROE-FICTIONAL"}' \
  | python scripts/scope_777_review_provenance_offline.py
# Expected process exit 3, REVIEW_ONLY plus six false flags.
```

Run exactly the standalone review acceptance in a checkout:

```bash
PYTHONPATH=src python -m unittest discover -s tests \
  -p 'test_scope_777_offline_provenance_review_20261015.py' -v
```

**Executed local reference validation:** the same isolated reviewer and
regression fixtures were executed under Python with all **29 / 29 standard
library test methods passing**, including real subprocess exit-code and privacy
checks, size/type boundaries, JSON-escape collisions, spoofed extra permit
fields, local file input, socket stdin/stdout refusal, rejected regular-file
stdout, complete regular-file snapshots (start offset, bounds and mutation),
positive and negative descriptor rebinding checks, failure-path descriptor
closure, and no input mutation. These were executed outside a full LightUp
checkout because the GitHub repository could not be cloned from this sandbox.
**This is not exact-head hosted/VPS CI proof.** The complete LightUp suite and
earlier SQLite producer/direct differential remain unexecuted in this run,
pending canonical repository CI.


### W4/W5: strict snapshots, pinned descriptors and fuzz acceptance (2026-10-15)

After the earlier 18-method evidence, W4/W5 added 11 independent tests and two
fail-closed protections:

1. **Regular input must be a complete immutable snapshot.** For fd0 files,
   reject seeked/nonzero starts, empty/oversized files and changed
   `st_dev/st_ino/st_mode/st_size/st_mtime_ns/st_ctime_ns` or incomplete
   consumption before any `REVIEW_ONLY` verdict.
2. **Pin the actual allowed endpoints before I/O.** Check pipe/file/TTY type,
   `os.dup` both input and output, verify identities before and after pinning,
   read/write only the pinned descriptors, detect original-fd rebinding and
   close duplicates even if the second `dup` fails.

**New deterministic W5 fuzz:** 2,048 seeded untrusted byte payloads ranging
from zero through above the exact 4KiB input ceiling, and 192 extra
non-whitespace/trailing-document mutations of an otherwise valid claim.
Every verdict has only the fixed status and six strictly false authority
flags; trailing mutations must be exactly HOLD. This is no real customer
data, scans or network request.

**Actually executed locally:** Python 3.13.5 compile and 29/29 standalone
reviewer tests passed twice (including `PYTHONHASHSEED=random`). GitHub
contents were re-fetched and match the exact locally tested script and tests
in character count and code-point FNV32 diagnostic. These are **not** full
repository Python 3.11/3.14 hosted checks, registered VPS CI, installed
ingress proof, or a production-authority fix. The 14 deliberate RED direct
policy acceptance cases remain unresolved by their original source owner.

## Verification

From a clean source checkout with the repository's established test environment:

```bash
PYTHONPATH=src python -m unittest -v tests/test_scope_777_producer_direct_provenance_differential_20261015.py
```

If dotted discovery does not work because `tests` is not a package, use:

```bash
PYTHONPATH=src python -m unittest discover -s tests -p 'test_scope_777_producer_direct_provenance_differential_20261015.py' -v
```

Expected baseline: four ordinary passes and fourteen *expected failures*, zero unexpected passes or errors. These expected failures are security debt, not authorization. Local code-level validation alone cannot establish registered VPS, deployment or security approval.
