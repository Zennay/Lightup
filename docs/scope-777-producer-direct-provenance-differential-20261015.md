# Issue #777 · Synthetic producer/direct provenance differential

**LightUp posture: INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.** This is an independent, add-only acceptance artifact; it does not alter `src/lightup/**`, branch `chatgpt/scope-authorization-direct-grant-approval-provenance-red-20261007`, production authority, workflow configuration, or any other worker's PR.

## W10: prove provenance narrowing cannot weaken other authorization gates (2026-10-15)

**New observed risk in the test-only strict gate:** the W9 runner originally
checked 14 malformed provenance variants and one legitimate grant only.
A defective "fix" that rejects all 14 bad provenance values but
simultaneously allows expired or out-of-scope assets would incorrectly
pass the old gate. W10 closes this **gate integrity** hole without
touching application source or another worker's PR.

- Extend the actual-source-backed
  `scripts/scope_777_strict_direct_policy_gate.py` with **11 independent
  forbidden-decision controls**: missing grant, expired grant, future
  grant, wrong asset, explicitly excluded asset, unapproved capability,
  over-risk grant, destructive lab-only risk, lab mode without a lab
  target, analysis with active risk, and passive with active risk.
  A valid analysis-only request must also continue to be allowed.
  All scenarios use synthetic `example.test` and no network/handlers.
- The test-only receipt now reports `negative_controls_examined` and
  `negative_controls_allowed`. It can produce `TEST_ONLY_PASS` only
  if the canonical request is allowed, **all 14 noncanonical grants are
  denied, all 11 independent negative guards deny, and the legitimate
  analysis-only control remains allowed**. It never elevates any of
  six literal false authority/release flags.
- Reject `ExecutionPolicy` side effects and noncanonical return types.
  The initial shallow request/grant snapshots missed changes to the
  nested `ScopeDefinition` object, so W10 adds an independent
  `deepcopy(request)` invariant. Two real regressions simulate
  mutation of scope assets and allowed capabilities; both now fail
  closed. Shallow snapshots remain to detect structural field changes.
- Extend
  `tests/test_scope_777_strict_gate_20261015.py` to **14 methods**:
  all 11 negative boundaries are individually mutation-tested with
  a test-only policy that correctly denies the 14 provenance faults
  but falsely grants **one** distinct boundary. Every resulting
  runner receipt is HOLD, with `invalid_allowed=0` and
  `negative_controls_allowed=1`. Additional ordinary green
  controls cover accidentally disabling valid analysis, nested scope
  mutation on allow and deny, request/grant mutation, and PolicyDecision
  subclass/non-boolean response spoofing.

**Actual isolated Python 3.13.5 execution:** `PYTHONHASHSEED=random
PYTHONPATH=src python -m unittest discover -s tests -p
'test_scope_777_*_20261015.py' -q` completed **80 tests, 0 unexpected
errors, 14 intentionally expected-RED provenance defects**.
`python -m compileall -q scripts tests src` succeeded. Running
`PYTHONPATH=src python scripts/scope_777_strict_direct_policy_gate.py`
against the original current-main policy still returns **exit 2**:
`{"status":"HOLD","invalid_examined":14,"invalid_allowed":14,
"negative_controls_examined":11,"negative_controls_allowed":0,...}`.
Exact GitHub copies of updated strict script and test file match locally
executed files by Unicode character count and diagnostic FNV checksum.

**Caveats:** this validates the test-only strict gate against the
isolated current-main `engagements.py` and `execution_policy.py`, not
the whole deployed product. The separate real-SQLite DomainStore suite,
hosted Python 3.11/3.14 CI and permanently registered VPS CI are still
unrun on this branch. The actual #777 production bypass remains
**14 expected failures / open** until the PR #100 source owner
changes `ExecutionPolicy.decide` and validates all gates on the
integrated immutable SHA. Keep **INCUBATE, BRANCH-ONLY, DRAFT/HOLD**;
no PR/merge/deploy/real grant/network scan/target contact.

## W9: strict production-policy RED gate (2026-10-15)

To eliminate ambiguity from `@expectedFailure` turning unresolved security
defects into an overall successful test command, this isolated branch now
contains a **separately runnable strict exit-code gate**:

- [`scripts/scope_777_strict_direct_policy_gate.py`](https://github.com/Zennay/Lightup/blob/chatgpt/scope-777-producer-direct-differential-20261015-0356/scripts/scope_777_strict_direct_policy_gate.py)
  imports the **real installed `lightup.execution_policy` and
  `lightup.engagements` models** from the current checkout, creates a
  fictional, non-network `example.test` grant, verifies the canonical
  control is allowed, then checks exactly fourteen invalid direct-provenance
  variants. The test-only runner **returns process exit 2** with
  `"status":"HOLD"` when any invalid grant is incorrectly allowed, when a
  policy decision is malformed or mutates its input, or when an error occurs.
  A fully repaired source instead gives `"status":"TEST_ONLY_PASS"`
  and exit 0. **Both receipts always include six literal false
  authorization/permit/dispatch/merge/deploy/release flags.** A gate success
  is *only a unit-test outcome*, never a real release/target authorization.
- [`tests/test_scope_777_strict_gate_20261015.py`](https://github.com/Zennay/Lightup/blob/chatgpt/scope-777-producer-direct-differential-20261015-0356/tests/test_scope_777_strict_gate_20261015.py)
  adds three ordinary passing tests: real subprocess exit/receipt privacy;
  temporary in-test-only `ExecutionPolicy.decide` narrowing making all 14
  invalid cases denied; and no-authority receipt integrity. No production
  policy patch or workflow configuration has been changed.

**Actual current-main observation** with exact copied `main` source SHA/blob
evidence listed in W8:

```bash
PYTHONPATH=src python scripts/scope_777_strict_direct_policy_gate.py
# {"...","invalid_allowed":14,"invalid_examined":14,"status":"HOLD"}
# Process exit 2. This is an expected security problem, not a green gate.
```

In the locally executed test-only narrowed policy preview, the strict gate
instead counted `invalid_allowed=0` and `TEST_ONLY_PASS` with six false
authority flags.

**Final W9 local verification**: `PYTHONPATH=src python -m unittest
discover -s tests -p 'test_scope_777_*_20261015.py' -q` ran **69 tests,
zero unexpected errors, fourteen expected failures**. `compileall`
completed. Breakdown: 41 offline-reviewer tests, 19 unpatched main policy
tests (5 normal passing controls + 14 expected security failures), 6
test-only preview tests and 3 strict-gate tests. The separate SQLite/real
`DomainStore` differential remains unexecuted locally due to missing full
repo dependency tree. Python 3.13 local isolated proof is **not** hosted
Python 3.11/3.14 or registered permanent VPS CI on this branch.

**Source-owner closure action:** make the strict gate exit **0 with
`invalid_allowed=0`** against the real integrated `ExecutionPolicy`, and
convert all 14 expected-RED acceptance controls into ordinary passing
denials. Preserve canonical ALLOW and missing/expired/out-of-scope DENY.
Then perform exact-head hosted+permanent VPS, durable consent/request lineage,
revocation, verified destination, independent security/privacy and human
release review. Until then **BRANCH-ONLY DRAFT/HOLD**; no PR, merge, deploy,
real grant, scan, handler or target contact.

## W8: actual unpatched main policy RED witness and pure fix proof (2026-10-15)

**This is now an observed runtime defect, not only a static hypothesis.**

The exact contents of two current GitHub `main` files were independently
retrieved and locally reconstituted with matching character count and
deterministic FNV32 codepoint checksum:

| Actual source | GitHub blob SHA | Characters | FNV32 |
| --- | --- | ---: | --- |
| `src/lightup/engagements.py` | `2271582fe4013be23041416d5cedd35105004ccd` | 2,418 | `b54cbb04` |
| `src/lightup/execution_policy.py` | `6fd14b09242ea5ffcf4c581f216679fbd02c00be` | 2,673 | `54244a85` |

A disposable local package consisting of these **unaltered actual mainline
modules** (not a mocked policy) ran two newly committed add-only acceptance
files. All identifiers and the sole target string `example.test` are
fictional; `ExecutionPolicy.decide` has no executor, network, SQLite
backend, handler, or scan contact in this test.

- [`test_scope_777_exact_main_policy_direct_20261015.py`](https://github.com/Zennay/Lightup/blob/chatgpt/scope-777-producer-direct-differential-20261015-0356/tests/test_scope_777_exact_main_policy_direct_20261015.py):
  19 `unittest` methods. **5 ordinary controls PASS** (canonical allowed,
  missing grant/expired/outside scope denied, typed no-write behavior).
  **14 expected failures reproduced** because the real unpatched
  `ExecutionPolicy` incorrectly ALLOWS all 14 noncanonical
  `approved_by/reference` variants (blank, whitespace, padded, subclass,
  bytes/int/None and Unicode padded). These 14 xfails are **open security
  debt, not successful security assertions**.
- [`test_scope_777_pure_fix_preview_20261015.py`](https://github.com/Zennay/Lightup/blob/chatgpt/scope-777-producer-direct-differential-20261015-0356/tests/test_scope_777_pure_fix_preview_20261015.py):
  6 actual green tests for a local `_preview_narrowed_decide` wrapper. It
  rejects **14/14** invalid direct grants, never widens legitimate
  active authorization, still rejects expired/out-of-scope/missing grants,
  leaves passive decisions unchanged and does not mutate inputs. The
  helper is **defined within a test**, not installed or hooked into
  product/production.

A separate explicit baseline-vs-preview Python run counted
`{"tested_invalid_cases": 14, "unpatched_policy_incorrect_allows": 14,
"test_only_preview_incorrect_allows": 0, "valid_canonical_allowed": true}`.

**Combined executed proof:** local Python 3.13.5
`PYTHONPATH=src python -m unittest discover -s tests -p
'test_scope_777_*_20261015.py' -q` returned **66 methods, zero unexpected
errors, 14 expected failures** (41 standalone reviewer controls + 19 real
policy baseline controls + 6 pure fix-preview controls). Python `compileall`
passed. The previously isolated 18-test **DomainStore SQLite** differential
was **not** executed: the full repository and its database dependencies
were not available in this local checkout. No GitHub-hosted or permanent
self-hosted/VPS CI has been run for this branch.

**Source-owner action:** preserve the existing production ownership in PR
#100. Move the proven pure exact-string canonicality condition into the real
`ExecutionPolicy` TARGET_ACTIVE path ahead of `grant.is_current()`,
conduct canonical `str` and trimmed nonempty checks for both fields, then
remove all fourteen `expectedFailure` decorators **only after** those
regressions pass normally on the integrated exact SHA. Re-run actual
SQLite producer roundtrip, external/persisted grant lineage, consent,
revocation and destination proofs. Neither this reference wrapper nor an
offline `REVIEW_ONLY` receipt constitutes real customer authorization.
**Keep branch-only, DRAFT/HOLD; no PR, merge, deployment, real grants or scans.**

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


## W6: canonical Unicode and uniform CLI privacy (2026-10-15)

The offline-only *review* CLI now refuses noncanonical Unicode approval
provenance even when JSON syntax is otherwise valid. In particular:

- Both provenance fields must already be Unicode **NFKC**: decomposed
  accented forms, fullwidth characters, ligatures, circled letters/numerals
  and compatibility substitutions cannot silently receive REVIEW_ONLY.
- All Unicode control/format/private-use/unassigned categories are refused;
  Unicode separators except ordinary ASCII space and the otherwise invisible
  combining grapheme joiner U+034F are refused as well.
- Canonical precomposed human names (for example José), ASCII internal
  spaces, and exactly 128 UTF-8 byte provenance fields still receive
  REVIEW_ONLY; a 129-byte field receives HOLD.

These are **lexical presentation safeguards only**; even REVIEW_ONLY has
six literal false authority flags and exit 3, not consent.

**Real local proof**: Python 3.13.5, `python -m compileall -q scripts tests`,
and `python -m unittest discover -s tests -p
'test_scope_777_offline_provenance_review_20261015.py' -q` completed with
**35/35 tests OK**, including positive canonical Unicode, compatibility and
invisible-character controls and fourteen independent real subprocess
malformed/secret-bearing payloads. All fourteen produced an exactly identical
HOLD output, empty stderr, exit 2 and no echoed confidential-looking values.
The current GitHub script/test files were independently fetched and compared
byte-for-byte at the Unicode character/codepoint level with the tested local
sources using length and a deterministic diagnostic checksum.

**Scope of evidence:** only this standalone Python 3.13 reference was
executed; not the full product SQLite integration, hosted Python 3.11/3.14,
permanent self-hosted runner, installed ingress or production release.
No workflows or PR were triggered; issue #777's branch-only HOLD ownership
is preserved.

## W7: reproduced visual spoof bypasses and tested source-owner handoff (2026-10-15)

On the isolated, uninstalled reviewer, the previous NFKC-only rule returned
`REVIEW_ONLY` for **U+FE0F variation selector, U+180B Mongolian selector,
U+20E3 enclosing keycap, and U+0338 combining overlay** inserted into a
fictional operator name. These were directly reproduced before repair. Their
NFKC spelling does not change, yet the printed string can be visually
misleading. W7 now denies these and related default-ignorable selector ranges
while continuing to review ordinary precomposed and script-required combining
marks, including Greek and Devanagari names.

A separate spoof class survives NFKC: mixing Latin letters with Cyrillic,
Greek or Armenian lookalikes. W7 conservatively rejects **mixed-script
letters among those four families within one field** while allowing
single-script international names. This is only a narrow lexical
anti-impersonation heuristic, **not** a general Unicode confusable algorithm,
proof of identity, or authenticated customer consent. Some legitimate
multilingual combined-script fields will receive HOLD; such reviews need a
separate human route, never a bypass.

**Executed local proof:** Python 3.13, 41/41 standard-library methods PASS,
including real subprocesses; exact source/test files were matched against
GitHub using code-point length and deterministic hashes.
The distinct SQLite-dependent 18-method producer/direct tests remain unrun
in this isolated sandbox and retain 14 expected-RED acceptance cases.

### Exact ownership-preserving production fix proposal for issue #777

The current `main` source `src/lightup/execution_policy.py` reaches
`grant.is_current()` after only checking `grant is None`. On the owner's
integrated PR #100 head, insert a **pure, fail-closed** check between those two
steps, before risk/scope/capability gates:

```python
if (type(grant.approved_by) is not str
        or not grant.approved_by.strip()
        or grant.approved_by != grant.approved_by.strip()
        or type(grant.reference) is not str
        or not grant.reference.strip()
        or grant.reference != grant.reference.strip()):
    return PolicyDecision(False, "authorization provenance is not canonical")
```

This is a **review proposal, not applied production code**. The source owner
must determine the integration point and verify ordering with PR #100,
persisted resolution, authentic consent, revocation and the activation gate.
Tests to certify *on the integrated exact head* are:

1. Every existing #777 direct policy RED case becomes an ordinary PASS
   asserting DENY: blank/whitespace/padded, Unicode-padded, `str`
   subclass, bytes/int/None for both provenance fields.
2. Canonical grant control remains ALLOW, *without* authorizing a real
   target; SQLite producer trims at issuance and persists the same canonical
   values.
3. Rejecting a malformed in-memory grant leaves both the grant snapshot
   and the durable store byte-for-byte unchanged; no handlers or target calls.
4. All pre-existing passive/analysis/lab-only tests retain behavior; no
   approval is implied by reviewer `REVIEW_ONLY` receipts.
5. Hosted exact-SHA Python 3.11/3.14 tests **and** independent, canonical
   registered permanent VPS proofs are required before any release review.

Do not modify this source-owner's file from the parallel reviewer lane.
Issue #777 stays open until real source integration and all mandatory
customer/operator-consent and destination/revoke gates pass.

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
