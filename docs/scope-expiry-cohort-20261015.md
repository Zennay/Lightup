# Offline authorization expiry-cohort review (2026-10-15)

**LightUp: INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.** This is an optional **non-authorizing report of untrusted claims**, not a grant, consent, scan preflight, execution permit, installation guide or release gate. It complements open time-window issue #347 without satisfying its producer acceptance or altering another worker's source.

## Problem

A scope reviewer needs an **aggregate, privacy-minimal view** of time-window metadata without reading client identifiers, exposing authorized assets or quietly treating a parseable date as customer permission. Existing source-owner grant issuance and executor PRs own actual runtime authorization and revocation. Their work must not be bypassed by a standalone report.

## Added self-owned files

- `scripts/review_scope_expiry_cohort_20261015_offline.py` — independent, pure-stdlib, stdin-only CLI.
- `tests/test_scope_expiry_cohort_20261015_offline.py` — real subprocess and direct unit regressions.
- This document.

No production imports, router wiring, SDK calls, network requests, persistent reads/writes, grant creation, grant mutation, scanning, runner/workflow edits, or changes to existing files.

## Strict input

Send UTF-8 JSON (maximum **16 KiB**) on stdin, without CLI flags. The only accepted shape is:

```json
{
  "as_of_utc": "2026-10-15T12:00:00Z",
  "horizon_hours": 24,
  "windows": [
    {"valid_from": "2026-10-14T12:00:00Z",
     "valid_until": "2026-10-16T12:00:00Z"}
  ]
}
```

- Exactly three top-level fields; no unknown properties or identifiers anywhere.
- 1–32 anonymous windows; only two datetime fields each; no client, hostname, asset, engagement, risk, tool, approval or secret accepted.
- Literal built-in JSON integer for horizon, 1–720 hours; no booleans, negative-zero, float/exponent aliases, five-digit oversized integers, duplicates or nonfinite constants.
- All dates are exact ASCII UTC `YYYY-MM-DDTHH:MM:SSZ`; reject Unicode digit lookalikes, offsets, noncanonical parsing, 24:00 rollover, invalid calendar dates, and empty/inverted periods. This avoids Python-version-dependent normalization.
- `as_of_utc` is a **user-supplied preview instant**, not evidence of an authenticated system clock.
- Any malformed member causes **atomic HOLD**; never show a partial healthy count.

## Bounded local-stream admission (W4)

The command reads **fd0 only**, never an input path or network address. It admits
an ordinary local regular file or anonymous/named pipe, not a Unix/TCP socket,
TTY, device node, or directory. It sets **nonblocking fd0**, reads at most
16 KiB plus one sentinel byte, and waits for **complete EOF within two seconds**
of its local monotonic clock. The prior implementation could wait indefinitely
for EOF even after receiving otherwise perfectly valid JSON; that is now an
atomic, generic `HOLD` exit 2. After both success and failure it restores fd0's
original blocking mode.

The input clock is a resource bound, not evidence that the supplied
`as_of_utc` is authentic. Do not pipe untrusted network connections or live
customer data into this preview. A real process-level watchdog/OS sandbox and
independently trusted consent remain out of scope. Actual subprocess
regressions cover a writer that keeps the pipe open, rejected Unix socket
stdin, and an accepted local temporary-file fd0 control. No external
connections or scans occur.

## Complete snapshot and FD-identity preflight (W8)

A regular-file packet must start at **byte offset zero** and have a declared
file size of **1–16 KiB** before any parsing. After actual EOF, the checker
compares read-byte count, resulting offset, original/final size and original/
final mtime/ctime to detect truncation, appends or concurrent file mutation.
This prevents a seeked input from being treated as a complete consent record.
For both local regular-file and pipe intake, the descriptor device/inode/type
must remain unchanged across reads and at EOF; output also rechecks its
descriptor identity immediately before the single bounded receipt write.
Any mismatch causes **HOLD** or a failed receipt, never a permit.

Subprocess canaries cover seeked inputs and empty/oversized regular files.
Isolated deterministic fstat mocks check a simulated modified file, switched
input identity and switched output identity (no write permitted). These are
**best-effort userland consistency checks, not a kernel-locked snapshot or
proof of source authenticity**. External provenance, live revocation and
customer permissions still require a separate trusted enforcement layer.

## Bounded and private local output (W5)

The CLI emits a **single ASCII JSON line of at most 512 bytes** by one
nonblocking `os.write` to fd1. Only a **local pipe or actual TTY** is eligible:
regular files, Unix/TCP sockets, and non-terminal device nodes are refused
without creating a receipt. A pipe with no reader or a saturated pipe must not
hang, retry a partial message, or print a Python traceback. The CLI restores
fd1's original blocking setting even after output errors and always exits
nonzero. If delivery fails, it returns exit 2; absence of a receipt **must
never** be interpreted as permission or as an approved result.

This deliberate restriction means `> out.json` redirection is not supported
for the opt-in preview; use a local pipe consumer if a receipt is needed. These
are userland fail-closed precautions, not an OS-level isolation guarantee.
The dedicated real subprocess tests exercise discarded file/socket sinks,
closed readers and an actually filled local pipe. A further real inherited-FD
control keeps the parent ends open and checks that **both fd0 and fd1 original
blocking modes are restored** after an accepted review and after malformed
JSON HOLD. Descriptor-mode restoration is a correctness property, not trusted
provenance or a substitute for OS isolation. No scan, real grant or
outbound network call is performed.

## Result contract

A structurally valid packet prints exactly one opaque JSON line and exits **3**, `REVIEW_ONLY`. Counts are mutually exclusive: `expired` (after inclusive end), `not_yet_started` (before start), `current_expiring_within_horizon`, and `current_later`. A malformed packet prints generic `HOLD`, exits **2** and reports **no counts**. Both results carry *six literal false bits*:

```json
{"authorization_verified":false,"permit_issued":false,"dispatch_enabled":false,"merge_approved":false,"deploy_approved":false,"release_approved":false}
```

No zero exit is possible for a normal input. No input values, timestamps, paths, client identifiers, or raw JSON snippets are echoed; even REVIEW_ONLY cannot show which anonymous row contributed to a count. A REVIEW_ONLY aggregation is not evidence of persisted, authentic, approved, current or non-revoked authorization.

## Pinned stdin object — read/EOF descriptor replacement safety (W12)

Like stdout, a successful fd0 `fstat()` is not a durable reservation:
another local thread can replace fd0 after validation. Input now duplicates
the verified open-file description and reads exclusively from that **pinned**
descriptor, rather than calling `os.read(0, ...)`. It checks both the
original and pinned descriptor device/inode/type before each read and again
at EOF. File-size, mtime/ctime and offset checks apply to the pinned regular
file; FIFO readers keep the same two-second bounded EOF policy. The pinned
descriptor is closed in `finally` even on invalid input, and its
blocking state is restored before closure.

Tests demonstrate a simulated original fd0 rebinding denies the packet
before read; a different pin is rejected and closed; two additional
mid-stream and EOF fd0 replacements must reject an already-partially-read
or apparently complete packet without accepting any counts;
the only descriptors handed to select/read are the pinned fd; and a
changed regular-file mtime produces HOLD with resource cleanup.
This protects against redirected bytes *after* an identity check but cannot
prove that the original sender or its content was trusted; no scan
authorization or runtime grant is created.

## Pinned stdout object — descriptor replacement safety (W11)

In addition, **stdout eligibility and pinned-object identity now share
the same single `fstat(1)` snapshot**. Previously an eligibility check
could observe a FIFO, then a *second* `fstat(1)` could observe a newly
substituted socket; using that second result for pin comparison would
wrongly carry FIFO admission onto the socket. The first checked metadata
object is now the reference identity throughout pinning. Dedicated
negative controls simulate FIFO→socket replacement and a socket as
the very first snapshot; both refuse any receipt.

A call to `fstat(1)` does **not** reserve file descriptor 1: another
thread can replace it with `dup2()` between verification and
`os.write(1, ...)`. The offline CLI now obtains a duplicate of the
previously inspected stdout pipe/TTY descriptor, verifies that the duplicate
and live fd1 refer to the expected device/inode/type, and sends **one
nonblocking bounded receipt through the duplicate, never raw fd1**.
Blocking-mode restoration and closing of the pinned duplicate happen in
nested `finally` handlers, even on a broken pipe. A changed live fd1
before the write causes no receipt.

Synthetic negative/positive tests pin the exact descriptor used to
write, refuse an identity mismatch before dispatch, and ensure a broken
pipe still restores blocking mode and closes the duplicate. Actual
subprocess pipe tests from W5–W7 remain in force. This narrows an
output-descriptor rebind race **without authenticating a receiver**:
a valid pipe may still have an untrusted reader, so real client metadata,
consent and permits remain outside this preview.

## Fixed-schema, deny-only receipt gate (W9)

Before **any** output descriptor can be written, the reviewer independently
revalidates the complete resulting JSON object. `HOLD` can contain only the
literal status and six literal `false` authority flags, **no counts**.
`REVIEW_ONLY` can contain only four nonnegative built-in integer counts with
a coherent total of **1–32**, plus exactly those same six false flags.
Unknown statuses (`PASS`, `APPROVED`), unexpected target/client keys, boolean
count aliases, noninteger/negative/unbounded counts, or any flag that is not
**literally False** produce no receipt and exit 2.

Dedicated controls try forged `approved` shapes, client names, all six
false-flag substitutions and 32-window counting. This gate limits accidental
metadata disclosure; it does **not** authenticate data or produce permission.
As before, a missing receipt must never be interpreted as success.

## Verification

```sh
python -m unittest discover -s tests -p 'test_scope_expiry_cohort_20261015_offline.py' -v
```

Use fictional windows only. Tests include real CLI invocation, 16 KiB bound, strict JSON shape, duplicate keys, wrong types, 24:00 rollover, Unicode decimal disguises, inclusive temporal boundaries and no authority flags. They do not initiate target traffic.

## Real model semantic parity and extreme-time controls

The follow-on acceptance suite exercises **126 synthetic, in-memory `AuthorizationGrant.is_current(now=...)` comparisons** against the CLI's four mutually exclusive categories. It checks current/noncurrent parity, future and expired boundaries for 6 start offsets × 3 durations × 7 evaluation instants. These are fictional model instances, not stored grants or operator approvals. A complete 32-window cohort has an actual positive-count subprocess control and a corrupted final member must cause atomic HOLD with **no partial counts**. A UTC value at 9999-12-31 23:59:58 with a 720-hour horizon explicitly guards against `datetime + timedelta` overflow: the reviewer instead computes the duration `end - as_of`.

A further adversarial real-subprocess test passes a 3,001-byte deeply nested JSON array that would otherwise raise Python's recursion guard. It must return exactly one generic HOLD JSON receipt (exit 2) and no stderr or traceback. A distinct invalid UTF-8 byte fixture proves the same privacy-preserving denial for decode failures. Neither can leak raw input or grant execution.

All these checks test *classification only*. The producer model's inclusive end semantics are preserved solely for this anonymous report; nothing is wired into the real authorization path. Every output remains non-authorizing.

## Timezone-independent UTC boundaries (W10)

A real subprocess acceptance matrix runs fixed fictional grants at the 2026
UK spring and autumn daylight-saving changes across four different host
`TZ` settings (`UTC`, `Europe/London`, `Pacific/Kiritimati` and
`America/New_York`). Identical UTC input bytes must produce **byte-for-byte
identical**, strictly false-authority receipts with no traceback and no
reclassification of expiry windows. This tests deterministic presentation
only: a caller's supplied `as_of_utc` is **not** a trusted clock or
evidence of live customer consent.

## Anonymous temporal consistency and calendar boundaries (W15)

A deterministic **150-receipt, 4,800-window classification matrix** runs a full
32-window fictional cohort at 30 increasing UTC instants against five
horizons (1, 6, 24, 72, and 720 hours). Every aggregate is compared against
an independently assembled Python UTC-datetime oracle and rechecked for six
literal false-authority bits. The test also asserts that as review time
advances, the expired cohort cannot shrink and the future cohort cannot grow;
increasing a horizon must not move rows from expiring-soon into later or change
the expired/future counts. Reverse-order permutations of the same anonymous
windows must yield byte-equivalent fields, without row identifiers or
per-target disclosure. These are *coherence invariants of synthetic
untrusted claims only*; no real grant is created or validated.

A second edge suite covers UTC year 0001, Gregorian leap day 2000/2024,
year 9999 overflow boundaries, and rejection of non-leap-year century
dates (1900/2100), year 0000 and 24:00 rollover. None of these time
fields is authenticated or used to permit active scanning.

## Installed runtime import isolation (W14)

The new acceptance test scans only installed Python source under
`src/lightup/**/*.py` to ensure no literal reference to this
`review_scope_expiry_cohort_20261015_offline` prototype appears in
production. This is a narrow, fail-closed source-import tripwire: it
prevents accidental ordinary wiring of the synthetic classifier into
live authorization while producer-owned grant and destination gates
are unresolved. It cannot prove absence of computed/dynamic imports,
plugin metadata or external callers; independent source-owner security
review remains necessary. An intentional future product integration
must independently justify and revise this test after full human
authorization, rather than silently promoting `REVIEW_ONLY`.

## Required independent source-owner handoff

Real-world authorization still requires: independently authenticated customer/operator consent; original request–grant FK and exact tenant/scope matching; revocation and time validity checked from trusted storage immediately before **each** dispatch; canonical DNS/network destination binding; separate destructive-lab human step-up; branch/run/runner attestation; independent security and privacy review and explicit human release. This reviewer is neither a substitute nor a prerequisite for those gates.

**Do not merge/deploy/activate just because these isolated tests are green.** Keep this PR in DRAFT/HOLD until source-owner collision review and an exact immutable-head hosted **and** registered permanent VPS test plus human approval.
