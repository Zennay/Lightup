# #931 — canonical passive-prospect identity (owner-source RED acceptance)

**Status:** INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD · non-authorizing.
**Pinned original source owner:** draft [#175](https://github.com/Zennay/Lightup/pull/175) at immutable `df9eac879bbe232cd1e50fd6e9dfe12ff38f8469`.
**Issue:** [#931](https://github.com/Zennay/Lightup/issues/931).
**New isolated test:** `tests/test_scope_931_profile_identity_owner_red_20261016.py`.
All names, sources and signals are fictional and remain entirely in process. No DNS,
network I/O, external target, customer record, grant, scan, or handler invocation.

## Gap / installed-source witness

Owner-source `ProspectProfile` is a mutable dataclass with ordinary annotated
`prospect_id` and `organization_name` fields. Python dataclass type annotations
do not validate runtime inputs. On this exact head, `ProspectProfile(None, ...)`,
`ProspectProfile("", ...)`, etc. currently construct an object. A passive,
public-only signal can then be attached to an ambiguously identified profile.
Existing correct `ProspectSignal.public_source` and
`requires_target_interaction` boolean gates **do not** validate profile identity.

## Contract and acceptance evidence

- Four ordinary installed-source PASS checks: exact string identity preserved,
  passive canonical signal admitted, nonpublic/interactive/type-confused signal
  rejected without append, and profile identity creates no target permit.
- Sixteen deliberately `@expectedFailure` **OPEN SOURCE RED** checks:
  null, numeric, bool, bytes, subclass, blank, whitespace identities for the prospect;
  corresponding organization cases; object with coercion hooks; and
  malformed profile rejected *before* constructor signal admission.
- One strict independent replay oracle asserts **all 16 real expected failures**,
  no skips/errors/unexpected successes. When the source owner fixes the bug, it
  intentionally fails rather than silently treating an unexpected pass as safety.
- This test does not assert a production fix, release permission, approval, or
  authentication/authorization. Hosted test success with expected REDs is not a
  green security posture.

## Source-owner repair handoff (NOT implemented here)

The only production owner is PR #175 / `src/lightup/discovery.py`; do not alter
their source or branch from this child. They should validate with exact built-in
`type(value) is str` and nonempty `value.strip()` on **both** identity fields
before accepting a profile or its initial signals, without trimming, normalizing
or evaluating polymorphic caller hooks. Prefer `ValueError` for malformed text
and preserve canonical strings byte-for-byte. Keep `ProspectSignal` exact-bool
fail-closed behavior; do not widen public/prospect admission. Independently
review whether identity can mutate after construction (#929), then enforce
identity validity at any relevant mutation/admission boundary.

After source correction, intentionally RED tests must be converted to ordinary
PASS assertions *in a source-owner reviewed change* and accompanied by a strict
latest-head CI matrix. A successful isolated child does not merge the owner fix.

## Required external gates

1. Independently reviewed owner-source #175 fix and #929 immutability composition.
2. Full hosted Python 3.11/3.14 and genuine permanently registered self-hosted
   VPS CI on the **exact final SHA**. Queued jobs do not count as evidence.
3. Security/privacy and legal permission review, explicit human release.
4. No real target access without actual client authority, current scope,
   revocation checks, separate operator permission and appropriate risk gate.

**NO MERGE / DEPLOY / REAL GRANTS / TARGET SCANS / ACTIVE SECURITY ACTIONS.**

## W3 — standalone synthetic-only intake review (uninstalled)

New **`scripts/scope_931_synthetic_identity_intake_20261016.py`** is a
*standalone offline diagnostic*, with companion
`tests/test_scope_931_synthetic_identity_intake_20261016.py`.
It does not import or alter `lightup`, instantiate a client grant, contact any
target, call DNS/network, inspect customer files or wire itself into admission.
Invoking it is **not** customer consent or permission to run an assessment.

Usage on **fictional JSON only**, through standard input:

```sh
printf '%s' '{"prospect_id":"fictional-id","organization_name":"Fiction Corp"}' |
  python scripts/scope_931_synthetic_identity_intake_20261016.py --offline-synthetic-only
```

The diagnostic consumes at most 4,097 bytes (4,096 byte accepted ceiling),\nand now requires a complete EOF within a monotonic two-second deadline\nfor local Linux stdin pipes; an unclosed full/partial stream yields HOLD,
strict JSON and exactly two keys, rejecting duplicate keys, non-UTF-8,
nonfinite JSON constants, malformed types, blank text, decoded control,
zero-width/bidi format characters, and overlong identity fields (128/256
codepoints). It intentionally **does not normalize identity strings**:
surrounding padding is retained but not printed, and Unicode letters may
receive syntactic `REVIEW_ONLY`. This is **shape review only**, never proof
that a human gave authorization or that a claimed organization is genuine.
Synthetic/non-synthetic provenance cannot be established from this JSON.

Every command and error path returns **nonzero** (2 for `HOLD`, 3 for
`REVIEW_ONLY`), with an opaque constant-shape JSON receipt. The six
`authorization`, `permit`, `dispatch`, `scan`, `deploy`, `release`
fields are always literal `false`; no input identity, source, exception or
argument is emitted. There is no success/GO result. The ordinary current
`ProspectProfile` implementation is unchanged and remains deficient.

Companion real subprocess tests exercise correct and corrupted JSON, duplicate
decoded keys, raw invalid UTF-8, types, whitespace, Unicode control/bidi,
bounded payloads, a real fragmented input stream and an intentionally\nnever-closed pipe, flag rejection, fixed confidentiality-preserving receipt,
canonical/noncanonical objects and deterministic key-order metamorphic cases.
These are **additional green tests**, not source remediation; do not
promote an offline review-only status into product release evidence.

**W3 exact-HEAD CI is required separately from the W2 520+86 logs.**

## W4 input completion contract

The opt-in diagnostic now uses a **monotonic 2-second EOF deadline** with
`select.select` and `os.read` rather than waiting forever for stdin to close.
A complete document on a pipe with no EOF also returns only HOLD; fragmented
valid JSON gets REVIEW_ONLY only **after** the last byte and actual EOF.
Two independent real subprocess regressions cover both cases. This is
Linux/Unix-local offline tooling; it does not guarantee a hostile OS can't
suspend the process, is not a network isolation sandbox, and is never permission
or a release signal. Exact latest SHA CI must be checked separately.

## W5 — local file-descriptor containment (still not an OS sandbox)

The offline checker now insists that **stdin is a local anonymous-pipe-shaped
FIFO** and **stdout is a distinct local pipe or a genuine TTY**. It refuses
regular files, Unix sockets, character devices and an input/output pipe with
the same device/inode *before reading any input*. When no safe output sink
exists, the command exits `2` with **no receipt bytes**; a forged
REVIEW_ONLY verdict cannot be written into a regular file or a socket.
A full output pipe is checked for nonblocking writability, returning exit `2`
rather than hanging when no output space is available. Normal dedicated
stdout pipes still emit the fixed generic receipt and six `false` flags.

The new real subprocess cases use disposable local temporary files, AF_UNIX
socketpairs, and anonymous pipes only. They establish that no source file is
read, no file/socket output is written, an aliased input/output pipe is refused,
and a full destination does not hang. No external network, customer files,
target, authorization grant or scanner is involved. These are **best-effort
local Unix diagnostics**, not a portable security boundary, immutable file
descriptor guarantee, secure sandbox or permission to scan. Full CI must be
reconfirmed on this exact W5 head; prior hosted checks are older-SHA evidence.

## W6 — Unicode scalar/alias-safe offline review, no owner-source changes

The standalone opt-in synthetic-only reviewer now accepts exact built-in
`str` identities for shape review **only if NFC is already satisfied**.
It deliberately **does not normalize** non-NFC text or claim an equivalent
string denotes the same client/asset/prospect. Characters in Unicode
categories `Cc/Cf/Cs/Zl/Zp` and all designated noncharacters (U+FDD0..FDEF
and every plane's terminal U+FFFE/U+FFFF) are `HOLD`.
A valid precomposed accented name remains `REVIEW_ONLY` (never a grant).
This stricter synthetic-only preflight is conservative: legitimate names with
decomposed characters may be sent for manual review rather than rewritten.

Five additional real subprocess tests compare NFC vs NFD, noncharacters in
both fields including supplementary planes encoded as JSON surrogates,
line/paragraph separators, nested duplicate or concatenated JSON objects,
and exactly the 4096-byte body boundary. These are privacy-preserving
negative acceptance checks; not an authoritative organization verification,
not a fix to installed `ProspectProfile` owner source, and not new permission.

**Trust boundary:** `REVIEW_ONLY` means purely parsed local synthetic
text. It cannot establish that an organization exists, belongs to the caller,
or has authorized a security assessment. No content from this CLI should be
fed into an execution permit, automation or client record. Existing 16
expected owner-source RED cases remain unremediated. Hosted and permanent
VPS evidence must use the immutable newest HEAD separately.

## W7 — static regressions blocking accidental privilege/capability drift

Two additional independent `unittest` cases inspect the *actual owned offline
CLI source* using Python's `ast` parser, without running real targets. They
pin an exact safe standard-library import allowlist and fail the test suite if
future edits add a new import, wildcard, production `lightup` coupling,
network/command libraries, dynamic `open/exec/eval/__import__` calls, or
unexpected `os` and `sys` attributes. This makes a dangerous widening of the
standalone tool an explicit review event before CI can be called green.

These source-level tripwires are deliberately narrow and conservative: they
**do not** prove impossibility of file/network activity in Python, make the OS
a secure sandbox, verify a client, or authorize a scan. They are paired with
real subprocess behavior tests and isolated owner-source expected REDs. The
production `src/lightup` owner and runner/CI workflows are unchanged.

## W8 — Linux procfs pipe provenance; named FIFO is not anonymous

W5 previously checked `stat.S_ISFIFO` and described it as an anonymous
pipe; this was **too strong**, since a filesystem-named FIFO has the same
POSIX mode. The latest standalone tool now separately reads
`/proc/self/fd/0` and `/proc/self/fd/1` (Linux-only) and requires the
kernel's exact `pipe:[inode]` descriptor identity to match `fstat` on
**each** end. Both ends must be distinct verified anonymous pipes.
Named FIFOs, pseudo-terminals and any environment without readable procfs
are fail-closed, with no input read and no output receipt; no fallback to
just `S_ISFIFO`. A valid review still has nonzero exit and six literal
false authorization flags.

Four additional tests use real disposable local FIFOs, a pseudoterminal
and a simulated unavailable procfs lookup. These are non-network,
non-target, non-production OS boundary cases, and do not create grants.
The source changes remain wholly in this child: no shared admission/
CI/workflows/VPS/other-worker edits. This is a local Linux tool policy,
not proof that procfs is tamper-proof, a container sandbox, or that an
identity is real or authorized. The production source gap #931 and
identity-rebinding #929 need source-owner remediation.

### W8 exact-source CI finding and correction

On the first W8 GitHub-hosted Python 3.11 run, the genuinely simulated
missing procfs entry caused `_anonymous_pipe` itself to raise `OSError`
instead of returning `False`. The surrounding CLI main was already
fail-closed, but the inspector's direct contract was too brittle, so this
was a **real test failure** and must not be called green. The private
inspector now catches OSError/type/overflow/value anomalies and returns
`False` without logging or echo. An additional real anonymous-pipe
regression feeds forged `pipe:[inode]` spellings and a mismatched inode
against `fstat`, requiring denial; only an exact matching synthetic
kernel-link format is accepted. The latest W8 commit requires complete
immutable-head hosted 3.11/3.14 and separately permanent VPS evidence.
