# Fictional scope-review packet copy integrity — #1503 (DRAFT/HOLD)

**LightUp posture: INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD. This is not an approval system.**

`src/lightup/fictional_packet_copy_1503.py` is an **unwired**, opt-in, pure Python-stdlib reviewer. Caller-supplied copies of an already-fictional review packet must be **identical canonical bytes** before a manual operator can mark the *copy* as unchanged. This is not the proposal widening/narrowing checker (#1501), operator notice generator (#1495), free-text privacy quarantine (#1497), or production policy evaluator.

## Exact schema and example

Canonical serialization is ASCII JSON, exact key order, no extraneous whitespace, escaped aliases, duplicate keys, unknown fields or trailing data, and at most **2048 bytes**. This example carries no author identity, real asset, real consent, signature, session, scan, URL or action:

```json
{"schema":"lightup-fictional-copy-v1","asset":"alpha.example.test","message":"REVIEW_REQUIRED","capabilities":["metadata_read","report_preview"],"authorized":false,"consent_verified":false,"dispatch_allowed":false,"release_allowed":false}
```

The `asset` must be a 1–32 character lowercase ASCII single label followed by literal `.example.test` (reserved fictional namespace); pseudo-IDNA prefixes `xn--`, doubled hyphens and trailing hyphens are disallowed. `capabilities` must contain 1–3 unique, lexicographically sorted values from `metadata_read`, `report_preview`, `scope_review`. `message` is only `REVIEW_REQUIRED` or `REVIEW_ON_HOLD`. All four authority flags must literally be JSON `false`.

## Offline use — canonical fictional packet creation and safe fanout

```python
from lightup.fictional_packet_copy_1503 import (
    build_fictional_copy_packet,
    compare_fictional_packet_copies,
    compare_fictional_packet_fanout,
)

source = build_fictional_copy_packet(
    "alpha.example.test",
    "REVIEW_REQUIRED",
    ("metadata_read", "report_preview"),
)
assert type(source) is bytes  # Fictional, not a customer record

pair = compare_fictional_packet_copies(source, source)
recipients = compare_fictional_packet_fanout(source, (source,) * 3)
assert pair.status == recipients.status == "REVIEW_ONLY"
assert recipients.authorized is False and recipients.dispatch_allowed is False
# Corruption of ANY recipient, even the last one, produces only generic HOLD.
assert compare_fictional_packet_fanout(source, (source, source, b"changed")).status == "HOLD"
```

The builder accepts **exact built-in str asset, exact built-in str message and exact built-in tuple of 1–3 sorted allowed str capability identifiers**, and returns `None` on any malformed/caller-subclass input. It hard-codes all four authority flags to JSON false and cannot accept identity, targets, proof, signing credentials or runtime mode. It is not intended for sensitive data.

Fanout accepts **1–16 exact built-in byte strings in an exact built-in tuple** and checks every copy against the same original strictly canonical bytes. There is no per-recipient status, content echo, metadata or partial digest on failure. This is *copy equality*, **not** sequential authorization proposal evolution (#1501). All copies are caller-controlled and neither pair nor fanout authenticates who authored or delivered the packet.

- Invalid or different copies: **HOLD**; digest is `None`; no caller text or partial metadata returned.
- Both exactly canonical and byte-identical: **REVIEW_ONLY** with a lowercase SHA256 fingerprint of the *fictional* bytes. A SHA256 digest alone is **not** signed provenance, tamper resistance against someone who controls both copies, client/operator consent, revocation, or release evidence.
- The immutable result always has `authorized=False`, `consent_verified=False`, `dispatch_allowed=False`, `release_allowed=False`.
- No production module imports or calls this helper. No paths, storage, network, DNS, SQLite, handlers or scans. No actual client assets should be supplied. The separate CLI emits only bounded non-authorizing HOLD/REVIEW_ONLY results.

## Reproducible checked-in fictional examples

- `docs/examples/fictional-copy-1503.json` is an **exact canonical no-newline** packet whose bytes the builder reproduces.
- `docs/examples/fictional-copy-changed-1503.json` is a different but still canonical **fictional** packet; comparing it to the first returns atomic generic `HOLD`. Both contain only reserved `.example.test` labels and four literal false authority flags.
- The dedicated hosted test suite reads both committed files as bytes and asserts identical encoding, expected builder equality and fail-closed end-to-end fanout behavior; edits to either example trigger that workflow. Neither file is a real consent record or scope grant.

## Offline CLI — safe terminal handoff, no release authority

`python -m lightup.fictional_packet_cli_1503` is an **explicit opt-in, stdin-only** wrapper over the same fictional-only parser and verifier. It does not open input paths, call networks, run tools, ask for credentials, or emit untrusted data. It reads **one ASCII JSON envelope, max 8,192 bytes**, with exactly these keys in exactly this order: `schema`, `original`, `copies`. `schema` must literally be `lightup-fictional-cli-v1`. `original` and `copies` are *JSON strings containing the original canonical fictional packet JSON bytes*, and `copies` must have 1–16 elements. The envelope itself must also be exact compact canonical ASCII JSON (no trailing newline, spaces, duplicate fields, escaped aliases, or byte-order mark).

To execute the **version-controlled fictional fixtures**:

```sh
PYTHONPATH=src python -m lightup.fictional_packet_cli_1503 < docs/examples/fictional-copy-cli-1503.json
# prints REVIEW_ONLY; shell exit 2, deliberately NOT successful authorization
PYTHONPATH=src python -m lightup.fictional_packet_cli_1503 < docs/examples/fictional-copy-cli-held-1503.json
# prints HOLD; shell exit 3
```

The **only** stdout is canonical, small ASCII JSON: `{"status":"HOLD","authorized":false,"consent_verified":false,"dispatch_allowed":false,"release_allowed":false}` (plus final newline) or `{"status":"REVIEW_ONLY","sha256":"...","authorized":false,"consent_verified":false,"dispatch_allowed":false,"release_allowed":false}` (plus newline). A SHA256 is generated only for identical, canonical, explicitly fictional bytes and is never provenance or consent. Exit code is **always nonzero**: 2 for REVIEW_ONLY and 3 for HOLD/input/pipe failures; never 0. The CLI accepts **no command-line arguments or mode flags** (including `--help`, `--approve` or file paths): any unexpected argument yields a generic HOLD. Missing binary streams, failed flushes, broken pipes and incomplete output writes fail closed with exit 3 rather than exposing partial review as success. CLI success labels must **never** be treated as execution permission. No real customer/target data should be fed to the CLI. Both input copies can be forged simultaneously, so equality alone proves no external fact.

### Canonical envelope generation (no handwritten nested JSON)

The CLI also exports a pure, strict builder for the stdin envelope. All supplied packet bytes must already be canonical and **strictly fictional**; it allows different but valid copies specifically so the verifier can return HOLD. It rejects real/noncanonical bytes, subclassed objects and more than sixteen copies by returning `None`.

```python
from lightup.fictional_packet_copy_1503 import build_fictional_copy_packet
from lightup.fictional_packet_cli_1503 import build_fictional_cli_envelope

original = build_fictional_copy_packet(
    "alpha.example.test", "REVIEW_REQUIRED", ("metadata_read",),
)
stdin_payload = build_fictional_cli_envelope(original, (original,) * 2)
assert type(stdin_payload) is bytes  # Already-validated canonical fictional bytes
# Feed stdin_payload to the opt-in CLI; do NOT treat REVIEW_ONLY as permission.
```

The two committed CLI fixtures must byte-match envelopes produced by this function; ordinary tests check this and run each one in a real subprocess. The builder performs no disk, network, database or process access and does not authenticate packet authors.


## Independently pinned fictional digest — opt-in second schema

The legacy `lightup-fictional-cli-v1` protocol checks copies against one
another; a party able to alter both baseline and recipients could make those
copies match. **The optional pinned protocol adds a separate digest check**
to detect that joint replacement *provided the digest was separately checked
and fixed before the copies were exchanged*.

- Direct pure function: `compare_fictional_packet_fanout_pinned(original, copies, expected_sha256)`.
- CLI schema: **`lightup-fictional-cli-pinned-v1`**, four exact fields in order: `schema`, `original`, `copies`, `expected_sha256`. All pre-existing requirements remain: bounded ASCII canonical JSON, solely fictional `.example.test` packets, 1–16 copies, four literal false permission flags and no extra fields. Pins are exact builtin lowercase ASCII `[0-9a-f]{64}` SHA-256 strings. Missing, upper-case, wrong-length and mismatched pins → generic `HOLD` with no digest or packet echo.
- `build_fictional_pinned_cli_envelope(original, copies, expected_sha256)` generates strict canonical stdin bytes but **does not verify the provenance of the pin**. The caller must obtain its value through a separately reviewed and independently controlled channel (for example, a human-reviewed immutable Git commit). Never derive the pin from just-arrived copies and call that a security check.
- Two versioned **fictional-only** end-to-end fixtures: `docs/examples/fictional-copy-cli-pinned-1503.json` has an original and two matching copies; `docs/examples/fictional-copy-cli-pinned-held-1503.json` replaces BOTH original and recipients with another syntactically valid fictional asset, while keeping the independently pinned old SHA-256. The latter must yield generic `HOLD` despite internal copy equality.

```sh
PYTHONPATH=src python -m lightup.fictional_packet_cli_1503 < docs/examples/fictional-copy-cli-pinned-1503.json
# REVIEW_ONLY with nonzero shell exit 2 (NOT authorization)
PYTHONPATH=src python -m lightup.fictional_packet_cli_1503 < docs/examples/fictional-copy-cli-pinned-held-1503.json
# HOLD, exit 3
```

Even with a correct independent pin, this is **not** a signature, authentication,
authorization, consent, revocation, asset ownership evidence, scanner permit,
or a release gate. If a malicious caller replaces both the bytes **and the pin**,
a matching result is possible. Both protocol versions remain unwired and
cannot grant runtime authority.

## Pinned-only CLI — reject legacy schema fallback (not runtime authority)

The original opt-in `python -m lightup.fictional_packet_cli_1503`
remains **backwards-compatible** and accepts both synthetic v1 (unpinned) and
v2 (pinned) envelopes. To avoid accidentally processing old, unpinned v1
envelopes in a workflow that requires a separately checked digest, use the
**different opt-in executable**:

```sh
PYTHONPATH=src python -m lightup.fictional_packet_cli_pinned_1503 < docs/examples/fictional-copy-cli-pinned-1503.json
# REVIEW_ONLY, exit 2, four authority flags false.
PYTHONPATH=src python -m lightup.fictional_packet_cli_pinned_1503 < docs/examples/fictional-copy-cli-pinned-held-1503.json
# HOLD, exit 3.
PYTHONPATH=src python -m lightup.fictional_packet_cli_pinned_1503 < docs/examples/fictional-copy-cli-1503.json
# HOLD, exit 3: legacy v1 denied even when all fictional copies match.
```

The dedicated Python3.11/3.14 offline suite now also asserts that **every
single-byte edit of a canonical v2 request** yields generic HOLD, joint
single-byte changes to original and all copies remain HOLD against the old
independent pin, and malformed/oversize subprocess input never exits 0.

The pinned-only module is a tiny wrapper around the **same strictly bounded
stdin** and **same generic HOLD/REVIEW_ONLY result writer**. It passes a
non-user-controlled boolean to a private parser that **rejects v1 at schema
selection**, before computing or returning a digest. Both modes continue to
reject command-line flags, data outside the exact ASCII canonical JSON
envelope, excess input, real assets and malformed pins. **Both modes always
exit nonzero and never authorize execution**. The pinned-only command does not
prevent an attacker from invoking a different executable, replacing the
separate SHA-256 reference, or altering a consumer that mistakes `REVIEW_ONLY`
for permission. It is solely an opt-in, offline guard against *accidental*
legacy fallback. No runtime or ingress module imports or invokes either CLI.

### Complete bounded stdin consumption (no prefix acceptance)

The review executables cannot interpret one early short read as the entire
request. An input stream is gathered **until byte EOF**, with a strict
**8,192-byte total cap** (reads request at most remaining capacity + 1 bytes).
If the stream delivers the exact valid JSON followed later by even one extra
whitespace character, line break, apparent approval object or other trailing
payload, the entire request becomes a generic `HOLD`. This rule applies to
both backwards-compatible and pinned-only commands; it does not permit
chunked records or sequential requests. Exact built-in `bytes` chunks are
required; non-binary streams, bytes subclasses and oversized/unending input
are rejected without calling user-defined coercions. The reader itself uses
no file, network, database or process API. A stream that does not yield EOF
can still block while waiting for data (no deadline/watchdog is provided),
so the CLI is intended for **finite offline input** and must never be a
network-facing handler or authorization service.

## Opt-in second-channel digest check (synthetic, offline only)

The pinned-only v2 envelope protects against silently accepting old unpinned
v1 input, but the `expected_sha256` inside that very envelope can itself
be changed alongside all fake packet copies. A new **separate opt-in**
command additionally requires a pre-selected SHA-256 from a **different
input channel**, the local environment variable
`LIGHTUP_FICTIONAL_EXPECTED_SHA256_1503`. This is useful for human-review
checklists where a reviewer independently holds an immutable reference, and
rejects accidental self-pinning when the envelope has changed.

```sh
# This is *not* a signed release, customer grant or production permission.
# Obtain the expected digest through a separately reviewed source.
# Example: use the known fictional fixture's SHA-256, not the incoming
# untrusted envelope's own expected_sha256 key.
LIGHTUP_FICTIONAL_EXPECTED_SHA256_1503="$(sha256sum docs/examples/fictional-copy-1503.json | cut -d' ' -f1)" \
  PYTHONPATH=src python -m lightup.fictional_packet_cli_anchored_1503 \
    < docs/examples/fictional-copy-cli-pinned-1503.json
# REVIEW_ONLY / exit 2, four authority flags false.

LIGHTUP_FICTIONAL_EXPECTED_SHA256_1503="$(sha256sum docs/examples/fictional-copy-1503.json | cut -d' ' -f1)" \
  PYTHONPATH=src python -m lightup.fictional_packet_cli_anchored_1503 \
    < docs/examples/fictional-copy-cli-pinned-held-1503.json
# generic HOLD / exit 3
```

The command requires three facts to match: strictly canonical **fictional**
packet bytes, the pinned hash **inside** the canonical v2 envelope and the
independently supplied **environment** SHA-256. It also denies legacy v1
schema, a missing/malformed/uppercase/mismatching environment digest,
unrecognized arguments, oversized input and delayed extra bytes after a
valid JSON prefix. A withheld independent reference means **HOLD**, never
fallback to envelope-only validation. This new CLI uses exactly the same
bounded stdin reader and non-authorizing stdout/exit policy as the other
two commands; there are no filesystem/network/database/scanner handlers.

**Security boundary:** The environment is *not authenticated*, securely
stored or protected against a malicious user who controls the process.
Someone who can rewrite **both the envelope and the environment value**
can still forge matching copies. This is an accidental-mismatch control,
**NOT** a cryptographic signature, real-client asset permission, operator
consent, at-use revocation, human GO or release evidence. Do not inject
real customer data/credentials, wire this to an execution path or claim
that the environment proves external provenance. Keep DRAFT/HOLD.

## Tests and ownership

Run both opt-in isolated suites with `PYTHONPATH=src python -m unittest discover -s tests -p 'test_fictional_packet*_1503.py' -v`; this pattern executes the copy checker and CLI test modules (including pinned-only real-subprocess cases, byte edits, fanout, and no-I/O tripwires). Dedicated **hosted** Python 3.11/3.14 workflow `.github/workflows/lightup-fictional-packet-1503.yml` runs both new offline test files when the new file set changes. This does not substitute for original full hosted preflight or the genuinely registered permanent VPS runner (#1144). All files exclusively added under #1503; do not cherry-pick as production authorization.

**Release STOP:** Original source owner fixes incl. #301, authentic both-client-and-operator informed consent, runtime revocation-at-use, full exact-head hosted + registered VPS proof, independent security/privacy review and explicit human GO remain open. Do **not** merge, deploy, scan, issue grants, wire any handler or assert approval based on this packet.
