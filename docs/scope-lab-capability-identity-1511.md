# LightUp #1511 — LAB_ONLY capability identity (offline, non-authorizing)

**Project:** INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD. This is a synthetic
review experiment, not production authorization or a completed source fix.

## Verified current-source gap

On the current unmodified `main` `src/lightup/activation.py`,
`ActivationGate.issue()` passes through the caller's `capability_id`
without a runtime type, canonical-identity or emptiness check before putting
it into an `ExecutionPermit`. In LAB_ONLY this also applies to the permitted
loopback/private-lab path. No target/network activity is needed to reproduce.

The issue #1511 acceptance file retains two deliberately **expected RED**
source tests: one whitespace capability ID and one arbitrary non-string
equality-spoof object. Those are *unfixed installed-source failures*, not PASS.

## Implemented independent no-I/O advisory

`lightup.fictional_lab_capability_review_1511` is an **unwired** pure helper.
It accepts an exact builtin `str` and caller-provided exact builtin
`tuple[str, ...]` with 1–64 distinct exact-builtin canonical IDs. Canonical
IDs are lowercase ASCII `[a-z][a-z0-9]*(?:-[a-z0-9]+)*`, length 1–64.
All other inputs, subclass spoofing, duplicates, absent IDs and ambiguities
return generic `HOLD`. Locally coherent purely fictional records return only
`REVIEW_ONLY`. Neither output ever grants anything: frozen
`authorized=False`, `consent_verified=False`,
`dispatch_allowed=False`, `release_allowed=False`.

This reference check is **not** an attested or complete registry, not a
signature, not authenticated client/operator consent and not live revocation.
It is never called by the installed `ActivationGate`, ToolExecutor or
any handler. Nothing here changes the original runtime's permit behavior.

## Replay / acceptance

```bash
PYTHONPATH=src PYTHONDONTWRITEBYTECODE=1 \
  python -m unittest discover -s tests \
  -p 'test_fictional_lab_capability_review_1511.py' -v
```

Ordinary acceptance covers valid synthetic input, non-authorizing decisions,
missing/blank/Unicode/path/overlong requests, tuple/str subclasses,
polymorphic objects, duplicate/unknown/malformed allowlists, data immutability,
no socket calls, and bound limits. Two original source tests intentionally
remain `expectedFailure`. Read the **exact HEAD** CI logs before claiming
hosted validation. Original full-suite hosted and permanent named registered
`vps-bb300bba` validation must also be independently proven; isolated
green cannot substitute for these gates.

## Ownership and release constraints

- Own only the new #1511 module, tests, document and isolated workflow.
- Do not edit `activation.py`, `models.py`, `scope.py`, any other worker's
  tests/PR/branch, default CI, grants, existing workflow or runner.
- #726 owns AUTHORIZED capability identity on #122's source-owner branch;
  #1094 owns ToolCall identifier admission; #1491 owns permit audit.
- Original runtime source owners must design and review the **actual** LAB_ONLY
  source fix, then convert RED into ordinary PASS after integration.
- Absolutely no merge, deploy, release, grants, real-target scans or handler
  dispatch until separate genuine client AND operator consent, at-use
  revocation, full source owner/security/privacy review, original full hosted
  suite and registered permanent VPS GREEN, and explicit human GO.


## W2 — optional fictional CLI (not a production interface)

New `scripts/fictional_lab_capability_cli_1511.py` reads up to 4096 bytes
from stdin and accepts only canonical ASCII JSON shaped exactly as
`{"schema":"fictional_lab_capability_v1","requested":"web-baseline","allowlist":["web-baseline"]}`.
It rejects duplicate keys, aliases, Unicode escapes, other encoding choices,
unknown fields, trailing data, poisoned types, ambiguous or duplicate
fictional IDs, and missing/overlong input. It never prints input and
never exits with code 0: **2 = REVIEW_ONLY**, **3 = HOLD**, both non-authorizing.
No target/network interaction or runtime wiring is introduced.

```bash
printf '%s' '{"schema":"fictional_lab_capability_v1","requested":"web-baseline","allowlist":["web-baseline"]}' \
  | PYTHONDONTWRITEBYTECODE=1 python scripts/fictional_lab_capability_cli_1511.py
# REVIEW_ONLY and exit 2. Never use this as permission to do anything.
PYTHONPATH=src PYTHONDONTWRITEBYTECODE=1 python -m unittest discover -s tests \
  -p 'test_fictional_lab_capability*_1511.py' -v
```

New separate tests cover genuine CLI subprocess return codes, no input echo,
corrupt/duplicate-key/binary/oversize/Unicode and canonical fixture admission,
as well as every single-byte NUL corruption of the positive fixture. The
isolated pinned workflow now runs **both** #1511 test files. Exact W2 head
and hosted logs must be checked anew: a prior SHA's green CI cannot be
substituted for the new SHA.

## W3 — result-object safety and production isolation

The earlier internal advisory reused `_HOLD` and `_REVIEW_ONLY` instance
singletons and had a public dataclass constructor accepting
`authorized=True` and similar authority-shaped keyword arguments. This is
an in-process *advisory object integrity* problem, **not a product-runtime
authorization bypass**. All regular review outputs were false, but Python
`object.__setattr__` can bypass ordinary dataclass `frozen=True` and
contaminate shared singleton results.

The rewritten pure module now:
- allocates a **fresh result** for each HOLD/REVIEW_ONLY call; deliberately
  tampering with one caller-owned object cannot poison subsequent results;
- accepts exactly `HOLD` and `REVIEW_ONLY` built-in string statuses,
  and prevents public callers from specifying any four authority flags
  in the normal constructor;
- retains `frozen=True, slots=True` but explicitly does **not** claim
  cryptographic object authenticity: malicious Python code may forge even
  these individual values. Do not treat these statuses as real permissions.

Two new owned test files verify constructor restrictions, forced per-object
mutation isolation, exact-type spoof rejection, parallel review independence,
no socket/file-open inside pure review, and static AST proof that unmodified
production source contains no direct import or literal dynamic import
of the optional fictional helper. The static check is deliberately limited:
it does not prove every reflective or future dynamic import route.

The own SHA-pinned, hosted-only read-only CI has been expanded to discover
the new tests. This remains **separate from the original producer, execution
handlers and live authorization**. Full original CI, a genuinely registered
permanent named VPS, independent security/privacy and actual client+operator
consent/revocation remain release prerequisites.

## W4 — actual in-process source-contract simulation (test instance only)

The additional isolated acceptance file
`tests/test_fictional_lab_capability_transition_1511.py` exercises an
**individual synthetic** `ActivationGate` through an entirely test-local
wrapper. The wrapper checks strict fictional capability identity and
then calls the unchanged original gate. Invalid blank, polymorphic, unknown,
noncanonical and overlong capability IDs are denied *by the test wrapper*
before an in-memory permit could be constructed. A canonical fake loopback
`web-baseline` fixture still behaves as the original LAB_ONLY path; PLAN_ONLY
and explicit public-host examples remain denied even with wrapper.

One test intentionally demonstrates that the **unwrapped original**
`ActivationGate.issue` STILL issues a synthetic whitespace capability permit.
This distinction prevents treating a successful wrapper test as actual
product remediation. There are no live targets, DNS, external sockets,
handlers, grants or deployments. No `ActivationGate` class/source edits
or persistent monkeypatch occur. The local wrapper is not exportable or
installed and its caller-provided fictional tool list is not a trusted
capability registry. A full production design would still require owner
review of canonical registry identity, real consent/revocation, race safety,
and immutable audit evidence.

W4 acceptance is included in the dedicated own read-only hosted Python3.11
and Python3.14 CI; only results from the **new exact HEAD** may be cited.

## W5 — actual fragmented stdin, bounded early HOLD and malformed JSON

New dedicated `test_fictional_lab_capability_streaming_1511.py` tests
the **real opt-in CLI subprocess** over multiple manually fragmented
stdin writes, partial/missing EOF completion, exact 4,096-byte and
4,097-byte payloads, Unicode-escaped duplicate schema aliases,
JSON `NaN`, Infinity, extreme exponent, malformed/corrupt payloads,
and deeply nested lists. Every proper prefix of the known synthetic
valid fixture is HOLD; only the entire canonical fake record can yield
REVIEW_ONLY, still exit 2 and not authorization. Truncated/oversize
real subprocess outputs are generic HOLD and exit 3, with private markers
never echoed. This is process-behavior evidence on the **own CLI only**,
not an installed ingress/network or actual client consent test.

The tests are included in the own pinned least-privilege workflow and
the static owner-path inventory. Original source, existing CI/VPS runners,
other workers, external targets and active handlers remain unchanged.

## W6 — atomic fictional LAB capability cohort, not real authority

New independent, strictly **unwired** source
`src/lightup/fictional_lab_capability_batch_1511.py` adds
`review_fictional_lab_capability_cohort_1511`. It reviews a bounded
exact-built-in `tuple` of 1–64 unique ASCII capability IDs against a
bounded **caller-provided, untrusted, fictional** tuple. Every ID and
both containers must be canonical exact builtins; duplicate IDs,
missing membership, subtype spoofing, unknown shapes or too many
entries result in a **single atomic HOLD**, with no per-ID result to
misconstrue as partial approval. A fully internally consistent fictional
record returns only `REVIEW_ONLY`. All results have all four false
consent/authority/dispatch/release fields. The helper does **not**
issue permits, sign evidence, prove a registry or call a handler.

New opt-in strict batch CLI
`scripts/fictional_lab_capability_batch_cli_1511.py` accepts only
ASCII exact canonical JSON of the shape:
```json
{"schema":"fictional_lab_capability_batch_v1","requested":["web-baseline","tls-baseline"],"allowlist":["tls-baseline","web-baseline"]}
```
Max 4096 bytes total, schema/field order fixed, no extra/duplicate/
aliased or escaped keys, no whitespace or trailing bytes, strictly bounded
in-memory review. Fixed responses: `REVIEW_ONLY\n` exit **2**, or
generic `HOLD\n` exit **3**, **never success 0**, no source or submitted
private content echoed. For example (expect nonzero exit **2**, NOT
permission to use any security tool):
```bash
printf '%s' '{"schema":"fictional_lab_capability_batch_v1","requested":["web-baseline"],"allowlist":["web-baseline"]}' |
  PYTHONDONTWRITEBYTECODE=1 python scripts/fictional_lab_capability_batch_cli_1511.py
```

New tests check every candidate mutation position through 64 entries,
full-batch HOLD on one mismatch or duplicated member, poison equality/
hash and tuple subclass objects without calling hostile methods, no
network/file opens, caller purity, singleton poisoning protection,
canonical JSON, all fixture prefixes/byte corruption, real subprocess
exit codes and no private input echo. The pinned read-only own CI
includes the new files and static import-isolation checks.

This is **not product source remediation** for `ActivationGate.issue`
or an independently attested registry. Separate genuine client and
operator consent, revocation at use, privacy/security review, owner
source fixes, full hosted AND actual registered permanent VPS green,
and explicit human GO remain mandatory. **DRAFT/HOLD; no merge,
deployment, scans, targets, grants or handler execution.**
